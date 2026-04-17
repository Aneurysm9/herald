//! RFC 2136 (DNS UPDATE) backend implementation.
//!
//! Manages DNS records on any RFC 2136-compatible authoritative server
//! (BIND, Knot, `PowerDNS`, etc.) by sending DNS UPDATE messages via
//! hickory-dns's `Client`.
//!
//! # Managed Record Tracking
//!
//! Unlike Cloudflare and Technitium, RFC 2136 has no native concept of a
//! record comment or tag. Herald tracks managed records in a local `SQLite`
//! database (`{state_dir}/rfc2136-{name}.db`). Only records in this database
//! are visible to the reconciler — pre-existing records in the zone are
//! ignored entirely, so they cannot be accidentally deleted.
//!
//! # TSIG Authentication
//!
//! If `tsig_key_file` is set, all DNS UPDATE messages are signed with
//! TSIG (RFC 2845/8945). The algorithm defaults to HMAC-SHA256 but
//! hickory supports the full set.

use super::{Backend, Change, ExistingRecord};
use crate::config::Rfc2136BackendConfig;
use crate::provider::{EnrichedRecord, Named, RecordValue};
use crate::storage::{SqliteStorage, StorageKey};
use crate::telemetry::Metrics;
use crate::tsig::{self, TSIG_FUDGE};
use anyhow::{Context, Result};
use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::xfer::DnsMultiplexer;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{Name, TSigner};
use opentelemetry::KeyValue;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// ── Storage types ─────────────────────────────────────────────────────────────

/// Composite key for a managed RFC 2136 record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RecordId {
    name: String,
    record_type: String,
    value: String,
}

impl StorageKey for RecordId {
    fn to_sql(&self) -> String {
        format!("{}|{}|{}", self.name, self.record_type, self.value)
    }

    fn from_sql(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, '|').collect();
        if parts.len() != 3 {
            anyhow::bail!("invalid RecordId format (expected 3 parts): {s}");
        }
        Ok(Self {
            name: parts[0].to_string(),
            record_type: parts[1].to_string(),
            value: parts[2].to_string(),
        })
    }
}

/// Persisted metadata for a Herald-managed record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRecord {
    zone: String,
    ttl: u32,
}

// ── Backend struct ────────────────────────────────────────────────────────────

/// RFC 2136 backend: sends DNS UPDATE messages via hickory-dns `Client`
/// and tracks managed records in `SQLite`.
pub(crate) struct Rfc2136Backend {
    name: String,
    zones: Vec<String>,
    primary_nameserver: SocketAddr,
    tsig_signer: Option<TSigner>,
    storage: Arc<Mutex<SqliteStorage<RecordId, StoredRecord>>>,
    metrics: Metrics,
}

impl Rfc2136Backend {
    /// Create a new RFC 2136 backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the nameserver address is invalid, the TSIG key file
    /// cannot be read, or the database cannot be opened.
    pub(crate) async fn new(
        config: &Rfc2136BackendConfig,
        index: usize,
        state_dir: &str,
        metrics: Metrics,
    ) -> Result<Self> {
        let name = config
            .name
            .clone()
            .unwrap_or_else(|| format!("rfc2136-{index}"));

        let addr_str = if config.primary_nameserver.contains(':') {
            config.primary_nameserver.clone()
        } else {
            format!("{}:53", config.primary_nameserver)
        };
        let primary_nameserver: SocketAddr = addr_str
            .parse()
            .with_context(|| format!("parsing nameserver address: {addr_str}"))?;

        let tsig_signer = match (&config.tsig_key_file, &config.tsig_key_name) {
            (Some(path), Some(key_name)) => {
                let signer = tsig::load_tsigner_from_file(
                    key_name,
                    path,
                    TsigAlgorithm::HmacSha256,
                    TSIG_FUDGE,
                )
                .await?;
                tracing::info!(name = %name, key_name = %key_name, "TSIG key loaded");
                Some(signer)
            }
            (Some(_), None) => {
                anyhow::bail!("rfc2136 backend '{name}': tsig_key_file requires tsig_key_name");
            }
            (None, _) => {
                tracing::warn!(
                    name = %name,
                    "no TSIG key configured — updates will be sent unsigned"
                );
                None
            }
        };

        let db_path = PathBuf::from(state_dir).join(format!("rfc2136-{name}.db"));
        let storage = SqliteStorage::new(&db_path, "managed_records")
            .with_context(|| format!("initializing RFC 2136 storage at {}", db_path.display()))?;

        tracing::info!(
            name = %name,
            zones = ?config.zones,
            nameserver = %primary_nameserver,
            "RFC 2136 backend initialized"
        );

        Ok(Self {
            name,
            zones: config.zones.clone(),
            primary_nameserver,
            tsig_signer,
            storage: Arc::new(Mutex::new(storage)),
            metrics,
        })
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Connect to the primary nameserver and return a hickory `Client`.
    ///
    /// A fresh TCP connection is created per call — each UPDATE gets its own
    /// connection, which matches our previous behaviour and avoids holding a
    /// long-lived connection that could time out.
    async fn connect_client(&self) -> Result<Client<TokioRuntimeProvider>> {
        let provider = TokioRuntimeProvider::default();
        let (connect_future, handle) = TcpClientStream::new(
            self.primary_nameserver,
            None,
            Some(Duration::from_secs(10)),
            provider,
        );

        let stream = connect_future
            .await
            .with_context(|| format!("connecting to {}", self.primary_nameserver))?;

        let multiplexer = DnsMultiplexer::new(stream, handle).with_timeout(Duration::from_secs(10));

        let multiplexer = if let Some(ref signer) = self.tsig_signer {
            multiplexer.with_signer(signer.clone())
        } else {
            multiplexer
        };

        let (client, bg) = Client::from_sender(multiplexer);
        tokio::spawn(bg);
        Ok(client)
    }

    async fn get_records_inner(&self) -> Result<Vec<ExistingRecord>> {
        let storage = self.storage.lock().await;
        let entries = storage
            .load_all()
            .context("loading managed records from database")?;
        drop(storage);

        let records = entries
            .into_iter()
            .filter_map(|(id, stored)| {
                let value = match RecordValue::parse(&id.record_type, &id.value) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            name = %id.name,
                            record_type = %id.record_type,
                            error = %e,
                            "skipping unparseable managed record"
                        );
                        return None;
                    }
                };
                let existing_id = id.to_sql();
                Some(ExistingRecord {
                    id: existing_id,
                    record: EnrichedRecord {
                        zone: stored.zone,
                        name: id.name,
                        value,
                        ttl: stored.ttl,
                    },
                    managed: true,
                })
            })
            .collect();

        Ok(records)
    }

    #[tracing::instrument(skip(self), fields(change = %change))]
    async fn apply_change_inner(&self, change: &Change) -> Result<()> {
        match change {
            Change::Create(record) => {
                self.send_add(record).await?;
                self.store_record(record).await?;
            }
            Change::Update { id: _, old, new } => {
                self.send_delete(old).await?;
                self.send_add(new).await?;
                self.delete_record(old).await?;
                self.store_record(new).await?;
            }
            Change::Delete(existing) => {
                self.send_delete(&existing.record).await?;
                self.delete_record(&existing.record).await?;
            }
        }
        Ok(())
    }

    async fn send_add(&self, record: &EnrichedRecord) -> Result<()> {
        let zone = Name::from_ascii(&record.zone)
            .with_context(|| format!("invalid zone name: {}", record.zone))?;
        let rrset = build_record_set(&record.name, &record.value, record.ttl)
            .with_context(|| format!("building record set for ADD: {record}"))?;

        let mut client = self
            .connect_client()
            .await
            .with_context(|| format!("connecting for ADD: {record}"))?;

        client
            .create(rrset, zone)
            .await
            .with_context(|| format!("DNS ADD for {record}"))?;

        Ok(())
    }

    async fn send_delete(&self, record: &EnrichedRecord) -> Result<()> {
        let zone = Name::from_ascii(&record.zone)
            .with_context(|| format!("invalid zone name: {}", record.zone))?;
        let rrset = build_record_set(&record.name, &record.value, record.ttl)
            .with_context(|| format!("building record set for DELETE: {record}"))?;

        let mut client = self
            .connect_client()
            .await
            .with_context(|| format!("connecting for DELETE: {record}"))?;

        client
            .delete_by_rdata(rrset, zone)
            .await
            .with_context(|| format!("DNS DELETE for {record}"))?;

        Ok(())
    }

    async fn store_record(&self, record: &EnrichedRecord) -> Result<()> {
        let key = RecordId {
            name: record.name.clone(),
            record_type: record.value.type_str().to_string(),
            value: record.value.value_str().clone(),
        };
        let stored = StoredRecord {
            zone: record.zone.clone(),
            ttl: record.ttl,
        };
        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || {
            let storage = storage.blocking_lock();
            storage.upsert(&key, &stored)
        })
        .await
        .context("database persistence task panicked")??;
        Ok(())
    }

    async fn delete_record(&self, record: &EnrichedRecord) -> Result<()> {
        let key = RecordId {
            name: record.name.clone(),
            record_type: record.value.type_str().to_string(),
            value: record.value.value_str().clone(),
        };
        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || {
            let storage = storage.blocking_lock();
            storage.delete(&key)
        })
        .await
        .context("database persistence task panicked")??;
        Ok(())
    }

    async fn get_records_with_metrics(&self) -> Result<Vec<ExistingRecord>> {
        let start = Instant::now();
        let result = self.get_records_inner().await;
        let elapsed = start.elapsed().as_secs_f64();
        let status = if result.is_ok() { "success" } else { "error" };
        self.metrics.backend_api_calls.add(
            1,
            &[
                KeyValue::new("backend", self.name.clone()),
                KeyValue::new("operation", "get_records"),
                KeyValue::new("status", status),
            ],
        );
        self.metrics
            .backend_api_duration
            .record(elapsed, &[KeyValue::new("backend", self.name.clone())]);
        result
    }

    async fn apply_change_with_metrics(&self, change: &Change) -> Result<()> {
        let op = match change {
            Change::Create(_) => "create",
            Change::Update { .. } => "update",
            Change::Delete(_) => "delete",
        };
        let start = Instant::now();
        let result = self.apply_change_inner(change).await;
        let elapsed = start.elapsed().as_secs_f64();
        let status = if result.is_ok() { "success" } else { "error" };
        self.metrics.backend_api_calls.add(
            1,
            &[
                KeyValue::new("backend", self.name.clone()),
                KeyValue::new("operation", op),
                KeyValue::new("status", status),
            ],
        );
        self.metrics
            .backend_api_duration
            .record(elapsed, &[KeyValue::new("backend", self.name.clone())]);
        if result.is_ok() {
            tracing::info!(
                backend = %self.name,
                change = %change,
                "applied DNS change"
            );
        } else if let Err(ref e) = result {
            tracing::error!(
                backend = %self.name,
                change = %change,
                error = %e,
                "failed to apply DNS change"
            );
        }
        result
    }
}

/// Build a single-record `RecordSet` from Herald's enriched record fields.
fn build_record_set(
    name: &str,
    value: &RecordValue,
    ttl: u32,
) -> Result<hickory_proto::rr::RecordSet> {
    use hickory_proto::rr::{RData, Record, RecordSet};
    let dns_name = hickory_proto::rr::Name::from_ascii(name)
        .with_context(|| format!("invalid record name: {name}"))?;
    let rdata = RData::try_from(value)?;
    let rtype = rdata.record_type();
    let record = Record::from_rdata(dns_name.clone(), ttl, rdata);
    let mut rrset = RecordSet::new(dns_name, rtype, 0);
    rrset.insert(record, 0);
    Ok(rrset)
}

impl Named for Rfc2136Backend {
    fn name(&self) -> &str {
        &self.name
    }
}

impl Backend for Rfc2136Backend {
    fn zones(&self) -> Vec<String> {
        self.zones.clone()
    }

    fn get_records(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ExistingRecord>>> + Send + '_>> {
        Box::pin(self.get_records_with_metrics())
    }

    fn apply_change<'a>(
        &'a self,
        change: &'a Change,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.apply_change_with_metrics(change))
    }
}
