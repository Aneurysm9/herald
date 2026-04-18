//! Shared test helpers for the RFC 2136 conformance suite.
//!
//! Provides `UpdateMessageBuilder` (hand-rolled wire construction for malformed-
//! message tests that hickory would refuse to build), `FakeBackend`, and
//! `DnsServerFixture` for receiver-behavior tests.

#![allow(dead_code)]
#![allow(clippy::doc_markdown)]

use crate::backend::{Backend, Change, ExistingRecord};
use crate::config::{DnsServerConfig, DynamicClientConfig, DynamicProviderConfig};
use crate::dns_server::DnsServer;
use crate::provider::dynamic::DynamicProvider;
use crate::provider::{Named, Provider};
use crate::telemetry::Metrics;
use crate::tsig::TSIG_FUDGE;
use anyhow::Result;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{Name, TSigner};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Notify;

// ── DNS wire-format constants (for hand-rolled test messages) ────────────────

pub(crate) const RTYPE_A: u16 = 1;
pub(crate) const RTYPE_AAAA: u16 = 28;
pub(crate) const RTYPE_SOA: u16 = 6;
pub(crate) const RTYPE_ANY: u16 = 255;

pub(crate) const CLASS_IN: u16 = 1;
pub(crate) const CLASS_ANY: u16 = 255;
pub(crate) const CLASS_NONE: u16 = 254;

/// Encode an A record as 4-byte RDATA.
pub(crate) fn rdata_a_bytes(addr: std::net::Ipv4Addr) -> Vec<u8> {
    addr.octets().to_vec()
}

/// Encode a DNS name to uncompressed wire format.
pub(crate) fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let name = name.trim_end_matches('.');
    if !name.is_empty() {
        for label in name.split('.') {
            #[allow(clippy::cast_possible_truncation)]
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0u8);
    buf
}

/// Build a 12-byte DNS header.
#[allow(clippy::similar_names)] // ancount/arcount/nscount are standard DNS field names
pub(crate) fn build_header(
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(12);
    hdr.extend_from_slice(&id.to_be_bytes());
    hdr.extend_from_slice(&flags.to_be_bytes());
    hdr.extend_from_slice(&qdcount.to_be_bytes());
    hdr.extend_from_slice(&ancount.to_be_bytes());
    hdr.extend_from_slice(&nscount.to_be_bytes());
    hdr.extend_from_slice(&arcount.to_be_bytes());
    hdr
}

/// Build a standard query message (opcode 0) for testing non-UPDATE rejection.
pub(crate) fn build_raw_query(id: u16, zone: &str) -> Vec<u8> {
    let mut msg = build_header(id, 0x0000, 1, 0, 0, 0);
    msg.extend_from_slice(&encode_dns_name(zone));
    msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    msg
}

// ── Prereq / UpdateOp enums ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) enum Prereq {
    RrsetExists {
        name: String,
        rtype: u16,
    },
    RrsetExistsValue {
        name: String,
        rtype: u16,
        rdata: Vec<u8>,
    },
    RrsetDoesNotExist {
        name: String,
        rtype: u16,
    },
    NameInUse {
        name: String,
    },
    NameNotInUse {
        name: String,
    },
    Raw {
        name: String,
        rtype: u16,
        class: u16,
        ttl: u32,
        rdata: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum UpdateOp {
    Add {
        name: String,
        rtype: u16,
        ttl: u32,
        rdata: Vec<u8>,
    },
    DeleteRrset {
        name: String,
        rtype: u16,
    },
    DeleteAllRrsets {
        name: String,
    },
    DeleteRr {
        name: String,
        rtype: u16,
        rdata: Vec<u8>,
    },
}

// ── UpdateMessageBuilder ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct UpdateMessageBuilder {
    zone: Option<String>,
    zocount_override: Option<u16>,
    zone_qtype_override: Option<u16>,
    zone_qclass_override: Option<u16>,
    extra_zones: Vec<(String, u16, u16)>,
    prereqs: Vec<Prereq>,
    updates: Vec<UpdateOp>,
}

impl UpdateMessageBuilder {
    pub(crate) fn new(zone: impl Into<String>) -> Self {
        Self {
            zone: Some(zone.into()),
            zocount_override: None,
            zone_qtype_override: None,
            zone_qclass_override: None,
            extra_zones: Vec::new(),
            prereqs: Vec::new(),
            updates: Vec::new(),
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            zone: None,
            zocount_override: None,
            zone_qtype_override: None,
            zone_qclass_override: None,
            extra_zones: Vec::new(),
            prereqs: Vec::new(),
            updates: Vec::new(),
        }
    }

    pub(crate) fn zocount_override(mut self, n: u16) -> Self {
        self.zocount_override = Some(n);
        self
    }

    pub(crate) fn zone_qtype(mut self, qtype: u16) -> Self {
        self.zone_qtype_override = Some(qtype);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn zone_qclass(mut self, qclass: u16) -> Self {
        self.zone_qclass_override = Some(qclass);
        self
    }

    pub(crate) fn extra_zone(mut self, name: impl Into<String>, qtype: u16, qclass: u16) -> Self {
        self.extra_zones.push((name.into(), qtype, qclass));
        self
    }

    pub(crate) fn prereq_rrset_exists(mut self, name: impl Into<String>, rtype: u16) -> Self {
        self.prereqs.push(Prereq::RrsetExists {
            name: name.into(),
            rtype,
        });
        self
    }

    pub(crate) fn prereq_rrset_exists_value(
        mut self,
        name: impl Into<String>,
        rtype: u16,
        rdata: Vec<u8>,
    ) -> Self {
        self.prereqs.push(Prereq::RrsetExistsValue {
            name: name.into(),
            rtype,
            rdata,
        });
        self
    }

    pub(crate) fn prereq_rrset_does_not_exist(
        mut self,
        name: impl Into<String>,
        rtype: u16,
    ) -> Self {
        self.prereqs.push(Prereq::RrsetDoesNotExist {
            name: name.into(),
            rtype,
        });
        self
    }

    pub(crate) fn prereq_name_in_use(mut self, name: impl Into<String>) -> Self {
        self.prereqs.push(Prereq::NameInUse { name: name.into() });
        self
    }

    pub(crate) fn prereq_name_not_in_use(mut self, name: impl Into<String>) -> Self {
        self.prereqs
            .push(Prereq::NameNotInUse { name: name.into() });
        self
    }

    pub(crate) fn prereq_raw(mut self, p: Prereq) -> Self {
        self.prereqs.push(p);
        self
    }

    pub(crate) fn add(
        mut self,
        name: impl Into<String>,
        rtype: u16,
        ttl: u32,
        rdata: Vec<u8>,
    ) -> Self {
        self.updates.push(UpdateOp::Add {
            name: name.into(),
            rtype,
            ttl,
            rdata,
        });
        self
    }

    pub(crate) fn delete_rrset(mut self, name: impl Into<String>, rtype: u16) -> Self {
        self.updates.push(UpdateOp::DeleteRrset {
            name: name.into(),
            rtype,
        });
        self
    }

    pub(crate) fn delete_all_rrsets(mut self, name: impl Into<String>) -> Self {
        self.updates
            .push(UpdateOp::DeleteAllRrsets { name: name.into() });
        self
    }

    pub(crate) fn delete_rr(mut self, name: impl Into<String>, rtype: u16, rdata: Vec<u8>) -> Self {
        self.updates.push(UpdateOp::DeleteRr {
            name: name.into(),
            rtype,
            rdata,
        });
        self
    }

    pub(crate) fn build(&self, id: u16) -> Vec<u8> {
        let zocount_actual =
            u16::try_from(self.zone.iter().count() + self.extra_zones.len()).unwrap_or(0);
        let zocount = self.zocount_override.unwrap_or(zocount_actual);
        let prcount = u16::try_from(self.prereqs.len()).expect("prereq count fits u16");
        let upcount = u16::try_from(self.updates.len()).expect("update count fits u16");

        let flags: u16 = 0x2800; // OPCODE=UPDATE(5)
        let mut msg = build_header(id, flags, zocount, prcount, upcount, 0);

        if let Some(ref zone) = self.zone {
            msg.extend_from_slice(&encode_dns_name(zone));
            msg.extend_from_slice(&self.zone_qtype_override.unwrap_or(RTYPE_SOA).to_be_bytes());
            msg.extend_from_slice(&self.zone_qclass_override.unwrap_or(CLASS_IN).to_be_bytes());
        }
        for (name, qtype, qclass) in &self.extra_zones {
            msg.extend_from_slice(&encode_dns_name(name));
            msg.extend_from_slice(&qtype.to_be_bytes());
            msg.extend_from_slice(&qclass.to_be_bytes());
        }

        for p in &self.prereqs {
            append_prereq_rr(&mut msg, p);
        }

        for u in &self.updates {
            append_update_rr(&mut msg, u);
        }

        msg
    }

    pub(crate) fn build_signed(&self, id: u16, key: &TSigner) -> Vec<u8> {
        let msg = self.build(id);
        sign_message_bytes(&msg, key)
    }

    pub(crate) fn build_signed_with_time(
        &self,
        id: u16,
        key: &TSigner,
        time_signed: u64,
    ) -> Vec<u8> {
        let msg = self.build(id);
        sign_message_bytes_with_time(&msg, key, time_signed)
    }
}

fn append_prereq_rr(msg: &mut Vec<u8>, p: &Prereq) {
    match p {
        Prereq::RrsetExists { name, rtype } => write_rr(msg, name, *rtype, CLASS_ANY, 0, &[]),
        Prereq::RrsetExistsValue { name, rtype, rdata } => {
            write_rr(msg, name, *rtype, CLASS_IN, 0, rdata);
        }
        Prereq::RrsetDoesNotExist { name, rtype } => {
            write_rr(msg, name, *rtype, CLASS_NONE, 0, &[]);
        }
        Prereq::NameInUse { name } => write_rr(msg, name, RTYPE_ANY, CLASS_ANY, 0, &[]),
        Prereq::NameNotInUse { name } => write_rr(msg, name, RTYPE_ANY, CLASS_NONE, 0, &[]),
        Prereq::Raw {
            name,
            rtype,
            class,
            ttl,
            rdata,
        } => write_rr(msg, name, *rtype, *class, *ttl, rdata),
    }
}

fn append_update_rr(msg: &mut Vec<u8>, u: &UpdateOp) {
    match u {
        UpdateOp::Add {
            name,
            rtype,
            ttl,
            rdata,
        } => write_rr(msg, name, *rtype, CLASS_IN, *ttl, rdata),
        UpdateOp::DeleteRrset { name, rtype } => write_rr(msg, name, *rtype, CLASS_ANY, 0, &[]),
        UpdateOp::DeleteAllRrsets { name } => write_rr(msg, name, RTYPE_ANY, CLASS_ANY, 0, &[]),
        UpdateOp::DeleteRr { name, rtype, rdata } => {
            write_rr(msg, name, *rtype, CLASS_NONE, 0, rdata);
        }
    }
}

fn write_rr(msg: &mut Vec<u8>, name: &str, rtype: u16, class: u16, ttl: u32, rdata: &[u8]) {
    msg.extend_from_slice(&encode_dns_name(name));
    msg.extend_from_slice(&rtype.to_be_bytes());
    msg.extend_from_slice(&class.to_be_bytes());
    msg.extend_from_slice(&ttl.to_be_bytes());
    let rdlen = u16::try_from(rdata.len()).expect("RDATA fits u16");
    msg.extend_from_slice(&rdlen.to_be_bytes());
    msg.extend_from_slice(rdata);
}

// ── TSIG signing helpers ─────────────────────────────────────────────────────

/// Construct a `TSigner` from raw bytes without file I/O.
pub(crate) fn make_test_tsig_key(key_name: &str, secret: &[u8]) -> TSigner {
    let name = Name::from_ascii(key_name).expect("test key name must be valid");
    TSigner::new(secret.to_vec(), TsigAlgorithm::HmacSha256, name, TSIG_FUDGE)
        .expect("TSigner construction must succeed in tests")
}

/// Canonical secret used across tests (32 bytes).
pub(crate) const TEST_TSIG_SECRET: &[u8] = b"herald-test-secret-0123456789ab";

/// Sign a message (raw bytes) with a TSigner, returning the signed bytes.
fn sign_message_bytes(msg: &[u8], key: &TSigner) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    sign_message_bytes_with_time(msg, key, now)
}

/// Sign a message with a fixed timestamp (for fudge-window tests).
fn sign_message_bytes_with_time(msg: &[u8], key: &TSigner, time_signed: u64) -> Vec<u8> {
    let parsed =
        hickory_proto::op::Message::from_vec(msg).expect("test message must parse for signing");
    let (tsig_record, _verifier) = key
        .sign_message(&parsed, time_signed)
        .expect("TSIG signing must succeed in tests");

    let mut signed = parsed;
    signed.signature = Some(tsig_record);
    signed
        .to_vec()
        .expect("signed message serialization must succeed")
}

// ── Response accessors ───────────────────────────────────────────────────────

pub(crate) fn extract_rcode(response: &[u8]) -> u8 {
    if response.len() < 4 {
        0
    } else {
        response[3] & 0x0F
    }
}

pub(crate) fn extract_id(response: &[u8]) -> u16 {
    assert!(response.len() >= 2);
    u16::from_be_bytes([response[0], response[1]])
}

pub(crate) fn extract_opcode(response: &[u8]) -> u8 {
    assert!(response.len() >= 3);
    (response[2] >> 3) & 0x0F
}

// ── FakeBackend ──────────────────────────────────────────────────────────────

/// `Backend` impl for tests. When `provider` is set, `get_records()` returns
/// the provider's current records as `ExistingRecord`s — this is needed for
/// prereq evaluation, which checks against actual zone contents.
///
/// Applied changes are recorded in `applied_changes` for integration test
/// assertions.
pub(crate) struct FakeBackend {
    name: String,
    zones: Vec<String>,
    provider: Option<Arc<DynamicProvider>>,
    applied_changes: tokio::sync::Mutex<Vec<Change>>,
}

impl FakeBackend {
    pub(crate) fn arc_with_provider(
        name: impl Into<String>,
        zones: Vec<String>,
        provider: Arc<DynamicProvider>,
    ) -> Arc<dyn Backend> {
        Arc::new(Self {
            name: name.into(),
            zones,
            provider: Some(provider),
            applied_changes: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    /// Create a `FakeBackend` without a provider (returns empty records).
    pub(crate) fn arc_empty(name: impl Into<String>, zones: Vec<String>) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            zones,
            provider: None,
            applied_changes: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    /// Return all changes that have been applied to this backend.
    pub(crate) async fn take_applied_changes(&self) -> Vec<Change> {
        let mut changes = self.applied_changes.lock().await;
        std::mem::take(&mut *changes)
    }
}

impl Named for FakeBackend {
    fn name(&self) -> &str {
        &self.name
    }
}

impl Backend for FakeBackend {
    fn zones(&self) -> Vec<String> {
        self.zones.clone()
    }

    fn get_records(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ExistingRecord>>> + Send + '_>> {
        Box::pin(async move {
            let Some(ref provider) = self.provider else {
                return Ok(Vec::new());
            };
            let desired = provider.records().await?;
            let zone = self.zones.first().cloned().unwrap_or_default();
            Ok(desired
                .into_iter()
                .enumerate()
                .map(|(i, r)| ExistingRecord {
                    id: format!("fake-{i}"),
                    record: crate::provider::EnrichedRecord {
                        zone: zone.clone(),
                        name: r.name,
                        value: r.value,
                        ttl: r.ttl,
                    },
                    managed: true,
                })
                .collect())
        })
    }

    fn apply_change<'a>(
        &'a self,
        change: &'a Change,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.applied_changes.lock().await.push(change.clone());
            Ok(())
        })
    }
}

// ── DnsServerFixture ─────────────────────────────────────────────────────────

pub(crate) const FIXTURE_KEY_NAME: &str = "client.example.com";
pub(crate) const FIXTURE_CLIENT: &str = "test-client";
pub(crate) const FIXTURE_ZONE: &str = "example.com";

pub(crate) struct DnsServerFixture {
    pub(crate) server: DnsServer,
    pub(crate) dynamic_provider: Arc<DynamicProvider>,
    pub(crate) key: TSigner,
    pub(crate) reconcile_notify: Arc<Notify>,
}

impl DnsServerFixture {
    pub(crate) async fn default_fixture() -> Self {
        Self::build(vec![FIXTURE_ZONE.to_string()]).await
    }

    pub(crate) async fn build(backend_zones: Vec<String>) -> Self {
        let mut clients = HashMap::new();
        clients.insert(
            FIXTURE_CLIENT.to_string(),
            DynamicClientConfig {
                allowed_domains: vec![format!("*.{FIXTURE_ZONE}"), FIXTURE_ZONE.to_string()],
                allowed_zones: vec![FIXTURE_ZONE.to_string()],
                rate_limit: None,
            },
        );
        Self::build_with_clients(backend_zones, clients).await
    }

    #[allow(clippy::unused_async)]
    pub(crate) async fn build_with_clients(
        backend_zones: Vec<String>,
        clients: HashMap<String, DynamicClientConfig>,
    ) -> Self {
        let dynamic_config = DynamicProviderConfig { clients };
        let dynamic_provider = Arc::new(
            DynamicProvider::new(dynamic_config, None, Metrics::noop())
                .expect("in-memory DynamicProvider should always construct"),
        );

        let backends: Vec<Arc<dyn Backend>> = vec![FakeBackend::arc_with_provider(
            "fake",
            backend_zones,
            Arc::clone(&dynamic_provider),
        )];

        let key = make_test_tsig_key(FIXTURE_KEY_NAME, TEST_TSIG_SECRET);
        let reconcile_notify = Arc::new(Notify::new());

        let dns_config = DnsServerConfig {
            listen: "[::]:0".to_string(),
            tsig_keys: Vec::new(),
        };

        let server = DnsServer::from_tsig_signers_for_test(
            &dns_config,
            vec![(
                FIXTURE_KEY_NAME.to_string(),
                make_test_tsig_key(FIXTURE_KEY_NAME, TEST_TSIG_SECRET),
                FIXTURE_CLIENT.to_string(),
            )],
            Arc::clone(&dynamic_provider),
            backends,
            Arc::clone(&reconcile_notify),
        )
        .expect("DnsServer test constructor should succeed");

        Self {
            server,
            dynamic_provider,
            key,
            reconcile_notify,
        }
    }

    pub(crate) async fn handle_signed(&self, builder: &UpdateMessageBuilder, id: u16) -> Vec<u8> {
        let msg = builder.build_signed(id, &self.key);
        self.server.handle_message(&msg).await
    }

    pub(crate) async fn seed_record(
        &self,
        zone: &str,
        name: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
    ) {
        self.dynamic_provider
            .set_record(FIXTURE_CLIENT, zone, name, record_type, value, ttl)
            .await
            .expect("seed_record should succeed");
    }

    pub(crate) async fn current_records(&self) -> Vec<(String, String, String)> {
        use crate::provider::Provider;
        self.dynamic_provider
            .records()
            .await
            .expect("records() should not fail in tests")
            .into_iter()
            .map(|r| {
                (
                    r.name.clone(),
                    r.value.type_str().to_string(),
                    r.value.value_str().clone(),
                )
            })
            .collect()
    }
}
