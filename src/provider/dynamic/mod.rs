use super::{DesiredRecord, Named, Provider, RecordValue, check_domain_permission};
use crate::config::DynamicProviderConfig;
use crate::storage::SqliteStorage;
use crate::telemetry::Metrics;
use anyhow::{Context, Result};
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Key for indexing dynamic records.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RecordKey {
    /// DNS zone (e.g., "example.com")
    pub(crate) zone: String,
    /// Fully qualified domain name (e.g., "wan.example.com")
    pub(crate) name: String,
    /// Record type as a string (e.g., "A", "AAAA", "CNAME")
    pub(crate) record_type: String,
}

impl crate::storage::StorageKey for RecordKey {
    fn to_sql(&self) -> String {
        // Use | as separator (valid DNS names don't contain |)
        format!("{}|{}|{}", self.zone, self.name, self.record_type)
    }

    fn from_sql(s: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = s.split('|').collect();
        if parts.len() != 3 {
            anyhow::bail!(
                "invalid RecordKey format: expected 3 parts, got {}",
                parts.len()
            );
        }
        Ok(Self {
            zone: parts[0].to_string(),
            name: parts[1].to_string(),
            record_type: parts[2].to_string(),
        })
    }
}

/// An active dynamic DNS entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DynamicEntry {
    /// The DNS record value (e.g., IP address, hostname)
    pub(crate) value: String,
    /// Time-to-live in seconds
    pub(crate) ttl: u32,
    /// The authenticated client that created this record
    pub(crate) client: String,
}

/// Provider for dynamic DNS records managed via the API.
///
/// Clients can create, update, and delete arbitrary DNS records, scoped
/// by `allowed_domains` and `allowed_zones`. Records are persisted to `SQLite`
/// and participate in reconciliation like any other provider.
pub(crate) struct DynamicProvider {
    config: DynamicProviderConfig,
    records: Arc<RwLock<HashMap<RecordKey, DynamicEntry>>>,
    storage: Option<Arc<Mutex<SqliteStorage<RecordKey, DynamicEntry>>>>,
    metrics: Metrics,
}

impl DynamicProvider {
    /// Create a new dynamic DNS provider.
    ///
    /// If `storage_path` is provided, records are persisted to `SQLite` at that path.
    /// Existing records are loaded from the database on startup. If `storage_path` is
    /// `None`, records are kept only in memory (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or existing records cannot be loaded.
    pub(crate) fn new(
        config: DynamicProviderConfig,
        storage_path: Option<PathBuf>,
        metrics: Metrics,
    ) -> Result<Self> {
        let (records_map, storage) = if let Some(path) = storage_path {
            let storage = SqliteStorage::new(&path, "dynamic_records").with_context(|| {
                format!("initializing dynamic DNS storage at {}", path.display())
            })?;

            // Load existing records from database
            let existing = storage
                .load_all()
                .context("loading existing dynamic DNS records from database")?;
            let records_map: HashMap<RecordKey, DynamicEntry> = existing.into_iter().collect();

            tracing::info!(
                count = records_map.len(),
                path = %path.display(),
                "loaded dynamic DNS records from database"
            );

            (records_map, Some(Arc::new(Mutex::new(storage))))
        } else {
            tracing::warn!("dynamic DNS persistence disabled - records will be lost on restart");
            (HashMap::new(), None)
        };

        Ok(Self {
            config,
            records: Arc::new(RwLock::new(records_map)),
            storage,
            metrics,
        })
    }

    /// Set (create or update) a dynamic DNS record.
    ///
    /// Checks that the client has permission for both the domain name and the zone.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is unknown, not allowed to manage the
    /// domain, or not allowed to target the zone.
    pub(crate) async fn set_record(
        &self,
        client: &str,
        zone: &str,
        name: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
    ) -> Result<()> {
        let result = self
            .set_record_inner(client, zone, name, record_type, value, ttl)
            .await;
        let status = if result.is_ok() { "success" } else { "error" };
        self.metrics.dynamic_operations.add(
            1,
            &[
                KeyValue::new("operation", "set"),
                KeyValue::new("status", status),
            ],
        );
        if result.is_ok() {
            let count = self.records.read().await.len();
            self.metrics
                .dynamic_records_active
                .record(count as u64, &[]);
        }
        result
    }

    async fn set_record_inner(
        &self,
        client: &str,
        zone: &str,
        name: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
    ) -> Result<()> {
        self.check_permission(client, zone, name)?;

        let key = RecordKey {
            zone: zone.to_string(),
            name: name.to_string(),
            record_type: record_type.to_string(),
        };

        let entry = DynamicEntry {
            value: value.to_string(),
            ttl,
            client: client.to_string(),
        };

        // Update in-memory state
        let mut records = self.records.write().await;
        records.insert(key.clone(), entry.clone());
        drop(records); // Release lock before I/O

        // Persist to database (blocking I/O)
        if let Some(ref storage) = self.storage {
            let storage = Arc::clone(storage);
            let key_clone = key.clone();
            let entry_clone = entry.clone();
            tokio::task::spawn_blocking(move || {
                let storage = storage.blocking_lock();
                storage.upsert(&key_clone, &entry_clone)
            })
            .await
            .context("database persistence task panicked")??;
        }

        tracing::info!(client, zone, name, record_type, "dynamic record set");
        Ok(())
    }

    /// Delete a dynamic DNS record.
    ///
    /// Only the client that created the record can delete it.
    /// Deleting a nonexistent record is a no-op (idempotent).
    ///
    /// # Errors
    ///
    /// Returns an error if the client is unknown, not allowed to manage the
    /// domain/zone, or tries to delete another client's record.
    pub(crate) async fn delete_record(
        &self,
        client: &str,
        zone: &str,
        name: &str,
        record_type: &str,
    ) -> Result<()> {
        let result = self
            .delete_record_inner(client, zone, name, record_type)
            .await;
        let status = if result.is_ok() { "success" } else { "error" };
        self.metrics.dynamic_operations.add(
            1,
            &[
                KeyValue::new("operation", "delete"),
                KeyValue::new("status", status),
            ],
        );
        if result.is_ok() {
            let count = self.records.read().await.len();
            self.metrics
                .dynamic_records_active
                .record(count as u64, &[]);
        }
        result
    }

    async fn delete_record_inner(
        &self,
        client: &str,
        zone: &str,
        name: &str,
        record_type: &str,
    ) -> Result<()> {
        self.check_permission(client, zone, name)?;

        let key = RecordKey {
            zone: zone.to_string(),
            name: name.to_string(),
            record_type: record_type.to_string(),
        };

        // Check ownership and delete from memory
        let mut records = self.records.write().await;
        if let Some(existing) = records.get(&key) {
            if existing.client != client {
                anyhow::bail!(
                    "client {client} cannot delete record owned by {}",
                    existing.client
                );
            }
            records.remove(&key);
        }
        drop(records); // Release lock before I/O

        // Persist deletion to database (blocking I/O)
        if let Some(ref storage) = self.storage {
            let storage = Arc::clone(storage);
            let key_clone = key.clone();
            tokio::task::spawn_blocking(move || {
                let storage = storage.blocking_lock();
                storage.delete(&key_clone)
            })
            .await
            .context("database persistence task panicked")??;
        }

        tracing::info!(client, zone, name, record_type, "dynamic record deleted");
        Ok(())
    }

    /// Delete all dynamic DNS records for a given name, regardless of type.
    ///
    /// Only records owned by the specified client are deleted. Records owned
    /// by other clients are left untouched.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is unknown or not permitted for the
    /// domain/zone.
    pub(crate) async fn delete_all_for_name(
        &self,
        client: &str,
        zone: &str,
        name: &str,
    ) -> Result<()> {
        self.check_permission(client, zone, name)?;

        let mut records = self.records.write().await;
        let keys_to_delete: Vec<RecordKey> = records
            .iter()
            .filter(|(k, v)| k.zone == zone && k.name == name && v.client == client)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &keys_to_delete {
            records.remove(key);
        }
        drop(records);

        if let Some(ref storage) = self.storage {
            for key in keys_to_delete {
                let storage = Arc::clone(storage);
                tokio::task::spawn_blocking(move || {
                    let storage = storage.blocking_lock();
                    storage.delete(&key)
                })
                .await
                .context("database persistence task panicked")??;
            }
        }

        tracing::info!(client, zone, name, "dynamic records deleted (all types)");
        Ok(())
    }

    /// Check that the client has permission for both the domain and the zone.
    pub(crate) fn check_permission(&self, client: &str, zone: &str, name: &str) -> Result<()> {
        let client_config = self
            .config
            .clients
            .get(client)
            .ok_or_else(|| anyhow::anyhow!("unknown dynamic client: {client}"))?;

        // Check domain permission
        check_domain_permission(client, name, &client_config.allowed_domains)?;

        // Check zone permission
        if !client_config.allowed_zones.iter().any(|z| z == zone) {
            anyhow::bail!("client {client} is not allowed to target zone {zone}");
        }

        Ok(())
    }
}

impl Named for DynamicProvider {
    fn name(&self) -> &str {
        "dynamic"
    }
}

impl Provider for DynamicProvider {
    fn records(&self) -> Pin<Box<dyn Future<Output = Result<Vec<DesiredRecord>>> + Send + '_>> {
        Box::pin(async move {
            let records = self.records.read().await;
            let result = records
                .iter()
                .filter_map(|(key, entry)| {
                    match RecordValue::parse(&key.record_type, &entry.value) {
                        Ok(value) => Some(DesiredRecord {
                            name: key.name.clone(),
                            value,
                            ttl: entry.ttl,
                        }),
                        Err(e) => {
                            tracing::error!(
                                name = %key.name,
                                record_type = %key.record_type,
                                error = %e,
                                "skipping invalid dynamic record"
                            );
                            None
                        }
                    }
                })
                .collect();
            Ok(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DynamicClientConfig, DynamicProviderConfig};
    use crate::telemetry::Metrics;
    use std::collections::HashMap;

    fn test_provider() -> DynamicProvider {
        let mut clients = HashMap::new();
        clients.insert(
            "opnsense".to_string(),
            DynamicClientConfig {
                allowed_domains: vec!["*.example.com".to_string()],
                allowed_zones: vec!["example.com".to_string()],
            },
        );
        clients.insert(
            "other".to_string(),
            DynamicClientConfig {
                allowed_domains: vec!["other.example.org".to_string()],
                allowed_zones: vec!["example.org".to_string()],
            },
        );
        DynamicProvider::new(DynamicProviderConfig { clients }, None, Metrics::noop()).unwrap()
    }

    #[tokio::test]
    async fn test_set_record_allowed() {
        let provider = test_provider();
        let result = provider
            .set_record(
                "opnsense",
                "example.com",
                "wan.example.com",
                "A",
                "198.51.100.1",
                60,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_set_record_denied_domain() {
        let provider = test_provider();
        let result = provider
            .set_record(
                "opnsense",
                "example.com",
                "bad.example.org",
                "A",
                "1.2.3.4",
                60,
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not allowed"));
    }

    #[tokio::test]
    async fn test_set_record_denied_zone() {
        let provider = test_provider();
        let result = provider
            .set_record(
                "opnsense",
                "example.org",
                "wan.example.com",
                "A",
                "1.2.3.4",
                60,
            )
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not allowed to target zone")
        );
    }

    #[tokio::test]
    async fn test_set_record_unknown_client() {
        let provider = test_provider();
        let result = provider
            .set_record(
                "nobody",
                "example.com",
                "wan.example.com",
                "A",
                "1.2.3.4",
                60,
            )
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown dynamic client")
        );
    }

    #[tokio::test]
    async fn test_delete_own_record() {
        let provider = test_provider();
        provider
            .set_record(
                "opnsense",
                "example.com",
                "wan.example.com",
                "A",
                "198.51.100.1",
                60,
            )
            .await
            .unwrap();

        let result = provider
            .delete_record("opnsense", "example.com", "wan.example.com", "A")
            .await;
        assert!(result.is_ok());

        let records = provider.records().await.unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_delete_other_clients_record() {
        // opnsense and other both need permission for the same domain+zone for the ownership check
        let mut clients = HashMap::new();
        clients.insert(
            "owner".to_string(),
            DynamicClientConfig {
                allowed_domains: vec!["shared.example.com".to_string()],
                allowed_zones: vec!["example.com".to_string()],
            },
        );
        clients.insert(
            "thief".to_string(),
            DynamicClientConfig {
                allowed_domains: vec!["shared.example.com".to_string()],
                allowed_zones: vec!["example.com".to_string()],
            },
        );
        let provider =
            DynamicProvider::new(DynamicProviderConfig { clients }, None, Metrics::noop()).unwrap();

        provider
            .set_record(
                "owner",
                "example.com",
                "shared.example.com",
                "A",
                "1.2.3.4",
                60,
            )
            .await
            .unwrap();

        let result = provider
            .delete_record("thief", "example.com", "shared.example.com", "A")
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cannot delete record owned by")
        );
    }

    #[tokio::test]
    async fn test_delete_nonexistent_is_ok() {
        let provider = test_provider();
        let result = provider
            .delete_record("opnsense", "example.com", "wan.example.com", "A")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_records_returns_entries() {
        let provider = test_provider();
        provider
            .set_record(
                "opnsense",
                "example.com",
                "wan.example.com",
                "A",
                "198.51.100.1",
                60,
            )
            .await
            .unwrap();

        let records = provider.records().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "wan.example.com");
        assert_eq!(
            records[0].value,
            RecordValue::parse("A", "198.51.100.1").unwrap()
        );
        assert_eq!(records[0].ttl, 60);
    }

    #[tokio::test]
    async fn test_update_overwrites() {
        let provider = test_provider();
        provider
            .set_record(
                "opnsense",
                "example.com",
                "wan.example.com",
                "A",
                "198.51.100.1",
                60,
            )
            .await
            .unwrap();

        provider
            .set_record(
                "opnsense",
                "example.com",
                "wan.example.com",
                "A",
                "198.51.100.2",
                120,
            )
            .await
            .unwrap();

        let records = provider.records().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].value,
            RecordValue::parse("A", "198.51.100.2").unwrap()
        );
        assert_eq!(records[0].ttl, 120);
    }
}
