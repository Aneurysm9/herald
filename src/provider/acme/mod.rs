use super::{DesiredRecord, Named, Provider, ProviderReport, RecordValue};
use crate::config::AcmeProviderConfig;
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

/// Provider for ACME DNS-01 challenge TXT records.
///
/// Records are added/removed via the API server with per-client scoped tokens.
/// Each client can only manage challenges for its allowed domains. Challenges
/// are persisted to `SQLite` to survive restarts (prevents mid-challenge failures).
pub(crate) struct AcmeProvider {
    config: AcmeProviderConfig,
    /// Active challenges: keyed by FQDN of the TXT record
    challenges: Arc<RwLock<HashMap<String, ChallengeEntry>>>,
    storage: Option<Arc<Mutex<SqliteStorage<String, ChallengeEntry>>>>,
    metrics: Metrics,
    /// Parsed from `config.challenge_ttl`; challenges older than this are
    /// expired out of the desired state.
    challenge_ttl: std::time::Duration,
}

/// An active ACME challenge entry.
///
/// Stored in the provider's internal map, keyed by the FQDN of the TXT record
/// (e.g., `_acme-challenge.service1.example.org`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ChallengeEntry {
    /// The TXT record value (ACME token digest)
    pub(crate) value: String,
    /// Which client set this challenge (for ownership verification on clear)
    pub(crate) client: String,
    /// Unix timestamp (seconds) when the challenge was set. Entries persisted
    /// before this field existed deserialize as "now", starting their TTL
    /// clock at upgrade rather than expiring immediately.
    #[serde(default = "unix_now")]
    pub(crate) created_at: u64,
}

/// Current Unix time in whole seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl AcmeProvider {
    /// Create a new ACME provider.
    ///
    /// If `storage_path` is provided, challenges are persisted to `SQLite` at that path.
    /// Existing challenges are loaded from the database on startup. If `storage_path` is
    /// `None`, challenges are kept only in memory (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or existing challenges cannot be loaded.
    pub(crate) fn new(
        config: AcmeProviderConfig,
        storage_path: Option<PathBuf>,
        metrics: Metrics,
    ) -> Result<Self> {
        let (challenges_map, storage) = if let Some(path) = storage_path {
            let storage = SqliteStorage::new(&path, "acme_challenges")
                .with_context(|| format!("initializing ACME storage at {}", path.display()))?;

            // Load existing challenges from database
            let existing = storage
                .load_all()
                .context("loading existing ACME challenges from database")?;
            let challenges_map: HashMap<String, ChallengeEntry> = existing.into_iter().collect();

            tracing::info!(
                count = challenges_map.len(),
                path = %path.display(),
                "loaded ACME challenges from database"
            );

            (challenges_map, Some(Arc::new(Mutex::new(storage))))
        } else {
            tracing::warn!(
                "ACME challenge persistence disabled - challenges will be lost on restart"
            );
            (HashMap::new(), None)
        };

        let challenge_ttl = humantime::parse_duration(&config.challenge_ttl)
            .with_context(|| format!("invalid challenge_ttl: {}", config.challenge_ttl))?;

        Ok(Self {
            config,
            challenges: Arc::new(RwLock::new(challenges_map)),
            storage,
            metrics,
            challenge_ttl,
        })
    }

    /// Set an ACME challenge TXT record.
    ///
    /// Called by the API server when an ACME client requests a challenge.
    /// The `fqdn` is the full domain name of the TXT record (e.g.,
    /// `_acme-challenge.service1.example.org`).
    ///
    /// Verifies that the client has permission for the specified FQDN.
    /// Records the challenge in the internal map.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is unknown or not allowed to manage
    /// challenges for the given FQDN.
    pub(crate) async fn set_challenge(&self, client: &str, fqdn: &str, value: &str) -> Result<()> {
        let result = self.set_challenge_inner(client, fqdn, value).await;
        let status = if result.is_ok() { "success" } else { "error" };
        self.metrics.acme_operations.add(
            1,
            &[
                KeyValue::new("operation", "set"),
                KeyValue::new("status", status),
            ],
        );
        if result.is_ok() {
            self.metrics.acme_challenges_active.add(1, &[]);
        }
        result
    }

    async fn set_challenge_inner(&self, client: &str, fqdn: &str, value: &str) -> Result<()> {
        self.check_client_permission(client, fqdn)?;

        let entry = ChallengeEntry {
            value: value.to_string(),
            client: client.to_string(),
            created_at: unix_now(),
        };

        // Persist to database first — the durable store is the source of truth.
        if let Some(ref storage) = self.storage {
            let storage = Arc::clone(storage);
            let fqdn_owned = fqdn.to_string();
            let entry_clone = entry.clone();
            tokio::task::spawn_blocking(move || {
                let storage = storage.blocking_lock();
                storage.upsert(&fqdn_owned, &entry_clone)
            })
            .await
            .context("database persistence task panicked")??;
        }

        // Update in-memory state only after persistence succeeds
        let mut challenges = self.challenges.write().await;
        challenges.insert(fqdn.to_string(), entry);
        drop(challenges);

        tracing::info!(client, fqdn, "ACME challenge set");
        Ok(())
    }

    /// Clear an ACME challenge TXT record.
    ///
    /// Called by the API server when an ACME client completes validation.
    /// Only the client that created the challenge can clear it.
    ///
    /// If the challenge doesn't exist, this is a no-op (idempotent).
    ///
    /// # Errors
    ///
    /// Returns an error if the client is unknown, not allowed to manage
    /// challenges for the given FQDN, or tries to clear another client's challenge.
    pub(crate) async fn clear_challenge(&self, client: &str, fqdn: &str) -> Result<()> {
        let result = self.clear_challenge_inner(client, fqdn).await;
        let status = if result.is_ok() { "success" } else { "error" };
        self.metrics.acme_operations.add(
            1,
            &[
                KeyValue::new("operation", "clear"),
                KeyValue::new("status", status),
            ],
        );
        if result.is_ok() {
            self.metrics.acme_challenges_active.add(-1, &[]);
        }
        result
    }

    async fn clear_challenge_inner(&self, client: &str, fqdn: &str) -> Result<()> {
        self.check_client_permission(client, fqdn)?;

        // Check ownership (requires reading in-memory state)
        {
            let challenges = self.challenges.read().await;
            if let Some(existing) = challenges.get(fqdn)
                && existing.client != client
            {
                anyhow::bail!(
                    "client {client} cannot clear challenge set by {}",
                    existing.client
                );
            }
        }

        // Persist deletion to database first
        if let Some(ref storage) = self.storage {
            let storage = Arc::clone(storage);
            let fqdn_owned = fqdn.to_string();
            tokio::task::spawn_blocking(move || {
                let storage = storage.blocking_lock();
                storage.delete(&fqdn_owned)
            })
            .await
            .context("database persistence task panicked")??;
        }

        // Remove from memory only after persistence succeeds
        let mut challenges = self.challenges.write().await;
        challenges.remove(fqdn);
        drop(challenges);

        tracing::info!(client, fqdn, "ACME challenge cleared");
        Ok(())
    }

    /// Check that the given client is allowed to manage challenges for the given FQDN.
    ///
    /// Verifies the client exists in the config and delegates to the shared
    /// `check_domain_permission` utility for pattern matching.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is unknown or the FQDN doesn't match any
    /// allowed domain pattern.
    fn check_client_permission(&self, client: &str, fqdn: &str) -> Result<()> {
        let client_config = self
            .config
            .clients
            .get(client)
            .ok_or_else(|| anyhow::anyhow!("unknown ACME client: {client}"))?;

        super::check_domain_permission(client, fqdn, &client_config.allowed_domains)
    }

    /// True when a challenge is older than the configured `challenge_ttl`.
    fn is_expired(&self, entry: &ChallengeEntry, now: u64) -> bool {
        now.saturating_sub(entry.created_at) > self.challenge_ttl.as_secs()
    }

    /// Remove expired challenges from storage and memory.
    ///
    /// Storage deletion happens first, mirroring `clear_challenge` ordering;
    /// if it fails the entry is left in place and retried next cycle —
    /// `records()` excludes it from the desired state either way. Entries are
    /// re-checked under the write lock so a challenge refreshed by a
    /// concurrent `set_challenge` is not removed.
    async fn purge_expired(&self, expired: Vec<String>, now: u64) {
        for fqdn in expired {
            if let Some(ref storage) = self.storage {
                let storage = Arc::clone(storage);
                let key = fqdn.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let storage = storage.blocking_lock();
                    storage.delete(&key)
                })
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(
                            fqdn = %fqdn,
                            error = %e,
                            "failed to purge expired ACME challenge from storage; will retry"
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(fqdn = %fqdn, error = %e, "storage purge task panicked");
                        continue;
                    }
                }
            }

            let mut challenges = self.challenges.write().await;
            if let Some(entry) = challenges.get(&fqdn)
                && self.is_expired(entry, now)
            {
                let entry = challenges.remove(&fqdn);
                drop(challenges);
                tracing::warn!(
                    fqdn = %fqdn,
                    client = entry.map(|e| e.client).as_deref().unwrap_or("unknown"),
                    ttl = %self.config.challenge_ttl,
                    "ACME challenge expired without being cleared"
                );
                self.metrics.acme_challenges_active.add(-1, &[]);
                self.metrics.acme_challenges_expired.add(1, &[]);
            }
        }
    }

    /// Get a handle to the challenges map for direct access.
    ///
    /// Provides read/write access to the internal challenge store.
    /// Currently unused but available for future introspection endpoints
    /// (e.g., listing active challenges).
    #[allow(dead_code)] // Available for direct challenge store access
    pub(crate) fn challenge_store(&self) -> Arc<RwLock<HashMap<String, ChallengeEntry>>> {
        self.challenges.clone()
    }
}

impl Named for AcmeProvider {
    fn name(&self) -> &str {
        "acme"
    }
}

impl Provider for AcmeProvider {
    fn records(&self) -> Pin<Box<dyn Future<Output = Result<ProviderReport>> + Send + '_>> {
        Box::pin(async move {
            let now = unix_now();

            // Purge expired challenges (crashed clients that never cleared).
            // Expiry is intentional removal from desired state — NOT a
            // ProviderIssue. An issue would mark this report incomplete and
            // trip the reconciler's delete-guard, blocking cleanup of the
            // orphaned TXT record at the backend forever.
            let expired: Vec<String> = {
                let challenges = self.challenges.read().await;
                challenges
                    .iter()
                    .filter(|(_, entry)| self.is_expired(entry, now))
                    .map(|(fqdn, _)| fqdn.clone())
                    .collect()
            };
            if !expired.is_empty() {
                self.purge_expired(expired, now).await;
            }

            let challenges = self.challenges.read().await;
            let records = challenges
                .iter()
                .filter(|(_, entry)| !self.is_expired(entry, now))
                .map(|(fqdn, challenge)| DesiredRecord {
                    name: fqdn.clone(),
                    value: RecordValue::TXT(challenge.value.clone()),
                    ttl: 60,
                })
                .collect();
            Ok(ProviderReport::ok(records))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeClientConfig, AcmeProviderConfig};
    use crate::telemetry::Metrics;

    fn test_provider() -> AcmeProvider {
        let mut clients = HashMap::new();
        clients.insert(
            "client_a".to_string(),
            AcmeClientConfig {
                rate_limit: None,
                allowed_domains: vec!["alpha.example.com".to_string()],
            },
        );
        clients.insert(
            "client_b".to_string(),
            AcmeClientConfig {
                rate_limit: None,
                allowed_domains: vec!["beta.example.com".to_string()],
            },
        );
        AcmeProvider::new(
            AcmeProviderConfig {
                clients,
                challenge_ttl: "48h".to_string(),
            },
            None,
            Metrics::noop(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_set_challenge_allowed() {
        let provider = test_provider();
        let result = provider
            .set_challenge("client_a", "_acme-challenge.alpha.example.com", "token123")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_set_challenge_denied() {
        let provider = test_provider();
        let result = provider
            .set_challenge("client_a", "_acme-challenge.beta.example.com", "token123")
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not allowed"));
    }

    #[tokio::test]
    async fn test_set_challenge_unknown_client() {
        let provider = test_provider();
        let result = provider
            .set_challenge("nobody", "_acme-challenge.alpha.example.com", "token123")
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unknown ACME client"));
    }

    #[tokio::test]
    async fn test_clear_own_challenge() {
        let provider = test_provider();
        provider
            .set_challenge("client_a", "_acme-challenge.alpha.example.com", "token123")
            .await
            .unwrap();

        let result = provider
            .clear_challenge("client_a", "_acme-challenge.alpha.example.com")
            .await;
        assert!(result.is_ok());

        // Verify the challenge was actually removed
        let records = provider.records().await.unwrap().records;
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_clear_other_clients_challenge() {
        // Both clients need permission for the same domain to reach the ownership check
        let mut clients = HashMap::new();
        clients.insert(
            "client_a".to_string(),
            AcmeClientConfig {
                rate_limit: None,
                allowed_domains: vec!["shared.example.com".to_string()],
            },
        );
        clients.insert(
            "client_b".to_string(),
            AcmeClientConfig {
                rate_limit: None,
                allowed_domains: vec!["shared.example.com".to_string()],
            },
        );
        let provider = AcmeProvider::new(
            AcmeProviderConfig {
                clients,
                challenge_ttl: "48h".to_string(),
            },
            None,
            Metrics::noop(),
        )
        .unwrap();

        provider
            .set_challenge("client_a", "_acme-challenge.shared.example.com", "token123")
            .await
            .unwrap();

        let result = provider
            .clear_challenge("client_b", "_acme-challenge.shared.example.com")
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("cannot clear challenge set by"));
    }

    #[tokio::test]
    async fn test_clear_nonexistent_is_ok() {
        let provider = test_provider();
        let result = provider
            .clear_challenge("client_a", "_acme-challenge.alpha.example.com")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_records_returns_challenges() {
        let provider = test_provider();
        provider
            .set_challenge(
                "client_a",
                "_acme-challenge.alpha.example.com",
                "validation-digest",
            )
            .await
            .unwrap();

        let records = provider.records().await.unwrap().records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "_acme-challenge.alpha.example.com");
        assert_eq!(
            records[0].value,
            RecordValue::TXT("validation-digest".to_string())
        );
        assert_eq!(records[0].ttl, 60);
    }

    #[tokio::test]
    async fn expired_challenge_is_dropped_and_report_stays_complete() {
        let mut clients = HashMap::new();
        clients.insert(
            "client_a".to_string(),
            AcmeClientConfig {
                rate_limit: None,
                allowed_domains: vec!["*.example.com".to_string()],
            },
        );
        let config = AcmeProviderConfig {
            clients,
            challenge_ttl: "1h".to_string(),
        };
        let provider = AcmeProvider::new(config, None, Metrics::noop()).unwrap();

        // A fresh challenge set through the public API.
        provider
            .set_challenge(
                "client_a",
                "_acme-challenge.fresh.example.com",
                "fresh-token",
            )
            .await
            .unwrap();

        // An aged challenge inserted directly, created 2h ago (TTL is 1h).
        let two_hours_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 7200;
        provider.challenge_store().write().await.insert(
            "_acme-challenge.stale.example.com".to_string(),
            ChallengeEntry {
                value: "stale-token".to_string(),
                client: "client_a".to_string(),
                created_at: two_hours_ago,
            },
        );

        let report = provider.records().await.unwrap();

        // The fresh challenge is still served; the expired one is gone.
        let names: Vec<&str> = report.records.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["_acme-challenge.fresh.example.com"]);

        // Expiry is intentional removal from desired state, NOT a provider
        // issue. An issue here would trip the reconciler's delete-guard and
        // permanently block cleanup of the orphaned TXT record at the backend.
        assert!(report.is_complete());
        assert!(report.issues.is_empty());
    }

    #[tokio::test]
    async fn expired_challenge_is_purged_from_memory_and_storage() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("acme.db");

        // Seed the database with an already-expired challenge, simulating an
        // orphan left behind by a crashed ACME client before a restart.
        {
            let storage: SqliteStorage<String, ChallengeEntry> =
                SqliteStorage::new(&db_path, "acme_challenges").unwrap();
            storage
                .upsert(
                    &"_acme-challenge.stale.example.com".to_string(),
                    &ChallengeEntry {
                        value: "stale-token".to_string(),
                        client: "client_a".to_string(),
                        created_at: unix_now() - 7200,
                    },
                )
                .unwrap();
        }

        let mut clients = HashMap::new();
        clients.insert(
            "client_a".to_string(),
            AcmeClientConfig {
                rate_limit: None,
                allowed_domains: vec!["*.example.com".to_string()],
            },
        );
        let config = AcmeProviderConfig {
            clients: clients.clone(),
            challenge_ttl: "1h".to_string(),
        };
        let provider = AcmeProvider::new(config, Some(db_path.clone()), Metrics::noop()).unwrap();

        // The expired challenge is not served...
        let report = provider.records().await.unwrap();
        assert!(report.records.is_empty());
        assert!(report.is_complete());

        // ...and has been purged from the in-memory map...
        assert!(provider.challenge_store().read().await.is_empty());

        // ...and from SQLite: a fresh provider loading the same database
        // starts with no challenges.
        drop(provider);
        let config = AcmeProviderConfig {
            clients,
            challenge_ttl: "1h".to_string(),
        };
        let reloaded = AcmeProvider::new(config, Some(db_path), Metrics::noop()).unwrap();
        assert!(reloaded.challenge_store().read().await.is_empty());
    }

    #[test]
    fn invalid_challenge_ttl_is_rejected_at_construction() {
        let config = AcmeProviderConfig {
            clients: HashMap::new(),
            challenge_ttl: "not-a-duration".to_string(),
        };
        let Err(err) = AcmeProvider::new(config, None, Metrics::noop()) else {
            panic!("constructing a provider with a bad TTL should fail");
        };
        assert!(err.to_string().contains("invalid challenge_ttl"));
    }

    #[test]
    fn legacy_entry_without_created_at_starts_clock_at_load() {
        // Entries persisted before the created_at field existed must not be
        // treated as instantly expired on upgrade: the serde default stamps
        // them with "now" so their TTL clock starts at load time.
        let entry: ChallengeEntry =
            serde_json::from_str(r#"{"value":"tok","client":"client_a"}"#).unwrap();
        let now = unix_now();
        assert!(
            now - entry.created_at < 60,
            "created_at should default to ~now"
        );
    }

    #[tokio::test]
    async fn test_wildcard_domain_permission() {
        let mut clients = HashMap::new();
        clients.insert(
            "wildcard_client".to_string(),
            AcmeClientConfig {
                rate_limit: None,
                allowed_domains: vec!["*.example.com".to_string()],
            },
        );
        let provider = AcmeProvider::new(
            AcmeProviderConfig {
                clients,
                challenge_ttl: "48h".to_string(),
            },
            None,
            Metrics::noop(),
        )
        .unwrap();

        // Wildcard should match subdomains
        let result = provider
            .set_challenge(
                "wildcard_client",
                "_acme-challenge.host.example.com",
                "token123",
            )
            .await;
        assert!(result.is_ok());

        // Wildcard should also match deeper subdomains
        let result = provider
            .set_challenge(
                "wildcard_client",
                "_acme-challenge.deep.sub.example.com",
                "token456",
            )
            .await;
        assert!(result.is_ok());
    }
}
