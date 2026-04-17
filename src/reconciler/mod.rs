use crate::backend::{Backend, Change};
use crate::provider::{DesiredRecord, EnrichedRecord, Provider};
use crate::telemetry::Metrics;
use crate::zone_util;
use anyhow::Result;
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// The reconciler diffs desired state (from providers) against actual state
/// (from backends) and produces a set of changes to converge.
pub(crate) struct Reconciler {
    dry_run: bool,
    metrics: Metrics,
}

impl Reconciler {
    /// Creates a new reconciler with the given settings.
    ///
    /// # Arguments
    ///
    /// * `dry_run` - If true, changes are logged but not applied to the backend
    /// * `metrics` - OpenTelemetry metrics instruments for observability
    pub(crate) fn new(dry_run: bool, metrics: Metrics) -> Self {
        Self { dry_run, metrics }
    }

    /// Run a single reconciliation pass.
    ///
    /// This method:
    /// 1. Collects desired records from all providers
    /// 2. Derives zones for records without explicit zones (using longest-suffix matching)
    /// 3. Fetches actual records from all backends
    /// 4. Diffs desired vs actual, producing changes (create/update/delete)
    /// 5. Partitions changes by backend and applies them
    ///
    /// The reconciler only touches records tagged with `managed: true` at the
    /// backends. Unmanaged records (created manually) are never modified or deleted.
    ///
    /// Provider errors are logged but don't halt reconciliation — healthy
    /// providers continue contributing records.
    ///
    /// Backend failures during record fetching are logged and that backend's records
    /// are skipped, but reconciliation continues with healthy backends.
    ///
    /// # Errors
    ///
    /// Returns an error if no backends are configured or if zone derivation fails
    /// for any record.
    pub(crate) async fn reconcile(
        &self,
        providers: &[Arc<dyn Provider>],
        backends: &[Arc<dyn Backend>],
    ) -> Result<()> {
        let start = Instant::now();

        if backends.is_empty() {
            anyhow::bail!("no backends configured");
        }

        // 1. Collect desired records from all providers
        let desired_raw = self.collect_desired_records(providers).await;

        // 2. Enrich records with derived zones
        let desired = Self::enrich_zones(desired_raw, backends)?;

        // 3. Get existing records from all backends
        let all_existing = self.collect_existing_records(backends).await;

        // 4. Diff to compute changes
        let changes = Self::diff(&desired, &all_existing);

        if changes.is_empty() {
            tracing::info!("no changes needed");
            self.metrics.reconciliation_runs.add(1, &[]);
            return Ok(());
        }

        // 5. Partition changes by backend and record metrics
        let changes_by_backend = Self::partition_changes_by_backend(&changes, backends)?;
        self.record_change_metrics(&changes);

        // 6. Log and apply changes
        for change in &changes {
            tracing::info!(%change, "planned change");
        }

        if self.dry_run {
            tracing::info!(count = changes.len(), "dry-run: changes not applied");
        } else {
            self.apply_changes(changes_by_backend, backends).await;
        }

        let elapsed = start.elapsed().as_secs_f64();
        self.metrics
            .reconciliation_runs
            .add(1, &[KeyValue::new("status", "success")]);
        self.metrics.reconciliation_duration.record(elapsed, &[]);

        Ok(())
    }

    /// Collect desired records from all providers.
    ///
    /// Continues on provider errors to ensure one failing provider doesn't block others.
    async fn collect_desired_records(&self, providers: &[Arc<dyn Provider>]) -> Vec<DesiredRecord> {
        let mut desired = Vec::new();
        for provider in providers {
            match provider.records().await {
                Ok(records) => {
                    tracing::debug!(
                        provider = provider.name(),
                        count = records.len(),
                        "collected records"
                    );
                    self.metrics.provider_records.record(
                        records.len() as u64,
                        &[KeyValue::new("provider", provider.name().to_string())],
                    );
                    desired.extend(records);
                }
                Err(e) => {
                    tracing::error!(provider = provider.name(), error = %e, "failed to collect records");
                    self.metrics
                        .provider_errors
                        .add(1, &[KeyValue::new("provider", provider.name().to_string())]);
                }
            }
        }
        desired
    }

    /// Enrich records with derived zones.
    ///
    /// Converts `DesiredRecord` (without zone) into `EnrichedRecord` (with required zone).
    /// Derives the zone using longest-suffix matching against backend zone declarations.
    fn enrich_zones(
        records: Vec<DesiredRecord>,
        backends: &[Arc<dyn Backend>],
    ) -> Result<Vec<EnrichedRecord>> {
        records
            .into_iter()
            .map(|record| {
                let (zone, _backend_idx) = zone_util::derive_zone(&record.name, backends)?;
                Ok(EnrichedRecord {
                    zone,
                    name: record.name,
                    value: record.value,
                    ttl: record.ttl,
                })
            })
            .collect()
    }

    /// Collect existing records from all backends.
    ///
    /// Continues on backend errors to ensure one failing backend doesn't block others.
    async fn collect_existing_records(
        &self,
        backends: &[Arc<dyn Backend>],
    ) -> Vec<crate::backend::ExistingRecord> {
        let mut all_existing = Vec::new();
        for backend in backends {
            match backend.get_records().await {
                Ok(mut existing) => {
                    tracing::debug!(
                        backend = backend.name(),
                        count = existing.len(),
                        "fetched existing records"
                    );
                    all_existing.append(&mut existing);
                }
                Err(e) => {
                    tracing::error!(
                        backend = backend.name(),
                        error = %e,
                        "failed to get records from backend"
                    );
                    self.metrics
                        .provider_errors
                        .add(1, &[KeyValue::new("provider", backend.name().to_string())]);
                }
            }
        }
        all_existing
    }

    /// Partition changes by backend based on zone ownership.
    fn partition_changes_by_backend<'a>(
        changes: &'a [Change],
        backends: &[Arc<dyn Backend>],
    ) -> Result<HashMap<usize, Vec<&'a Change>>> {
        let mut changes_by_backend: HashMap<usize, Vec<&Change>> = HashMap::new();
        for change in changes {
            let zone = match change {
                Change::Create(r) => &r.zone,
                Change::Update { new, .. } => &new.zone,
                Change::Delete(er) => &er.record.zone,
            };

            let backend_idx = backends
                .iter()
                .position(|b| b.zones().contains(zone))
                .ok_or_else(|| anyhow::anyhow!("no backend found for zone {zone}"))?;

            changes_by_backend
                .entry(backend_idx)
                .or_default()
                .push(change);
        }
        Ok(changes_by_backend)
    }

    /// Record per-change-type metrics.
    fn record_change_metrics(&self, changes: &[Change]) {
        for change in changes {
            let change_type = match change {
                Change::Create(_) => "create",
                Change::Update { .. } => "update",
                Change::Delete(_) => "delete",
            };
            self.metrics
                .reconciliation_changes
                .add(1, &[KeyValue::new("change_type", change_type)]);
        }
    }

    /// Apply changes to backends.
    async fn apply_changes(
        &self,
        changes_by_backend: HashMap<usize, Vec<&Change>>,
        backends: &[Arc<dyn Backend>],
    ) {
        for (backend_idx, backend_changes) in changes_by_backend {
            let backend = &backends[backend_idx];
            tracing::info!(
                backend = backend.name(),
                changes = backend_changes.len(),
                "applying changes to backend"
            );

            for change in backend_changes {
                if let Err(e) = backend.apply_change(change).await {
                    tracing::error!(%change, error = %e, "failed to apply change");
                }
            }
        }
        tracing::info!("changes applied");
    }

    /// Diff desired records against existing records, producing a list of changes.
    ///
    /// This function supports multi-value DNS records (e.g., round-robin A records,
    /// multiple MX records) by grouping records into sets by (zone, name, type) and
    /// performing set-based comparison.
    ///
    /// Algorithm:
    /// 1. Group desired and existing records by (zone, name, type) key
    /// 2. For each key, compare the multi-value record sets:
    ///    - Match records by (value, ttl)
    ///    - Create missing desired records (prefer UPDATE if managed record available)
    ///    - Delete managed existing records not in desired set
    /// 3. Handle unmanaged conflicts (warn, don't modify)
    fn diff(
        desired: &[EnrichedRecord],
        existing: &[crate::backend::ExistingRecord],
    ) -> Vec<Change> {
        use std::collections::HashSet;

        type RecordKey = (String, String, String); // (zone, name, type_str)

        // Group desired records by key → Vec<EnrichedRecord>
        let mut desired_map: HashMap<RecordKey, Vec<EnrichedRecord>> = HashMap::new();
        for record in desired {
            let key = (
                record.zone.clone(),
                record.name.clone(),
                record.value.type_str().to_string(),
            );
            desired_map.entry(key).or_default().push(record.clone());
        }

        // Group existing records by key → Vec<ExistingRecord>
        let mut existing_map: HashMap<RecordKey, Vec<crate::backend::ExistingRecord>> =
            HashMap::new();
        for record in existing {
            let key = (
                record.record.zone.clone(),
                record.record.name.clone(),
                record.record.value.type_str().to_string(),
            );
            existing_map.entry(key).or_default().push(record.clone());
        }

        let mut changes = Vec::new();

        // Collect all unique keys from both maps
        let all_keys: HashSet<RecordKey> = desired_map
            .keys()
            .chain(existing_map.keys())
            .cloned()
            .collect();

        // For each key, compare multi-value record sets
        for key in all_keys {
            let desired_set = desired_map.get(&key).cloned().unwrap_or_default();
            let existing_set = existing_map.get(&key).cloned().unwrap_or_default();

            // Track which existing records have been matched to desired records
            let mut matched_existing: HashSet<usize> = HashSet::new();

            // First pass: find exact matches (same value + ttl)
            for desired_rec in &desired_set {
                if let Some((idx, _)) = existing_set.iter().enumerate().find(|(idx, e)| {
                    !matched_existing.contains(idx)
                        && e.record.value == desired_rec.value
                        && e.record.ttl == desired_rec.ttl
                }) {
                    // Exact match found — mark as matched
                    matched_existing.insert(idx);
                }
            }

            // Check if there are ANY unmanaged records in this set
            // If so, be conservative and skip creates (but allow managed updates/deletes)
            let has_unmanaged_records = existing_set.iter().any(|e| !e.managed);

            // Second pass: create or update records not matched
            for desired_rec in &desired_set {
                // Check if this desired record was already matched
                let already_matched = existing_set.iter().enumerate().any(|(idx, e)| {
                    matched_existing.contains(&idx)
                        && e.record.value == desired_rec.value
                        && e.record.ttl == desired_rec.ttl
                });

                if already_matched {
                    continue; // Already in sync
                }

                // Need to create or update
                // Prefer updating an unmatched managed record
                if let Some((idx, existing_rec)) = existing_set
                    .iter()
                    .enumerate()
                    .find(|(idx, e)| e.managed && !matched_existing.contains(idx))
                {
                    // Update this managed record
                    changes.push(Change::Update {
                        id: existing_rec.id.clone(),
                        old: existing_rec.record.clone(),
                        new: desired_rec.clone(),
                    });
                    matched_existing.insert(idx);
                } else if has_unmanaged_records {
                    // Unmanaged records exist for this key — be conservative, skip create
                    tracing::warn!(
                        name = %desired_rec.name,
                        record_type = desired_rec.value.type_str(),
                        value = %desired_rec.value,
                        "skipping create due to unmanaged records at this key"
                    );
                } else {
                    // No managed record to update, no unmanaged conflicts — create new
                    changes.push(Change::Create(desired_rec.clone()));
                }
            }

            // Third pass: delete unmatched managed records
            for (idx, existing_rec) in existing_set.iter().enumerate() {
                if existing_rec.managed && !matched_existing.contains(&idx) {
                    changes.push(Change::Delete(existing_rec.clone()));
                }
            }
        }

        changes
    }
}

#[cfg(test)]
mod tests {
    #[allow(clippy::wildcard_imports)]
    use super::*;
    use crate::backend::ExistingRecord;
    use crate::provider::{Named, RecordValue};
    use crate::telemetry::Metrics;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    fn desired(name: &str, rtype: &str, value: &str) -> DesiredRecord {
        DesiredRecord {
            name: name.to_string(),
            value: RecordValue::parse(rtype, value).unwrap(),
            ttl: 300,
        }
    }

    fn enriched(name: &str, rtype: &str, value: &str) -> EnrichedRecord {
        EnrichedRecord {
            zone: "example.com".to_string(),
            name: name.to_string(),
            value: RecordValue::parse(rtype, value).unwrap(),
            ttl: 300,
        }
    }

    fn managed(id: &str, name: &str, rtype: &str, value: &str) -> ExistingRecord {
        ExistingRecord {
            id: id.to_string(),
            record: enriched(name, rtype, value),
            managed: true,
        }
    }

    fn unmanaged(id: &str, name: &str, rtype: &str, value: &str) -> ExistingRecord {
        ExistingRecord {
            id: id.to_string(),
            record: enriched(name, rtype, value),
            managed: false,
        }
    }

    struct StubProvider {
        label: &'static str,
        desired: Vec<DesiredRecord>,
        fail: bool,
    }

    impl Named for StubProvider {
        fn name(&self) -> &str {
            self.label
        }
    }

    impl Provider for StubProvider {
        fn records(&self) -> Pin<Box<dyn Future<Output = Result<Vec<DesiredRecord>>> + Send + '_>> {
            let fail = self.fail;
            let desired = self.desired.clone();
            Box::pin(async move {
                if fail {
                    anyhow::bail!("stub provider error");
                }
                Ok(desired)
            })
        }
    }

    struct StubBackend {
        zones: Vec<String>,
        existing: Vec<ExistingRecord>,
        apply_count: Arc<Mutex<usize>>,
    }

    impl StubBackend {
        fn new(zones: Vec<String>, existing: Vec<ExistingRecord>) -> (Self, Arc<Mutex<usize>>) {
            let count = Arc::new(Mutex::new(0_usize));
            (
                Self {
                    zones,
                    existing,
                    apply_count: Arc::clone(&count),
                },
                count,
            )
        }
    }

    impl Named for StubBackend {
        fn name(&self) -> &str {
            "stub"
        }
    }

    impl Backend for StubBackend {
        fn zones(&self) -> Vec<String> {
            self.zones.clone()
        }

        fn get_records(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<ExistingRecord>>> + Send + '_>> {
            let existing = self.existing.clone();
            Box::pin(async move { Ok(existing) })
        }

        fn apply_change<'a>(
            &'a self,
            _change: &'a Change,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                *self.apply_count.lock().unwrap() += 1;
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn test_create_new_record() {
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![desired("www.example.com", "A", "1.2.3.4")],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(vec!["example.com".to_string()], vec![]);

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_no_changes_when_in_sync() {
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![desired("www.example.com", "A", "1.2.3.4")],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![managed("rec1", "www.example.com", "A", "1.2.3.4")],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        assert_eq!(*apply_count.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_update_changed_value() {
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![desired("www.example.com", "A", "2.2.2.2")],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![managed("rec1", "www.example.com", "A", "1.1.1.1")],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_update_changed_ttl() {
        let reconciler = Reconciler::new(false, Metrics::noop());
        let desired_rec = DesiredRecord {
            ttl: 600,
            ..desired("www.example.com", "A", "1.2.3.4")
        };
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![desired_rec],
            fail: false,
        });
        // Existing record has ttl=300 (default from helper)
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![managed("rec1", "www.example.com", "A", "1.2.3.4")],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_delete_stale_managed() {
        let reconciler = Reconciler::new(false, Metrics::noop());
        // No desired records
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![],
            fail: false,
        });
        // But a managed record exists at the backend
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![managed("rec1", "old.example.com", "A", "1.1.1.1")],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_skip_unmanaged_delete() {
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![],
            fail: false,
        });
        // Unmanaged record exists — should NOT be deleted
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![unmanaged("rec1", "manual.example.com", "A", "1.1.1.1")],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        assert_eq!(*apply_count.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_skip_unmanaged_conflict() {
        let reconciler = Reconciler::new(false, Metrics::noop());
        // Desired record that conflicts with an unmanaged existing record
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![desired("manual.example.com", "A", "2.2.2.2")],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![unmanaged("rec1", "manual.example.com", "A", "1.1.1.1")],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // No create (record exists) and no update (unmanaged) → empty
        assert_eq!(*apply_count.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_dry_run_skips_apply() {
        let reconciler = Reconciler::new(true, Metrics::noop()); // dry_run = true
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![desired("new.example.com", "A", "1.2.3.4")],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(vec!["example.com".to_string()], vec![]);

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // Changes are computed but never applied
        assert_eq!(*apply_count.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_provider_error_continues() {
        let reconciler = Reconciler::new(false, Metrics::noop());
        let failing: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "failing",
            desired: vec![],
            fail: true,
        });
        let healthy: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "healthy",
            desired: vec![desired("ok.example.com", "A", "1.2.3.4")],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(vec!["example.com".to_string()], vec![]);

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler
            .reconcile(&[failing, healthy], backends)
            .await
            .unwrap();

        // The healthy provider's record still produces a Create
        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_same_name_different_zones_coexist() {
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("www.example.com", "A", "1.1.1.1"),
                desired("www.example.org", "A", "2.2.2.2"),
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string(), "example.org".to_string()],
            vec![],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // Both records should be created (different zones)
        assert_eq!(*apply_count.lock().unwrap(), 2);
    }

    // ========== Multi-Value Record Tests ==========

    #[tokio::test]
    async fn test_round_robin_a_records_create() {
        // Test creating multiple A records for the same name (round-robin DNS)
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("lb.example.com", "A", "1.1.1.1"),
                desired("lb.example.com", "A", "2.2.2.2"),
                desired("lb.example.com", "A", "3.3.3.3"),
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(vec!["example.com".to_string()], vec![]);

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // All 3 A records should be created
        assert_eq!(*apply_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_round_robin_no_changes_when_in_sync() {
        // Test that multiple A records already in sync produce no changes
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("lb.example.com", "A", "1.1.1.1"),
                desired("lb.example.com", "A", "2.2.2.2"),
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![
                managed("rec1", "lb.example.com", "A", "1.1.1.1"),
                managed("rec2", "lb.example.com", "A", "2.2.2.2"),
            ],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // No changes needed
        assert_eq!(*apply_count.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_round_robin_add_one_ip() {
        // Test adding one more IP to existing round-robin set
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("lb.example.com", "A", "1.1.1.1"),
                desired("lb.example.com", "A", "2.2.2.2"),
                desired("lb.example.com", "A", "3.3.3.3"), // New
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![
                managed("rec1", "lb.example.com", "A", "1.1.1.1"),
                managed("rec2", "lb.example.com", "A", "2.2.2.2"),
            ],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // 1 create for the new IP
        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_round_robin_remove_one_ip() {
        // Test removing one IP from existing round-robin set
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("lb.example.com", "A", "1.1.1.1"),
                // 2.2.2.2 removed
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![
                managed("rec1", "lb.example.com", "A", "1.1.1.1"),
                managed("rec2", "lb.example.com", "A", "2.2.2.2"), // Should be deleted
            ],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // 1 delete for the removed IP
        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_round_robin_update_one_ip() {
        // Test updating one IP in a round-robin set
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("lb.example.com", "A", "1.1.1.1"),
                desired("lb.example.com", "A", "9.9.9.9"), // Changed from 2.2.2.2
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![
                managed("rec1", "lb.example.com", "A", "1.1.1.1"),
                managed("rec2", "lb.example.com", "A", "2.2.2.2"),
            ],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // 1 update: rec2 gets updated from 2.2.2.2 to 9.9.9.9
        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_multiple_mx_records() {
        // Test multiple MX records with different priorities
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("example.com", "MX", "10:mail1.example.com"),
                desired("example.com", "MX", "20:mail2.example.com"),
                desired("example.com", "MX", "30:mail3.example.com"),
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(vec!["example.com".to_string()], vec![]);

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // All 3 MX records should be created
        assert_eq!(*apply_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_multiple_txt_records() {
        // Test multiple TXT records (e.g., SPF + DKIM + DMARC)
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("example.com", "TXT", "v=spf1 include:_spf.example.com ~all"),
                desired("example.com", "TXT", "v=DKIM1; k=rsa; p=MIGfMA0GCS..."),
                desired(
                    "example.com",
                    "TXT",
                    "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
                ),
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(vec!["example.com".to_string()], vec![]);

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // All 3 TXT records should be created
        assert_eq!(*apply_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_multi_value_mixed_operations() {
        // Test mixed create/update/delete in multi-value set
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("lb.example.com", "A", "1.1.1.1"), // Keep
                desired("lb.example.com", "A", "2.2.2.2"), // Keep
                desired("lb.example.com", "A", "4.4.4.4"), // New value
                                                           // 3.3.3.3 will be removed
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![
                managed("rec1", "lb.example.com", "A", "1.1.1.1"), // Keep
                managed("rec2", "lb.example.com", "A", "2.2.2.2"), // Keep
                managed("rec3", "lb.example.com", "A", "3.3.3.3"), // Will be updated
            ],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // Algorithm prefers UPDATE over CREATE+DELETE:
        // rec3 gets updated from 3.3.3.3 → 4.4.4.4 (more efficient than delete+create)
        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_multi_value_replace_all() {
        // Test replacing entire multi-value set
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("lb.example.com", "A", "10.0.0.1"),
                desired("lb.example.com", "A", "10.0.0.2"),
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![
                managed("rec1", "lb.example.com", "A", "1.1.1.1"),
                managed("rec2", "lb.example.com", "A", "2.2.2.2"),
            ],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // 2 updates: rec1→10.0.0.1, rec2→10.0.0.2
        assert_eq!(*apply_count.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn test_multi_value_with_unmanaged_conflict() {
        // Test that unmanaged records in multi-value set are not touched
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("lb.example.com", "A", "1.1.1.1"),
                desired("lb.example.com", "A", "2.2.2.2"), // Conflicts with unmanaged
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![
                managed("rec1", "lb.example.com", "A", "9.9.9.9"), // Will be updated to 1.1.1.1
                unmanaged("rec2", "lb.example.com", "A", "2.2.2.2"), // Conflict - skip create
            ],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // 1 update (rec1), 2.2.2.2 skipped due to unmanaged conflict
        assert_eq!(*apply_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_multi_value_true_create_and_delete() {
        // Test that algorithm can still do CREATE+DELETE when needed
        // (all existing managed records are already matched)
        let reconciler = Reconciler::new(false, Metrics::noop());
        let provider: Arc<dyn Provider> = Arc::new(StubProvider {
            label: "test",
            desired: vec![
                desired("lb.example.com", "A", "1.1.1.1"), // Keep
                desired("lb.example.com", "A", "2.2.2.2"), // Keep
                desired("lb.example.com", "A", "4.4.4.4"), // Create (new)
                desired("lb.example.com", "A", "5.5.5.5"), // Create (new)
                                                           // 3.3.3.3 will be deleted
            ],
            fail: false,
        });
        let (backend, apply_count) = StubBackend::new(
            vec!["example.com".to_string()],
            vec![
                managed("rec1", "lb.example.com", "A", "1.1.1.1"), // Keep
                managed("rec2", "lb.example.com", "A", "2.2.2.2"), // Keep
                managed("rec3", "lb.example.com", "A", "3.3.3.3"), // Delete
            ],
        );

        let backends: &[Arc<dyn Backend>] = &[Arc::new(backend) as Arc<dyn Backend>];
        reconciler.reconcile(&[provider], backends).await.unwrap();

        // 1 update (rec3 → 4.4.4.4) + 1 create (5.5.5.5) + 0 delete = 2 changes
        // Note: rec3 gets updated to accommodate one of the new values
        assert_eq!(*apply_count.lock().unwrap(), 2);
    }
}
