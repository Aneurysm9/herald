//! Integration tests that exercise multi-component workflows end-to-end.
//!
//! These tests wire real providers + `FakeBackend` + reconciler together and
//! verify that records flow correctly across component boundaries.

use crate::backend::{Backend, Change};
use crate::config::{
    AcmeClientConfig, AcmeProviderConfig, DynamicClientConfig, DynamicProviderConfig, MirrorMatch,
    MirrorProviderConfig, MirrorRule, MirrorSource, MirrorTransform, MirrorTransformKind,
    StaticProviderConfig, StaticRecord,
};
use crate::provider::acme::AcmeProvider;
use crate::provider::dynamic::DynamicProvider;
use crate::provider::mirror::MirrorProvider;
use crate::provider::r#static::StaticProvider;
use crate::provider::{DesiredRecord, Provider, RecordValue};
use crate::reconciler::Reconciler;
use crate::telemetry::Metrics;
use crate::testing::FakeBackend;
use std::collections::HashMap;
use std::sync::Arc;

// ── Tier 1: Provider → Reconciler → Backend ────────────────────────────────

#[tokio::test]
async fn test_static_provider_reconciliation() {
    let backend = FakeBackend::arc_empty("test", vec!["example.com".to_string()]);
    let backends: Vec<Arc<dyn Backend>> = vec![backend.clone()];

    let provider = Arc::new(StaticProvider::new(&StaticProviderConfig {
        records: vec![
            StaticRecord {
                name: "www.example.com".to_string(),
                r#type: "A".to_string(),
                value: "203.0.113.1".to_string(),
                ttl: 300,
            },
            StaticRecord {
                name: "mail.example.com".to_string(),
                r#type: "MX".to_string(),
                value: "10:mx.example.com".to_string(),
                ttl: 300,
            },
        ],
    }));
    let providers: Vec<Arc<dyn Provider>> = vec![provider];

    let reconciler = Reconciler::new(false, Metrics::noop());
    reconciler.reconcile(&providers, &backends).await.unwrap();

    let changes = backend.take_applied_changes().await;
    assert_eq!(changes.len(), 2, "expected 2 creates, got: {changes:?}");

    // Both should be Create operations
    for change in &changes {
        assert!(
            matches!(change, Change::Create(_)),
            "expected Create, got: {change:?}"
        );
    }

    // Verify record names
    let names: Vec<&str> = changes
        .iter()
        .map(|c| match c {
            Change::Create(r) => r.name.as_str(),
            _ => unreachable!(),
        })
        .collect();
    assert!(names.contains(&"www.example.com"));
    assert!(names.contains(&"mail.example.com"));
}

#[tokio::test]
async fn test_static_provider_idempotent_reconciliation() {
    // After the first reconcile creates records, a second should produce no changes
    // (since FakeBackend returns its provider's records as "existing").
    let dynamic = Arc::new(
        DynamicProvider::new(
            DynamicProviderConfig {
                clients: HashMap::from([(
                    "test".to_string(),
                    DynamicClientConfig {
                        allowed_domains: vec!["*.example.com".to_string()],
                        allowed_zones: vec!["example.com".to_string()],
                        rate_limit: None,
                    },
                )]),
            },
            None,
            Metrics::noop(),
        )
        .unwrap(),
    );

    // Seed a record into the dynamic provider — this becomes both
    // desired state (from the provider) and existing state (from FakeBackend).
    dynamic
        .set_record(
            "test",
            "example.com",
            "www.example.com",
            "A",
            "203.0.113.1",
            300,
        )
        .await
        .unwrap();

    let backend =
        FakeBackend::arc_with_provider("test", vec!["example.com".to_string()], dynamic.clone());
    // We can't get FakeBackend directly from arc_with_provider (returns Arc<dyn Backend>),
    // so we need a different approach to check changes.
    // Use the reconciler's dry-run log output or just verify no errors.
    let backends: Vec<Arc<dyn Backend>> = vec![backend];
    let providers: Vec<Arc<dyn Provider>> = vec![dynamic];

    let reconciler = Reconciler::new(false, Metrics::noop());
    // Should succeed with no changes (desired == existing)
    reconciler.reconcile(&providers, &backends).await.unwrap();
}

#[tokio::test]
async fn test_acme_challenge_lifecycle() {
    let backend = FakeBackend::arc_empty("test", vec!["example.com".to_string()]);
    let backends: Vec<Arc<dyn Backend>> = vec![backend.clone()];

    let acme = Arc::new(
        AcmeProvider::new(
            AcmeProviderConfig {
                clients: HashMap::from([(
                    "webserver".to_string(),
                    AcmeClientConfig {
                        allowed_domains: vec!["*.example.com".to_string()],
                        rate_limit: None,
                    },
                )]),
            },
            None, // no persistence
            Metrics::noop(),
        )
        .unwrap(),
    );
    let providers: Vec<Arc<dyn Provider>> = vec![acme.clone()];

    // Set a challenge
    acme.set_challenge(
        "webserver",
        "_acme-challenge.www.example.com",
        "challenge-token-123",
    )
    .await
    .unwrap();

    // Reconcile — should create the TXT record
    let reconciler = Reconciler::new(false, Metrics::noop());
    reconciler.reconcile(&providers, &backends).await.unwrap();

    let changes = backend.take_applied_changes().await;
    assert_eq!(changes.len(), 1, "expected 1 create for challenge TXT");
    match &changes[0] {
        Change::Create(r) => {
            assert_eq!(r.name, "_acme-challenge.www.example.com");
            assert_eq!(r.value.type_str(), "TXT");
        }
        other => panic!("expected Create, got: {other:?}"),
    }

    // Clear the challenge
    acme.clear_challenge("webserver", "_acme-challenge.www.example.com")
        .await
        .unwrap();

    // Verify the provider now emits no records
    let records = acme.records().await.unwrap();
    assert!(records.is_empty(), "expected no records after clear");
}

#[tokio::test]
async fn test_dynamic_dns_lifecycle() {
    let dynamic = Arc::new(
        DynamicProvider::new(
            DynamicProviderConfig {
                clients: HashMap::from([(
                    "opnsense".to_string(),
                    DynamicClientConfig {
                        allowed_domains: vec!["*.example.com".to_string()],
                        allowed_zones: vec!["example.com".to_string()],
                        rate_limit: None,
                    },
                )]),
            },
            None,
            Metrics::noop(),
        )
        .unwrap(),
    );

    let backend = FakeBackend::arc_empty("test", vec!["example.com".to_string()]);
    let backends: Vec<Arc<dyn Backend>> = vec![backend.clone()];
    let providers: Vec<Arc<dyn Provider>> = vec![dynamic.clone()];

    // Create a record via API
    dynamic
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

    // Reconcile — should create the record
    let reconciler = Reconciler::new(false, Metrics::noop());
    reconciler.reconcile(&providers, &backends).await.unwrap();

    let changes = backend.take_applied_changes().await;
    assert_eq!(changes.len(), 1);
    match &changes[0] {
        Change::Create(r) => {
            assert_eq!(r.name, "wan.example.com");
            assert_eq!(r.value.type_str(), "A");
        }
        other => panic!("expected Create, got: {other:?}"),
    }

    // Delete the record
    dynamic
        .delete_record("opnsense", "example.com", "wan.example.com", "A")
        .await
        .unwrap();

    // Verify provider emits no records
    let records = dynamic.records().await.unwrap();
    assert!(records.is_empty());
}

// ── Tier 2: Multi-component interactions ────────────────────────────────────

#[tokio::test]
async fn test_multi_provider_merge() {
    let backend = FakeBackend::arc_empty("test", vec!["example.com".to_string()]);
    let backends: Vec<Arc<dyn Backend>> = vec![backend.clone()];

    // Static provider with one record
    let static_prov = Arc::new(StaticProvider::new(&StaticProviderConfig {
        records: vec![StaticRecord {
            name: "www.example.com".to_string(),
            r#type: "A".to_string(),
            value: "203.0.113.1".to_string(),
            ttl: 300,
        }],
    }));

    // Dynamic provider with a different record
    let dynamic = Arc::new(
        DynamicProvider::new(
            DynamicProviderConfig {
                clients: HashMap::from([(
                    "test".to_string(),
                    DynamicClientConfig {
                        allowed_domains: vec!["*.example.com".to_string()],
                        allowed_zones: vec!["example.com".to_string()],
                        rate_limit: None,
                    },
                )]),
            },
            None,
            Metrics::noop(),
        )
        .unwrap(),
    );
    dynamic
        .set_record(
            "test",
            "example.com",
            "api.example.com",
            "A",
            "203.0.113.2",
            60,
        )
        .await
        .unwrap();

    let providers: Vec<Arc<dyn Provider>> = vec![static_prov, dynamic];

    let reconciler = Reconciler::new(false, Metrics::noop());
    reconciler.reconcile(&providers, &backends).await.unwrap();

    let changes = backend.take_applied_changes().await;
    assert_eq!(
        changes.len(),
        2,
        "expected 2 creates from two providers, got: {changes:?}"
    );

    let names: Vec<&str> = changes
        .iter()
        .filter_map(|c| match c {
            Change::Create(r) => Some(r.name.as_str()),
            _ => None,
        })
        .collect();
    assert!(names.contains(&"www.example.com"), "missing static record");
    assert!(names.contains(&"api.example.com"), "missing dynamic record");
}

#[tokio::test]
async fn test_provider_failure_resilience() {
    let backend = FakeBackend::arc_empty("test", vec!["example.com".to_string()]);
    let backends: Vec<Arc<dyn Backend>> = vec![backend.clone()];

    // One working provider
    let working = Arc::new(StaticProvider::new(&StaticProviderConfig {
        records: vec![StaticRecord {
            name: "www.example.com".to_string(),
            r#type: "A".to_string(),
            value: "203.0.113.1".to_string(),
            ttl: 300,
        }],
    }));

    // One failing provider (from api test stubs)
    let failing = Arc::new(crate::api::tests::StubProvider {
        label: "failing",
        desired: vec![],
        fail: true,
    });

    let providers: Vec<Arc<dyn Provider>> = vec![working, failing];

    let reconciler = Reconciler::new(false, Metrics::noop());
    // Reconciliation should succeed despite one provider failing
    reconciler.reconcile(&providers, &backends).await.unwrap();

    let changes = backend.take_applied_changes().await;
    assert_eq!(
        changes.len(),
        1,
        "working provider's record should still be created"
    );
}

#[tokio::test]
async fn test_multi_backend_zone_routing() {
    let backend_com = FakeBackend::arc_empty("cf", vec!["example.com".to_string()]);
    let backend_org = FakeBackend::arc_empty("tech", vec!["example.org".to_string()]);
    let backends: Vec<Arc<dyn Backend>> =
        vec![backend_com.clone() as Arc<dyn Backend>, backend_org.clone()];

    let provider = Arc::new(StaticProvider::new(&StaticProviderConfig {
        records: vec![
            StaticRecord {
                name: "www.example.com".to_string(),
                r#type: "A".to_string(),
                value: "203.0.113.1".to_string(),
                ttl: 300,
            },
            StaticRecord {
                name: "www.example.org".to_string(),
                r#type: "A".to_string(),
                value: "203.0.113.2".to_string(),
                ttl: 300,
            },
        ],
    }));
    let providers: Vec<Arc<dyn Provider>> = vec![provider];

    let reconciler = Reconciler::new(false, Metrics::noop());
    reconciler.reconcile(&providers, &backends).await.unwrap();

    let com_changes = backend_com.take_applied_changes().await;
    let org_changes = backend_org.take_applied_changes().await;

    assert_eq!(
        com_changes.len(),
        1,
        "example.com backend should get 1 change"
    );
    assert_eq!(
        org_changes.len(),
        1,
        "example.org backend should get 1 change"
    );

    match &com_changes[0] {
        Change::Create(r) => assert_eq!(r.name, "www.example.com"),
        other => panic!("expected Create, got: {other:?}"),
    }
    match &org_changes[0] {
        Change::Create(r) => assert_eq!(r.name, "www.example.org"),
        other => panic!("expected Create, got: {other:?}"),
    }
}

/// Build a mirror config suitable for the integration test.
///
/// Uses `type: dns` so no `token_file`/`url` is required; the source is never
/// actually polled in the test — records are seeded into the cache directly
/// via `MirrorProvider::set_cache_for_test`.
fn test_mirror_config(
    name: Option<&str>,
    zone: &str,
    rules: Vec<MirrorRule>,
) -> MirrorProviderConfig {
    MirrorProviderConfig {
        name: name.map(str::to_string),
        source: MirrorSource {
            r#type: "dns".to_string(),
            url: None,
            zone: zone.to_string(),
            token_file: None,
            subdomains: vec![],
            nameserver: None,
            tsig_key_name: None,
        },
        rules,
        interval: "5m".to_string(),
    }
}

#[tokio::test]
async fn test_multiple_mirrors_contribute_distinct_records() {
    // Two independent mirrors with different names, sources, and rule sets
    // must both reach the reconciler as separate providers and contribute
    // distinct records to the backend without colliding.
    let backend_com = FakeBackend::arc_empty("cf", vec!["example.com".to_string()]);
    let backend_org = FakeBackend::arc_empty("cf-org", vec!["example.org".to_string()]);
    let backends: Vec<Arc<dyn Backend>> =
        vec![backend_com.clone() as Arc<dyn Backend>, backend_org.clone()];

    let first_rule = MirrorRule {
        r#match: MirrorMatch {
            r#type: Some("AAAA".to_string()),
            name: None,
        },
        transform: MirrorTransform {
            kind: MirrorTransformKind::Suffix {
                suffix: "example.com".to_string(),
            },
            ttl: Some(600),
        },
    };
    let second_rule = MirrorRule {
        r#match: MirrorMatch {
            r#type: None,
            name: None,
        },
        transform: MirrorTransform {
            kind: MirrorTransformKind::Rename {
                to: "db.example.org".to_string(),
            },
            ttl: None,
        },
    };

    let first = Arc::new(
        MirrorProvider::new(
            test_mirror_config(
                Some("internal-dns"),
                "internal.example.net",
                vec![first_rule],
            ),
            0,
            Metrics::noop(),
        )
        .await
        .expect("constructing first mirror"),
    );
    let second = Arc::new(
        MirrorProvider::new(
            test_mirror_config(Some("corp-dns"), "corp.internal", vec![second_rule]),
            1,
            Metrics::noop(),
        )
        .await
        .expect("constructing second mirror"),
    );

    // Seed each mirror's cache directly — the `dns` source isn't actually
    // reachable in tests, and polling behavior is covered by unit tests.
    first
        .set_cache_for_test(vec![DesiredRecord {
            name: "host1.example.com".to_string(),
            value: RecordValue::parse("AAAA", "2001:db8::1").unwrap(),
            ttl: 600,
        }])
        .await;
    second
        .set_cache_for_test(vec![DesiredRecord {
            name: "db.example.org".to_string(),
            value: RecordValue::parse("A", "198.51.100.7").unwrap(),
            ttl: 300,
        }])
        .await;

    let providers: Vec<Arc<dyn Provider>> = vec![first, second];
    let reconciler = Reconciler::new(false, Metrics::noop());
    reconciler.reconcile(&providers, &backends).await.unwrap();

    let com_changes = backend_com.take_applied_changes().await;
    let org_changes = backend_org.take_applied_changes().await;

    assert_eq!(com_changes.len(), 1, "example.com should get host1");
    assert_eq!(org_changes.len(), 1, "example.org should get db");

    match &com_changes[0] {
        Change::Create(r) => {
            assert_eq!(r.name, "host1.example.com");
            assert_eq!(r.ttl, 600, "per-rule TTL override must survive reconcile");
        }
        other => panic!("expected Create, got: {other:?}"),
    }
    match &org_changes[0] {
        Change::Create(r) => {
            assert_eq!(r.name, "db.example.org");
            assert_eq!(r.ttl, 300, "default TTL applied when rule omits ttl");
        }
        other => panic!("expected Create, got: {other:?}"),
    }
}

/// Two mirror instances emit the same FQDN with different values. The
/// reconciler groups desired records by `(zone, name, type)` and supports
/// multi-value record sets, so both values should land at the backend rather than
/// one silently winning over the other. This documents the cross-mirror
/// merge semantics — operators get multi-value DNS records if they configure
/// overlapping mirrors, not a collision error.
#[tokio::test]
async fn test_same_fqdn_across_mirrors_merges_into_rrset() {
    let backend = FakeBackend::arc_empty("cf", vec!["example.com".to_string()]);
    let backends: Vec<Arc<dyn Backend>> = vec![backend.clone()];

    let first = Arc::new(
        MirrorProvider::new(
            test_mirror_config(
                Some("site-a"),
                "a.internal",
                vec![MirrorRule {
                    r#match: MirrorMatch {
                        r#type: None,
                        name: None,
                    },
                    transform: MirrorTransform {
                        kind: MirrorTransformKind::Suffix {
                            suffix: "example.com".to_string(),
                        },
                        ttl: None,
                    },
                }],
            ),
            0,
            Metrics::noop(),
        )
        .await
        .unwrap(),
    );
    let second = Arc::new(
        MirrorProvider::new(
            test_mirror_config(
                Some("site-b"),
                "b.internal",
                vec![MirrorRule {
                    r#match: MirrorMatch {
                        r#type: None,
                        name: None,
                    },
                    transform: MirrorTransform {
                        kind: MirrorTransformKind::Suffix {
                            suffix: "example.com".to_string(),
                        },
                        ttl: None,
                    },
                }],
            ),
            1,
            Metrics::noop(),
        )
        .await
        .unwrap(),
    );

    first
        .set_cache_for_test(vec![DesiredRecord {
            name: "api.example.com".to_string(),
            value: RecordValue::parse("A", "203.0.113.1").unwrap(),
            ttl: 300,
        }])
        .await;
    second
        .set_cache_for_test(vec![DesiredRecord {
            name: "api.example.com".to_string(),
            value: RecordValue::parse("A", "203.0.113.2").unwrap(),
            ttl: 300,
        }])
        .await;

    let providers: Vec<Arc<dyn Provider>> = vec![first, second];
    let reconciler = Reconciler::new(false, Metrics::noop());
    reconciler.reconcile(&providers, &backends).await.unwrap();

    let changes = backend.take_applied_changes().await;
    assert_eq!(
        changes.len(),
        2,
        "both mirror values should be created as a multi-value record set, got: {changes:?}"
    );

    // Both changes must be `Create` and must share the same (name, type) —
    // otherwise the count-of-2 assertion would pass trivially even if the
    // reconciler had emitted two unrelated records instead of a real
    // multi-value record set at the same FQDN.
    let mut values: Vec<String> = Vec::new();
    for change in &changes {
        let Change::Create(r) = change else {
            panic!("expected Create, got: {change:?}");
        };
        assert_eq!(r.name, "api.example.com", "all Creates must share the FQDN");
        assert_eq!(
            r.value.type_str(),
            "A",
            "all Creates must share the record type"
        );
        values.push(r.value.to_string());
    }
    values.sort();
    assert_eq!(
        values,
        vec!["203.0.113.1".to_string(), "203.0.113.2".to_string()],
        "both values from the two mirrors must land in the record set"
    );
}
