use std::future::Future;
use std::pin::Pin;

use super::{DesiredRecord, Named, Provider, RecordValue};
use crate::config::StaticProviderConfig;
use anyhow::Result;

/// Provider that contributes a fixed set of records from configuration.
///
/// Record values are parsed from config strings into `RecordValue` at construction
/// time. Invalid records are logged and skipped.
pub(crate) struct StaticProvider {
    records: Vec<DesiredRecord>,
}

impl StaticProvider {
    /// Creates a new static provider from the given configuration.
    ///
    /// Static records are parsed into [`DesiredRecord`] format and stored
    /// internally. They never change at runtime. Records with invalid types
    /// or values are skipped with an error log.
    pub(crate) fn new(config: &StaticProviderConfig) -> Self {
        let records = config
            .records
            .iter()
            .filter_map(|r| match RecordValue::parse(&r.r#type, &r.value) {
                Ok(value) => Some(DesiredRecord {
                    name: r.name.clone(),
                    value,
                    ttl: r.ttl,
                }),
                Err(e) => {
                    tracing::error!(
                        name = %r.name,
                        record_type = %r.r#type,
                        error = %e,
                        "skipping invalid static record"
                    );
                    None
                }
            })
            .collect();
        Self { records }
    }
}

impl Named for StaticProvider {
    fn name(&self) -> &str {
        "static"
    }
}

impl Provider for StaticProvider {
    fn records(&self) -> Pin<Box<dyn Future<Output = Result<Vec<DesiredRecord>>> + Send + '_>> {
        let records = self.records.clone();
        Box::pin(async move { Ok(records) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{StaticProviderConfig, StaticRecord};
    use crate::provider::RecordValue;

    fn make_record(name: &str, record_type: &str, value: &str) -> StaticRecord {
        StaticRecord {
            name: name.to_string(),
            r#type: record_type.to_string(),
            value: value.to_string(),
            ttl: 300,
        }
    }

    #[test]
    fn test_empty_records_list() {
        let provider = StaticProvider::new(&StaticProviderConfig { records: vec![] });
        assert_eq!(provider.name(), "static");
        assert!(provider.records.is_empty());
    }

    #[test]
    fn test_valid_a_record_is_stored() {
        let provider = StaticProvider::new(&StaticProviderConfig {
            records: vec![make_record("www.example.com", "A", "203.0.113.1")],
        });
        assert_eq!(provider.records.len(), 1);
        assert_eq!(provider.records[0].name, "www.example.com");
        assert_eq!(
            provider.records[0].value,
            RecordValue::A("203.0.113.1".parse().unwrap())
        );
        assert_eq!(provider.records[0].ttl, 300);
    }

    #[test]
    fn test_valid_aaaa_record_is_stored() {
        let provider = StaticProvider::new(&StaticProviderConfig {
            records: vec![make_record("ipv6.example.com", "AAAA", "2001:db8::1")],
        });
        assert_eq!(
            provider.records[0].value,
            RecordValue::AAAA("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn test_valid_cname_record_is_stored() {
        let provider = StaticProvider::new(&StaticProviderConfig {
            records: vec![make_record(
                "alias.example.com",
                "CNAME",
                "target.example.com",
            )],
        });
        assert_eq!(
            provider.records[0].value,
            RecordValue::CNAME("target.example.com".to_string())
        );
    }

    #[test]
    fn test_valid_txt_record_is_stored() {
        let provider = StaticProvider::new(&StaticProviderConfig {
            records: vec![make_record("example.com", "TXT", "v=spf1 ~all")],
        });
        assert_eq!(
            provider.records[0].value,
            RecordValue::TXT("v=spf1 ~all".to_string())
        );
    }

    #[test]
    fn test_explicit_ttl_is_preserved() {
        let provider = StaticProvider::new(&StaticProviderConfig {
            records: vec![StaticRecord {
                name: "www.example.com".to_string(),
                r#type: "A".to_string(),
                value: "1.2.3.4".to_string(),
                ttl: 60,
            }],
        });
        assert_eq!(provider.records[0].ttl, 60);
    }

    #[test]
    fn test_invalid_record_type_is_skipped() {
        let provider = StaticProvider::new(&StaticProviderConfig {
            records: vec![
                make_record("good.example.com", "A", "1.2.3.4"),
                make_record("bad.example.com", "BOGUSTYPE", "somevalue"),
            ],
        });
        // Only the valid record is kept
        assert_eq!(provider.records.len(), 1);
        assert_eq!(provider.records[0].name, "good.example.com");
    }

    #[test]
    fn test_invalid_ip_value_is_skipped() {
        let provider = StaticProvider::new(&StaticProviderConfig {
            records: vec![
                make_record("good.example.com", "A", "1.2.3.4"),
                make_record("bad.example.com", "A", "not-an-ip-address"),
            ],
        });
        assert_eq!(provider.records.len(), 1);
        assert_eq!(provider.records[0].name, "good.example.com");
    }

    #[test]
    fn test_all_invalid_records_yields_empty_provider() {
        let provider = StaticProvider::new(&StaticProviderConfig {
            records: vec![
                make_record("a.example.com", "UNKNOWN", "value"),
                make_record("b.example.com", "A", "not-an-ip"),
            ],
        });
        assert!(provider.records.is_empty());
    }

    #[tokio::test]
    async fn test_records_returns_all_stored() {
        let provider = StaticProvider::new(&StaticProviderConfig {
            records: vec![
                make_record("a.example.com", "A", "1.1.1.1"),
                make_record("b.example.com", "A", "2.2.2.2"),
            ],
        });
        let records = Provider::records(&provider).await.unwrap();
        assert_eq!(records.len(), 2);
    }
}
