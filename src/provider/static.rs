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
