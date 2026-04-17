pub(crate) mod cloudflare;
pub(crate) mod rfc2136;
pub(crate) mod technitium;

use crate::provider::{EnrichedRecord, Named};
use anyhow::Result;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

/// Represents a DNS record as it exists at the backend.
#[derive(Debug, Clone)]
pub(crate) struct ExistingRecord {
    /// Backend-specific record ID (e.g., Cloudflare record ID)
    pub id: String,
    /// The DNS record data
    pub record: EnrichedRecord,
    /// Whether this record is managed by Herald (has the "managed-by: herald" comment tag)
    pub managed: bool,
}

/// A change to apply to the backend.
#[derive(Debug)]
pub(crate) enum Change {
    Create(EnrichedRecord),
    Update {
        id: String,
        old: EnrichedRecord,
        new: EnrichedRecord,
    },
    Delete(ExistingRecord),
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Change::Create(r) => write!(f, "CREATE {r}"),
            Change::Update { old, new, .. } => write!(f, "UPDATE {old} -> {new}"),
            Change::Delete(r) => write!(f, "DELETE {}", r.record),
        }
    }
}

/// Trait that all DNS backends must implement.
pub(crate) trait Backend: Named + Send + Sync {
    /// Returns the list of DNS zones this backend manages.
    ///
    /// Used by the reconciler to determine which backend should handle
    /// a given FQDN via longest suffix matching.
    fn zones(&self) -> Vec<String>;

    /// Fetch all existing records managed by this backend.
    fn get_records(&self)
    -> Pin<Box<dyn Future<Output = Result<Vec<ExistingRecord>>> + Send + '_>>;

    /// Apply a single change.
    fn apply_change<'a>(
        &'a self,
        change: &'a Change,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}
