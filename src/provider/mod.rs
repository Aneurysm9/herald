pub(crate) mod acme;
pub(crate) mod dynamic;
pub(crate) mod mirror;
pub(crate) mod record_type;
pub(crate) mod record_value;
pub(crate) mod r#static;

pub(crate) use record_type::RecordType;
pub(crate) use record_value::RecordValue;

use anyhow::Result;
use serde::Serialize;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A desired DNS record as emitted by providers (before zone enrichment).
///
/// Providers specify only the FQDN, type, value, and TTL. The reconciler derives
/// the zone using longest-suffix matching against backend zone declarations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DesiredRecord {
    /// Fully qualified domain name (e.g., "www.example.com")
    pub name: String,
    /// Record type and value combined
    pub value: RecordValue,
    /// TTL in seconds
    pub ttl: u32,
}

impl fmt::Display for DesiredRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} (ttl={})",
            self.name,
            self.value.type_str(),
            self.value,
            self.ttl
        )
    }
}

/// Serializes to a flat JSON format for API compatibility:
/// `{"name": "...", "record_type": "A", "value": "...", "ttl": 300}`
impl Serialize for DesiredRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("DesiredRecord", 4)?;
        s.serialize_field("name", &self.name)?;
        s.serialize_field("record_type", self.value.type_str())?;
        s.serialize_field("value", &self.value.value_str())?;
        s.serialize_field("ttl", &self.ttl)?;
        s.end()
    }
}

/// An enriched DNS record with zone information (after zone derivation).
///
/// The reconciler enriches `DesiredRecord` into `EnrichedRecord` by deriving the
/// zone field. This ensures that all records reaching backends have a guaranteed
/// zone, preventing runtime errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EnrichedRecord {
    /// Which DNS zone this record belongs to (derived from FQDN using
    /// longest-suffix matching against backend zone declarations)
    pub zone: String,
    /// Fully qualified domain name (e.g., "www.example.com")
    pub name: String,
    /// Record type and value combined
    pub value: RecordValue,
    /// TTL in seconds
    pub ttl: u32,
}

impl fmt::Display for EnrichedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} {} (ttl={})",
            self.zone,
            self.name,
            self.value.type_str(),
            self.value,
            self.ttl
        )
    }
}

/// Shared sub-trait for named components (providers and backends).
pub(crate) trait Named {
    /// Returns the name of this component (for logging and diagnostics).
    fn name(&self) -> &str;
}

/// Trait that all record providers must implement.
///
/// Each provider contributes records to a unified desired-state set.
/// Providers are independent and composable.
pub(crate) trait Provider: Named + Send + Sync {
    /// Returns the current set of desired DNS records from this provider.
    fn records(&self) -> Pin<Box<dyn Future<Output = Result<Vec<DesiredRecord>>> + Send + '_>>;
}

/// Check that a client is allowed to manage records for the given FQDN.
///
/// Matches `fqdn` against the provided `allowed_domains` patterns.
/// Supports wildcard matching: `*.example.org` matches `host.example.org`,
/// `deep.sub.example.org`, etc.
///
/// # Errors
///
/// Returns an error if the FQDN doesn't match any allowed domain pattern.
pub(crate) fn check_domain_permission(
    client: &str,
    fqdn: &str,
    allowed_domains: &[String],
) -> Result<()> {
    let allowed = allowed_domains.iter().any(|d| {
        let pattern = d.strip_prefix("*.").unwrap_or(d.as_str());
        fqdn.ends_with(pattern)
    });

    if !allowed {
        anyhow::bail!("client {client} is not allowed to manage records for {fqdn}");
    }

    Ok(())
}

impl<T: Named> Named for Arc<T> {
    fn name(&self) -> &str {
        T::name(self)
    }
}

/// Blanket impl so `Arc<T: Provider>` can be used as `Box<dyn Provider>`.
/// This is needed because `AcmeProvider` and `MirrorProvider` are shared
/// between background tasks and the provider list.
impl<T: Provider> Provider for Arc<T> {
    fn records(&self) -> Pin<Box<dyn Future<Output = Result<Vec<DesiredRecord>>> + Send + '_>> {
        T::records(self)
    }
}
