use super::error::DnsError;
use crate::backend::Backend;
use crate::provider::RecordValue;
use crate::provider::dynamic::DynamicProvider;
use crate::zone_util::derive_zone;
use hickory_proto::rr::{DNSClass, RData, RecordType};
use std::sync::Arc;

/// A validated but not-yet-applied update action. Separating validation from
/// mutation ensures atomicity per RFC 2136 §3.4: all RRs are validated first,
/// and mutations only happen if every RR passes.
pub(super) enum ValidatedUpdate {
    Set {
        client: String,
        zone: String,
        name: String,
        type_name: String,
        value: String,
        ttl: u32,
    },
    Delete {
        client: String,
        zone: String,
        name: String,
        type_name: String,
    },
    DeleteType {
        client: String,
        zone: String,
        name: String,
        type_name: String,
    },
    DeleteAll {
        client: String,
        zone: String,
        name: String,
    },
    Skip,
}

/// Validate a single update RR without mutating state. Returns a
/// `ValidatedUpdate` that can be applied later, ensuring atomicity
/// per RFC 2136 §3.4: if any RR fails validation, no updates are applied.
pub(super) fn validate_update_record(
    client: &str,
    record: &hickory_proto::rr::Record,
    backends: &[Arc<dyn Backend>],
    dynamic_provider: &DynamicProvider,
) -> Result<ValidatedUpdate, DnsError> {
    let name = record.name.to_utf8();
    let name = name.trim_end_matches('.').to_string();
    let rtype = record.record_type();
    let dns_class = record.dns_class;

    let (zone, _) = derive_zone(&name, backends)
        .map_err(|_| DnsError::NotZone(format!("no zone found for {name}")))?;

    dynamic_provider
        .check_permission(client, &zone, &name)
        .map_err(|e| DnsError::Refused(e.to_string()))?;

    let has_rdata = !matches!(&record.data, RData::Update0(..));
    let ttl = record.ttl;

    if dns_class == DNSClass::ANY && !has_rdata && rtype == RecordType::ANY {
        return Ok(ValidatedUpdate::DeleteAll {
            client: client.to_string(),
            zone,
            name,
        });
    }

    let type_name = match rtype {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::TXT => "TXT",
        RecordType::MX => "MX",
        RecordType::NS => "NS",
        _ => return Ok(ValidatedUpdate::Skip),
    };

    match dns_class {
        DNSClass::IN if has_rdata => {
            let value = RecordValue::try_from(&record.data).map_err(|e| {
                DnsError::FormErr(format!("undecodable RDATA for {name} {type_name}: {e}"))
            })?;
            Ok(ValidatedUpdate::Set {
                client: client.to_string(),
                zone,
                name,
                type_name: type_name.to_string(),
                value: value.value_str().clone(),
                ttl,
            })
        }
        DNSClass::NONE if has_rdata => Ok(ValidatedUpdate::Delete {
            client: client.to_string(),
            zone,
            name,
            type_name: type_name.to_string(),
        }),
        DNSClass::ANY if !has_rdata => Ok(ValidatedUpdate::DeleteType {
            client: client.to_string(),
            zone,
            name,
            type_name: type_name.to_string(),
        }),
        _ => Ok(ValidatedUpdate::Skip),
    }
}

/// Apply a previously validated update action to the dynamic provider.
pub(super) async fn apply_validated_update(
    action: ValidatedUpdate,
    dynamic_provider: &DynamicProvider,
) -> Result<(), DnsError> {
    match action {
        ValidatedUpdate::Set {
            client,
            zone,
            name,
            type_name,
            value,
            ttl,
        } => {
            dynamic_provider
                .set_record(&client, &zone, &name, &type_name, &value, ttl)
                .await
                .map_err(|e| DnsError::Refused(e.to_string()))?;
            tracing::debug!(
                client,
                name,
                record_type = type_name,
                zone,
                "DNS UPDATE: record added"
            );
        }
        ValidatedUpdate::Delete {
            client,
            zone,
            name,
            type_name,
        } => {
            dynamic_provider
                .delete_record(&client, &zone, &name, &type_name)
                .await
                .map_err(|e| DnsError::Refused(e.to_string()))?;
            tracing::debug!(
                client,
                name,
                record_type = type_name,
                zone,
                "DNS UPDATE: record deleted"
            );
        }
        ValidatedUpdate::DeleteType {
            client,
            zone,
            name,
            type_name,
        } => {
            dynamic_provider
                .delete_record(&client, &zone, &name, &type_name)
                .await
                .map_err(|e| DnsError::Refused(e.to_string()))?;
            tracing::debug!(
                client,
                name,
                record_type = type_name,
                zone,
                "DNS UPDATE: RRset deleted"
            );
        }
        ValidatedUpdate::DeleteAll { client, zone, name } => {
            dynamic_provider
                .delete_all_for_name(&client, &zone, &name)
                .await
                .map_err(|e| DnsError::Refused(e.to_string()))?;
            tracing::debug!(
                client,
                name,
                zone,
                "DNS UPDATE: all records for name deleted"
            );
        }
        ValidatedUpdate::Skip => {}
    }
    Ok(())
}
