use super::error::DnsError;
use crate::backend::{Backend, ExistingRecord};
use crate::provider::RecordValue;
use crate::zone_util::derive_zone;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, RData, RecordType};
use std::collections::HashMap;
use std::sync::Arc;

/// Evaluate RFC 2136 §3.2 prerequisites against actual backend state.
///
/// Queries the backend for each unique name referenced in the prerequisite
/// section, then checks each prerequisite RR against the results. This
/// uses targeted per-name queries (`get_records_by_name`) instead of
/// fetching the entire zone, which is both more efficient and ensures the
/// RFC 2136 backend checks the authoritative server (not local `SQLite`).
pub(super) async fn evaluate_prereqs(
    backends: &[Arc<dyn Backend>],
    prereqs: &[hickory_proto::rr::Record],
    zone_query: &hickory_proto::op::Query,
) -> Result<(), DnsError> {
    let zone_name = zone_query.name().to_utf8();
    let zone_name_trimmed = zone_name.trim_end_matches('.');

    let (zone, backend_idx) = derive_zone(zone_name_trimmed, backends)
        .map_err(|_| DnsError::NotZone(format!("no backend for zone {zone_name}")))?;
    let backend = &backends[backend_idx];

    // Collect unique prerequisite names and fetch records per name.
    let mut unique_names: Vec<String> = prereqs
        .iter()
        .map(|p| p.name.to_utf8().trim_end_matches('.').to_string())
        .collect();
    unique_names.sort_unstable();
    unique_names.dedup();

    let mut records_by_name: HashMap<String, Vec<ExistingRecord>> = HashMap::new();
    for name in &unique_names {
        let records = backend
            .get_records_by_name(name, &zone)
            .await
            .map_err(|e| DnsError::Refused(format!("failed to query records for {name}: {e}")))?;
        records_by_name.insert(name.clone(), records);
    }

    for prereq in prereqs {
        // §3.2: prereq TTL MUST be zero.
        if prereq.ttl != 0 {
            return Err(DnsError::FormErr(format!(
                "prerequisite TTL must be 0, got {}",
                prereq.ttl
            )));
        }

        let prereq_name = prereq.name.to_utf8();
        let prereq_name = prereq_name.trim_end_matches('.');
        let prereq_class = prereq.dns_class;
        let prereq_type = prereq.record_type();
        let has_rdata = !matches!(&prereq.data, RData::Update0(..));

        let empty: Vec<ExistingRecord> = Vec::new();
        let name_records = records_by_name.get(prereq_name).unwrap_or(&empty);

        match (prereq_class, prereq_type, has_rdata) {
            // §2.4.1 RRset exists (value-independent): CLASS=ANY, specific TYPE, no RDATA
            (DNSClass::ANY, rtype, false) if rtype != RecordType::ANY => {
                let type_str = rtype.to_string();
                let found = name_records
                    .iter()
                    .any(|r| r.record.value.type_str() == type_str);
                if !found {
                    return Err(DnsError::PrereqFailed(ResponseCode::NXRRSet));
                }
            }

            // §2.4.2 RRset exists (value-dependent): CLASS=IN, specific TYPE, RDATA present
            (DNSClass::IN, rtype, true) if rtype != RecordType::ANY => {
                let type_str = rtype.to_string();
                let prereq_value = RecordValue::try_from(&prereq.data)
                    .map_err(|e| DnsError::FormErr(format!("bad prereq RDATA: {e}")))?;
                let found = name_records.iter().any(|r| {
                    r.record.value.type_str() == type_str && r.record.value == prereq_value
                });
                if !found {
                    return Err(DnsError::PrereqFailed(ResponseCode::NXRRSet));
                }
            }

            // §2.4.3 RRset does not exist: CLASS=NONE, specific TYPE, no RDATA
            (DNSClass::NONE, rtype, false) if rtype != RecordType::ANY => {
                let type_str = rtype.to_string();
                let found = name_records
                    .iter()
                    .any(|r| r.record.value.type_str() == type_str);
                if found {
                    return Err(DnsError::PrereqFailed(ResponseCode::YXRRSet));
                }
            }

            // §2.4.4 Name is in use: CLASS=ANY, TYPE=ANY, no RDATA
            (DNSClass::ANY, RecordType::ANY, false) => {
                if name_records.is_empty() {
                    return Err(DnsError::PrereqFailed(ResponseCode::NXDomain));
                }
            }

            // §2.4.5 Name is not in use: CLASS=NONE, TYPE=ANY, no RDATA
            (DNSClass::NONE, RecordType::ANY, false) => {
                if !name_records.is_empty() {
                    return Err(DnsError::PrereqFailed(ResponseCode::YXDomain));
                }
            }

            _ => {
                return Err(DnsError::FormErr(format!(
                    "unrecognized prerequisite form: class={prereq_class:?} type={prereq_type:?} has_rdata={has_rdata}"
                )));
            }
        }
    }

    Ok(())
}
