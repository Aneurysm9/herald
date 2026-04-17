//! Shared utilities for interacting with the Technitium DNS Server API.
//!
//! This module provides common types and functions used by both the mirror provider
//! (which reads from Technitium) and the Technitium backend (which writes to it).

use serde::Deserialize;

/// Technitium API response wrapper.
///
/// All Technitium API endpoints return this structure with a `status` field
/// and an optional `response` body for successful requests.
#[derive(Deserialize)]
pub(crate) struct TechnitiumResponse {
    pub response: TechnitiumResponseBody,
}

/// Response body containing DNS records.
#[derive(Deserialize)]
pub(crate) struct TechnitiumResponseBody {
    pub records: Vec<TechnitiumRecord>,
}

/// A DNS record as returned by the Technitium API.
///
/// The `rData` field is polymorphic — its structure depends on the record type.
/// Use `extract_rdata()` to convert it to a string value.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TechnitiumRecord {
    pub name: String,
    pub r#type: String,
    pub ttl: u32,
    pub r_data: serde_json::Value,
    /// Optional comment field — Herald uses "managed-by: herald" to track managed records
    #[serde(default)]
    pub comments: Option<String>,
}

/// Extract the record value from Technitium's polymorphic `rData` field.
///
/// Converts the JSON `rData` structure into a string value that Herald can use
/// in DNS record definitions. Returns `None` for unsupported record types.
///
/// # Supported Record Types
///
/// - **A/AAAA**: `{"ipAddress": "..."}`
/// - **CNAME**: `{"cname": "..."}`
/// - **TXT**: `{"text": "..."}`
/// - **MX**: `{"preference": N, "exchange": "..."}` → `"N:exchange"`
///
/// # Examples
///
/// ```ignore
/// # use serde_json::json;
/// let rdata = json!({"ipAddress": "203.0.113.1"});
/// assert_eq!(extract_rdata("A", &rdata), Some("203.0.113.1".to_string()));
///
/// let rdata = json!({"preference": 10, "exchange": "mail.example.com"});
/// assert_eq!(extract_rdata("MX", &rdata), Some("10:mail.example.com".to_string()));
/// ```
pub(crate) fn extract_rdata(record_type: &str, r_data: &serde_json::Value) -> Option<String> {
    match record_type {
        "A" | "AAAA" => r_data.get("ipAddress")?.as_str().map(String::from),
        "CNAME" => r_data.get("cname")?.as_str().map(String::from),
        "TXT" => r_data.get("text")?.as_str().map(String::from),
        "MX" => {
            let preference = r_data.get("preference")?.as_u64()?;
            let exchange = r_data.get("exchange")?.as_str()?;
            Some(format!("{preference}:{exchange}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_rdata_a() {
        let rdata = json!({"ipAddress": "1.2.3.4"});
        assert_eq!(extract_rdata("A", &rdata), Some("1.2.3.4".to_string()));
    }

    #[test]
    fn test_extract_rdata_aaaa() {
        let rdata = json!({"ipAddress": "2001:db8::1"});
        assert_eq!(
            extract_rdata("AAAA", &rdata),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_extract_rdata_cname() {
        let rdata = json!({"cname": "example.com"});
        assert_eq!(
            extract_rdata("CNAME", &rdata),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_rdata_txt() {
        let rdata = json!({"text": "v=spf1 include:_spf.google.com ~all"});
        assert_eq!(
            extract_rdata("TXT", &rdata),
            Some("v=spf1 include:_spf.google.com ~all".to_string())
        );
    }

    #[test]
    fn test_extract_rdata_mx() {
        let rdata = json!({"preference": 10, "exchange": "mail.example.com"});
        assert_eq!(
            extract_rdata("MX", &rdata),
            Some("10:mail.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_rdata_mx_missing_preference() {
        let rdata = json!({"exchange": "mail.example.com"});
        assert_eq!(extract_rdata("MX", &rdata), None);
    }

    #[test]
    fn test_extract_rdata_unknown_type() {
        let rdata = json!({"primaryNameServer": "ns1.example.com"});
        assert_eq!(extract_rdata("SOA", &rdata), None);
    }

    #[test]
    fn test_extract_rdata_missing_field() {
        let rdata = json!({"somethingElse": "value"});
        assert_eq!(extract_rdata("A", &rdata), None);
    }
}
