//! Typed DNS record values.
//!
//! `RecordValue` merges the record type and value into a single enum, making it
//! impossible to construct a mismatched type/value pair (e.g., an A record with
//! an IPv6 address).

use anyhow::{Context, Result};
use serde::Serialize;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A DNS record value with its type encoded in the variant.
///
/// Each variant carries the parsed, validated value for its record type.
/// Use [`RecordValue::parse`] to construct from raw strings at system boundaries
/// (API responses, config files).
///
/// Variant names use uppercase to match DNS record type conventions (consistent
/// with [`RecordType`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)] // DNS record types are uppercase by convention
pub(crate) enum RecordValue {
    /// IPv4 address record
    A(Ipv4Addr),
    /// IPv6 address record
    AAAA(Ipv6Addr),
    /// Canonical name (alias)
    CNAME(String),
    /// Text record
    TXT(String),
    /// Mail exchanger with priority
    MX { priority: u16, exchange: String },
    /// Name server
    NS(String),
    /// Service locator
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Certification Authority Authorization
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
}

impl RecordValue {
    /// Parse a record value from a type string and value string.
    ///
    /// This is the single boundary parsing function — call it wherever raw strings
    /// enter Herald (backend API responses, mirror sources, API requests, config).
    ///
    /// # Errors
    ///
    /// Returns an error if the record type is unsupported or the value cannot be
    /// parsed for the given type.
    pub(crate) fn parse(record_type: &str, value: &str) -> Result<Self> {
        match record_type.to_ascii_uppercase().as_str() {
            "A" => {
                let addr: Ipv4Addr = value
                    .parse()
                    .with_context(|| format!("invalid IPv4 address: {value}"))?;
                Ok(Self::A(addr))
            }
            "AAAA" => {
                let addr: Ipv6Addr = value
                    .parse()
                    .with_context(|| format!("invalid IPv6 address: {value}"))?;
                Ok(Self::AAAA(addr))
            }
            "CNAME" => Ok(Self::CNAME(value.to_string())),
            "TXT" => Ok(Self::TXT(value.to_string())),
            "MX" => {
                let (priority, exchange) = value.split_once(':').ok_or_else(|| {
                    anyhow::anyhow!("invalid MX format (expected priority:exchange): {value}")
                })?;
                let priority: u16 = priority
                    .parse()
                    .with_context(|| format!("invalid MX priority: {priority}"))?;
                Ok(Self::MX {
                    priority,
                    exchange: exchange.to_string(),
                })
            }
            "NS" => Ok(Self::NS(value.to_string())),
            "SRV" => {
                let parts: Vec<&str> = value.splitn(4, ':').collect();
                if parts.len() != 4 {
                    anyhow::bail!(
                        "invalid SRV format (expected priority:weight:port:target): {value}"
                    );
                }
                Ok(Self::SRV {
                    priority: parts[0]
                        .parse()
                        .with_context(|| format!("invalid SRV priority: {}", parts[0]))?,
                    weight: parts[1]
                        .parse()
                        .with_context(|| format!("invalid SRV weight: {}", parts[1]))?,
                    port: parts[2]
                        .parse()
                        .with_context(|| format!("invalid SRV port: {}", parts[2]))?,
                    target: parts[3].to_string(),
                })
            }
            "CAA" => {
                let parts: Vec<&str> = value.splitn(3, ' ').collect();
                if parts.len() != 3 {
                    anyhow::bail!("invalid CAA format (expected 'flags tag value'): {value}");
                }
                Ok(Self::CAA {
                    flags: parts[0]
                        .parse()
                        .with_context(|| format!("invalid CAA flags: {}", parts[0]))?,
                    tag: parts[1].to_string(),
                    value: parts[2].to_string(),
                })
            }
            other => anyhow::bail!("unsupported record type: {other}"),
        }
    }

    /// Get the string representation of the record type (e.g., "A", "AAAA").
    #[must_use]
    pub(crate) fn type_str(&self) -> &'static str {
        match self {
            Self::A(_) => "A",
            Self::AAAA(_) => "AAAA",
            Self::CNAME(_) => "CNAME",
            Self::TXT(_) => "TXT",
            Self::MX { .. } => "MX",
            Self::NS(_) => "NS",
            Self::SRV { .. } => "SRV",
            Self::CAA { .. } => "CAA",
        }
    }

    /// Get the value as a string suitable for DNS backend APIs.
    ///
    /// For most types this is the standard string representation.
    /// For MX records, returns the `"priority:exchange"` Herald convention.
    #[must_use]
    pub(crate) fn value_str(&self) -> String {
        match self {
            Self::A(addr) => addr.to_string(),
            Self::AAAA(addr) => addr.to_string(),
            Self::CNAME(name) | Self::NS(name) => name.clone(),
            Self::TXT(text) => text.clone(),
            Self::MX { priority, exchange } => format!("{priority}:{exchange}"),
            Self::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                format!("{priority}:{weight}:{port}:{target}")
            }
            Self::CAA { flags, tag, value } => format!("{flags} {tag} {value}"),
        }
    }
}

impl fmt::Display for RecordValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(addr) => write!(f, "{addr}"),
            Self::AAAA(addr) => write!(f, "{addr}"),
            Self::CNAME(name) | Self::NS(name) => write!(f, "{name}"),
            Self::TXT(text) => write!(f, "\"{text}\""),
            Self::MX { priority, exchange } => write!(f, "{priority} {exchange}"),
            Self::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                write!(f, "{priority} {weight} {port} {target}")
            }
            Self::CAA { flags, tag, value } => write!(f, "{flags} {tag} \"{value}\""),
        }
    }
}

impl Serialize for RecordValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize as the value string for JSON API compatibility
        serializer.serialize_str(&self.value_str())
    }
}

// ── hickory-dns RData conversions ────────────────────────────────────────────

use hickory_proto::rr::rdata::{self, A, AAAA, CNAME, MX, NS, TXT};
use hickory_proto::rr::{Name, RData};

impl TryFrom<&RecordValue> for RData {
    type Error = anyhow::Error;

    fn try_from(value: &RecordValue) -> Result<Self> {
        match value {
            RecordValue::A(ip) => Ok(RData::A(A(*ip))),
            RecordValue::AAAA(ip) => Ok(RData::AAAA(AAAA(*ip))),
            RecordValue::CNAME(name) => {
                let n = Name::from_ascii(name)
                    .with_context(|| format!("invalid CNAME target: {name}"))?;
                Ok(RData::CNAME(CNAME(n)))
            }
            RecordValue::TXT(text) => Ok(RData::TXT(TXT::new(vec![text.clone()]))),
            RecordValue::MX { priority, exchange } => {
                let ex = Name::from_ascii(exchange)
                    .with_context(|| format!("invalid MX exchange: {exchange}"))?;
                Ok(RData::MX(MX::new(*priority, ex)))
            }
            RecordValue::NS(name) => {
                let n =
                    Name::from_ascii(name).with_context(|| format!("invalid NS target: {name}"))?;
                Ok(RData::NS(NS(n)))
            }
            RecordValue::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                let t = Name::from_ascii(target)
                    .with_context(|| format!("invalid SRV target: {target}"))?;
                Ok(RData::SRV(rdata::SRV::new(*priority, *weight, *port, t)))
            }
            RecordValue::CAA {
                flags, value: val, ..
            } => Ok(RData::CAA(rdata::CAA::new_issue(
                *flags != 0,
                Some(Name::from_ascii(val).unwrap_or_else(|_| Name::root())),
                vec![],
            ))),
        }
    }
}

impl TryFrom<&RData> for RecordValue {
    type Error = anyhow::Error;

    #[allow(clippy::similar_names)] // txt/text are the standard TXT record data vs. decoded text
    fn try_from(rdata: &RData) -> Result<Self> {
        match rdata {
            RData::A(a) => Ok(RecordValue::A(a.0)),
            RData::AAAA(aaaa) => Ok(RecordValue::AAAA(aaaa.0)),
            RData::CNAME(cname) => Ok(RecordValue::CNAME(cname.0.to_utf8())),
            RData::TXT(txt) => {
                let text = txt
                    .txt_data
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                    .collect::<String>();
                Ok(RecordValue::TXT(text))
            }
            RData::MX(mx) => Ok(RecordValue::MX {
                priority: mx.preference,
                exchange: mx.exchange.to_utf8(),
            }),
            RData::NS(ns) => Ok(RecordValue::NS(ns.0.to_utf8())),
            RData::SRV(srv) => Ok(RecordValue::SRV {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                target: srv.target.to_utf8(),
            }),
            _ => anyhow::bail!("unsupported RData type for Herald: {rdata:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_a_record() {
        let rv = RecordValue::parse("A", "203.0.113.1").unwrap();
        assert_eq!(rv, RecordValue::A("203.0.113.1".parse().unwrap()));
        assert_eq!(rv.type_str(), "A");
        assert_eq!(rv.type_str(), "A");
        assert_eq!(rv.value_str(), "203.0.113.1");
    }

    #[test]
    fn test_parse_aaaa_record() {
        let rv = RecordValue::parse("AAAA", "2001:db8::1").unwrap();
        assert_eq!(rv, RecordValue::AAAA("2001:db8::1".parse().unwrap()));
        assert_eq!(rv.type_str(), "AAAA");
        assert_eq!(rv.value_str(), "2001:db8::1");
    }

    #[test]
    fn test_parse_cname_record() {
        let rv = RecordValue::parse("CNAME", "example.com").unwrap();
        assert_eq!(rv, RecordValue::CNAME("example.com".to_string()));
        assert_eq!(rv.type_str(), "CNAME");
    }

    #[test]
    fn test_parse_txt_record() {
        let rv = RecordValue::parse("TXT", "v=spf1 include:_spf.example.com ~all").unwrap();
        assert_eq!(
            rv,
            RecordValue::TXT("v=spf1 include:_spf.example.com ~all".to_string())
        );
    }

    #[test]
    fn test_parse_mx_record() {
        let rv = RecordValue::parse("MX", "10:mail.example.com").unwrap();
        assert_eq!(
            rv,
            RecordValue::MX {
                priority: 10,
                exchange: "mail.example.com".to_string()
            }
        );
        assert_eq!(rv.value_str(), "10:mail.example.com");
    }

    #[test]
    fn test_parse_ns_record() {
        let rv = RecordValue::parse("NS", "ns1.example.com").unwrap();
        assert_eq!(rv, RecordValue::NS("ns1.example.com".to_string()));
    }

    #[test]
    fn test_parse_srv_record() {
        let rv = RecordValue::parse("SRV", "10:5:443:server.example.com").unwrap();
        assert_eq!(
            rv,
            RecordValue::SRV {
                priority: 10,
                weight: 5,
                port: 443,
                target: "server.example.com".to_string()
            }
        );
    }

    #[test]
    fn test_parse_caa_record() {
        let rv = RecordValue::parse("CAA", "0 issue letsencrypt.org").unwrap();
        assert_eq!(
            rv,
            RecordValue::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string()
            }
        );
    }

    #[test]
    fn test_parse_case_insensitive_type() {
        let rv = RecordValue::parse("aaaa", "2001:db8::1").unwrap();
        assert_eq!(rv.type_str(), "AAAA");
    }

    #[test]
    fn test_parse_invalid_type() {
        assert!(RecordValue::parse("INVALID", "value").is_err());
    }

    #[test]
    fn test_parse_invalid_ipv4() {
        assert!(RecordValue::parse("A", "not-an-ip").is_err());
    }

    #[test]
    fn test_parse_invalid_ipv6() {
        assert!(RecordValue::parse("AAAA", "not-an-ip").is_err());
    }

    #[test]
    fn test_parse_invalid_mx_format() {
        assert!(RecordValue::parse("MX", "no-colon").is_err());
        assert!(RecordValue::parse("MX", "notanumber:mail.example.com").is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(
            format!("{}", RecordValue::A("1.2.3.4".parse().unwrap())),
            "1.2.3.4"
        );
        assert_eq!(
            format!("{}", RecordValue::TXT("hello".to_string())),
            "\"hello\""
        );
        assert_eq!(
            format!(
                "{}",
                RecordValue::MX {
                    priority: 10,
                    exchange: "mail.example.com".to_string()
                }
            ),
            "10 mail.example.com"
        );
    }

    #[test]
    fn test_roundtrip_value_str() {
        // Verify that parse(type, value_str()) == original for all types
        let cases = vec![
            RecordValue::A("203.0.113.1".parse().unwrap()),
            RecordValue::AAAA("2001:db8::1".parse().unwrap()),
            RecordValue::CNAME("example.com".to_string()),
            RecordValue::TXT("v=spf1 ~all".to_string()),
            RecordValue::MX {
                priority: 10,
                exchange: "mail.example.com".to_string(),
            },
            RecordValue::NS("ns1.example.com".to_string()),
            RecordValue::SRV {
                priority: 10,
                weight: 5,
                port: 443,
                target: "server.example.com".to_string(),
            },
            RecordValue::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string(),
            },
        ];

        for original in cases {
            let type_str = original.type_str();
            let value_str = original.value_str();
            let parsed = RecordValue::parse(type_str, &value_str).unwrap();
            assert_eq!(
                parsed, original,
                "roundtrip failed for {type_str} {value_str}"
            );
        }
    }

    #[test]
    fn test_serde_serializes_as_value_str() {
        let rv = RecordValue::A("1.2.3.4".parse().unwrap());
        let json = serde_json::to_string(&rv).unwrap();
        assert_eq!(json, "\"1.2.3.4\"");

        let rv = RecordValue::MX {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        };
        let json = serde_json::to_string(&rv).unwrap();
        assert_eq!(json, "\"10:mail.example.com\"");
    }
}
