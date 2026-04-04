//! DNS record type enumeration.
//!
//! Provides a type-safe enum for DNS record types, preventing typos and
//! enabling exhaustive matching.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// DNS record type.
///
/// Represents the common DNS record types supported by Herald. This enum
/// provides compile-time validation and exhaustive matching, preventing
/// runtime errors from typos like "AAA" instead of "AAAA".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[allow(clippy::upper_case_acronyms)] // DNS record types are uppercase by convention
pub(crate) enum RecordType {
    /// IPv4 address record
    A,
    /// IPv6 address record
    AAAA,
    /// Canonical name (alias) record
    CNAME,
    /// Text record
    TXT,
    /// Mail exchanger record
    MX,
    /// Name server record
    NS,
    /// Service locator record
    SRV,
    /// Certification Authority Authorization record
    CAA,
}

impl RecordType {
    /// Get the string representation of this record type.
    ///
    /// Returns the uppercase DNS record type name (e.g., "A", "AAAA").
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::CNAME => "CNAME",
            Self::TXT => "TXT",
            Self::MX => "MX",
            Self::NS => "NS",
            Self::SRV => "SRV",
            Self::CAA => "CAA",
        }
    }

    /// Get all supported record types.
    ///
    /// Useful for iteration, validation, or displaying available types.
    #[must_use]
    #[allow(dead_code)] // May be useful in the future
    pub(crate) const fn all() -> &'static [Self] {
        &[
            Self::A,
            Self::AAAA,
            Self::CNAME,
            Self::TXT,
            Self::MX,
            Self::NS,
            Self::SRV,
            Self::CAA,
        ]
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RecordType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::AAAA),
            "CNAME" => Ok(Self::CNAME),
            "TXT" => Ok(Self::TXT),
            "MX" => Ok(Self::MX),
            "NS" => Ok(Self::NS),
            "SRV" => Ok(Self::SRV),
            "CAA" => Ok(Self::CAA),
            _ => anyhow::bail!("unsupported DNS record type: {s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str_valid() {
        assert_eq!("A".parse::<RecordType>().unwrap(), RecordType::A);
        assert_eq!("aaaa".parse::<RecordType>().unwrap(), RecordType::AAAA); // Case insensitive
        assert_eq!("CNAME".parse::<RecordType>().unwrap(), RecordType::CNAME);
        assert_eq!("txt".parse::<RecordType>().unwrap(), RecordType::TXT);
        assert_eq!("MX".parse::<RecordType>().unwrap(), RecordType::MX);
    }

    #[test]
    fn test_from_str_invalid() {
        assert!("AAA".parse::<RecordType>().is_err()); // Typo
        assert!("UNKNOWN".parse::<RecordType>().is_err());
        assert!("".parse::<RecordType>().is_err());
    }

    #[test]
    fn test_as_str() {
        assert_eq!(RecordType::A.as_str(), "A");
        assert_eq!(RecordType::AAAA.as_str(), "AAAA");
        assert_eq!(RecordType::TXT.as_str(), "TXT");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", RecordType::A), "A");
        assert_eq!(format!("{}", RecordType::AAAA), "AAAA");
    }

    #[test]
    fn test_serde_roundtrip() {
        let rt = RecordType::AAAA;
        let json = serde_json::to_string(&rt).unwrap();
        assert_eq!(json, r#""AAAA""#);
        let parsed: RecordType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, rt);
    }

    #[test]
    fn test_all() {
        let all = RecordType::all();
        assert_eq!(all.len(), 8);
        assert!(all.contains(&RecordType::A));
        assert!(all.contains(&RecordType::AAAA));
        assert!(all.contains(&RecordType::CAA));
    }
}
