//! Zone derivation utilities.
//!
//! Provides shared logic for deriving DNS zones from FQDNs using longest-suffix
//! matching against backend zone declarations.

use crate::backend::Backend;
use anyhow::Result;
use std::sync::Arc;

/// Derive the zone and backend index for a given FQDN using longest suffix matching.
///
/// This function implements the core Herald zone derivation algorithm:
/// 1. Normalize FQDN and zones (trim dots, lowercase)
/// 2. Check if FQDN ends with each zone (exact match or subdomain)
/// 3. Select longest matching zone
///
/// Returns `(zone, backend_index)` tuple if a backend can handle the FQDN.
///
/// # Examples
///
/// ```ignore
/// // FQDN: "www.example.com", zones: ["example.com"] → "example.com"
/// // FQDN: "host.sub.example.com", zones: ["example.com", "sub.example.com"]
/// //       → "sub.example.com" (longest match)
/// ```
///
/// # Errors
///
/// Returns an error if no backend zone matches the FQDN.
pub(crate) fn derive_zone(fqdn: &str, backends: &[Arc<dyn Backend>]) -> Result<(String, usize)> {
    let fqdn_normalized = fqdn.trim_end_matches('.').to_lowercase();

    let mut best_match: Option<(String, usize, usize)> = None; // (zone, zone_len, backend_idx)

    for (backend_idx, backend) in backends.iter().enumerate() {
        for zone in backend.zones() {
            let zone_normalized = zone.trim_end_matches('.').to_lowercase();

            // Check if FQDN matches this zone
            let matches = if fqdn_normalized == zone_normalized {
                true // Exact match
            } else if let Some(prefix) = fqdn_normalized.strip_suffix(&zone_normalized) {
                prefix.ends_with('.') // Proper subdomain
            } else {
                false
            };

            if matches {
                let zone_len = zone_normalized.len();
                if best_match
                    .as_ref()
                    .is_none_or(|(_, len, _)| zone_len > *len)
                {
                    best_match = Some((zone.clone(), zone_len, backend_idx));
                }
            }
        }
    }

    best_match
        .map(|(zone, _, backend_idx)| (zone, backend_idx))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no backend found for FQDN {} (available backends: {})",
                fqdn,
                backends
                    .iter()
                    .map(|b| format!("{}[{}]", b.name(), b.zones().join(", ")))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Change, ExistingRecord};
    use crate::provider::Named;
    use std::future::Future;
    use std::pin::Pin;

    struct TestBackend {
        zones: Vec<String>,
    }

    impl Named for TestBackend {
        fn name(&self) -> &str {
            "test"
        }
    }

    impl Backend for TestBackend {
        fn zones(&self) -> Vec<String> {
            self.zones.clone()
        }

        fn get_records(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<ExistingRecord>>> + Send + '_>> {
            Box::pin(async move { Ok(vec![]) })
        }

        fn apply_change<'a>(
            &'a self,
            _change: &'a Change,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move { Ok(()) })
        }
    }

    #[test]
    fn test_exact_match() {
        let backends: Vec<Arc<dyn Backend>> = vec![Arc::new(TestBackend {
            zones: vec!["example.com".to_string()],
        })];

        let (zone, idx) = derive_zone("example.com", &backends).unwrap();
        assert_eq!(zone, "example.com");
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_subdomain_match() {
        let backends: Vec<Arc<dyn Backend>> = vec![Arc::new(TestBackend {
            zones: vec!["example.com".to_string()],
        })];

        let (zone, idx) = derive_zone("www.example.com", &backends).unwrap();
        assert_eq!(zone, "example.com");
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_longest_suffix_match() {
        let backends: Vec<Arc<dyn Backend>> = vec![Arc::new(TestBackend {
            zones: vec!["example.com".to_string(), "sub.example.com".to_string()],
        })];

        let (zone, idx) = derive_zone("host.sub.example.com", &backends).unwrap();
        assert_eq!(zone, "sub.example.com"); // Longest match
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_multiple_backends() {
        let backends: Vec<Arc<dyn Backend>> = vec![
            Arc::new(TestBackend {
                zones: vec!["example.com".to_string()],
            }),
            Arc::new(TestBackend {
                zones: vec!["example.org".to_string()],
            }),
        ];

        let (zone, idx) = derive_zone("www.example.org", &backends).unwrap();
        assert_eq!(zone, "example.org");
        assert_eq!(idx, 1); // Second backend
    }

    #[test]
    fn test_trailing_dot_normalization() {
        let backends: Vec<Arc<dyn Backend>> = vec![Arc::new(TestBackend {
            zones: vec!["example.com.".to_string()], // Zone has trailing dot
        })];

        let (zone, idx) = derive_zone("www.example.com", &backends).unwrap();
        assert_eq!(zone, "example.com.");
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_case_insensitive() {
        let backends: Vec<Arc<dyn Backend>> = vec![Arc::new(TestBackend {
            zones: vec!["Example.COM".to_string()],
        })];

        let (zone, idx) = derive_zone("WWW.example.com", &backends).unwrap();
        assert_eq!(zone, "Example.COM"); // Returns original case
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_no_match() {
        let backends: Vec<Arc<dyn Backend>> = vec![Arc::new(TestBackend {
            zones: vec!["example.com".to_string()],
        })];

        let result = derive_zone("www.other.org", &backends);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no backend found"));
    }

    #[test]
    fn test_partial_suffix_no_match() {
        let backends: Vec<Arc<dyn Backend>> = vec![Arc::new(TestBackend {
            zones: vec!["example.com".to_string()],
        })];

        // "notexample.com" should NOT match "example.com"
        let result = derive_zone("notexample.com", &backends);
        assert!(result.is_err());
    }
}
