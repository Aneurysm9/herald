//! Per-client rate limiting using a token-bucket algorithm.
//!
//! The [`RateLimiterRegistry`] holds per-client rate limiters backed by
//! `governor`. Each client gets its own limiter, created lazily on first
//! request. Clients with a per-client config override use that quota;
//! others fall back to the global default.

use crate::config::RateLimitConfig;
use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::num::NonZeroU32;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Registry of per-client rate limiters.
///
/// Thread-safe and lock-free for concurrent lookups. Limiters are created
/// lazily on first request and reused for subsequent requests.
pub(crate) struct RateLimiterRegistry {
    limiters: DashMap<String, DirectLimiter>,
    default_quota: Quota,
    client_quotas: HashMap<String, Quota>,
}

impl RateLimiterRegistry {
    /// Create a new registry from a global default config and per-client overrides.
    pub(crate) fn new(
        default: RateLimitConfig,
        client_overrides: &HashMap<String, RateLimitConfig>,
    ) -> Self {
        Self {
            limiters: DashMap::new(),
            default_quota: quota_from_config(default),
            client_quotas: client_overrides
                .iter()
                .map(|(name, cfg)| (name.clone(), quota_from_config(*cfg)))
                .collect(),
        }
    }

    /// Check whether the client is within their rate limit.
    ///
    /// Returns `Ok(())` if the request is allowed, `Err(())` if rate limited.
    pub(crate) fn check(&self, client: &str) -> Result<(), ()> {
        let limiter = self.limiters.entry(client.to_string()).or_insert_with(|| {
            let quota = self
                .client_quotas
                .get(client)
                .copied()
                .unwrap_or(self.default_quota);
            RateLimiter::direct(quota)
        });
        limiter.check().map_err(|_| ())
    }
}

fn quota_from_config(config: RateLimitConfig) -> Quota {
    let rps = NonZeroU32::new(config.requests_per_second).unwrap_or(NonZeroU32::MIN);
    let burst = NonZeroU32::new(config.burst).unwrap_or(rps);
    Quota::per_second(rps).allow_burst(burst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> RateLimitConfig {
        RateLimitConfig {
            requests_per_second: 10,
            burst: 2,
        }
    }

    #[test]
    fn test_allows_within_burst() {
        let registry = RateLimiterRegistry::new(default_config(), &HashMap::new());
        // Burst of 2 should allow 2 immediate requests
        assert!(registry.check("client-a").is_ok());
        assert!(registry.check("client-a").is_ok());
    }

    #[test]
    fn test_rejects_over_burst() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst: 1,
        };
        let registry = RateLimiterRegistry::new(config, &HashMap::new());
        // Burst of 1: first succeeds, second is rejected immediately
        assert!(registry.check("client-a").is_ok());
        assert!(registry.check("client-a").is_err());
    }

    #[test]
    fn test_per_client_independence() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst: 1,
        };
        let registry = RateLimiterRegistry::new(config, &HashMap::new());
        // client-a exhausts its burst
        assert!(registry.check("client-a").is_ok());
        assert!(registry.check("client-a").is_err());
        // client-b is independent — still has its burst
        assert!(registry.check("client-b").is_ok());
    }

    #[test]
    fn test_client_override_quota() {
        let default = RateLimitConfig {
            requests_per_second: 10,
            burst: 1,
        };
        let overrides = HashMap::from([(
            "vip".to_string(),
            RateLimitConfig {
                requests_per_second: 100,
                burst: 5,
            },
        )]);
        let registry = RateLimiterRegistry::new(default, &overrides);

        // VIP client gets burst of 5
        for _ in 0..5 {
            assert!(registry.check("vip").is_ok());
        }
        // 6th should fail
        assert!(registry.check("vip").is_err());

        // Normal client gets burst of 1
        assert!(registry.check("normal").is_ok());
        assert!(registry.check("normal").is_err());
    }
}
