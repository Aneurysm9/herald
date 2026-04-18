mod acme;
mod auth;
mod dns;
mod dyndns;
mod error;
mod health;
mod reconcile;
mod records;

pub(crate) use error::ApiError;

use axum::{
    Router,
    extract::State,
    middleware,
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use opentelemetry::KeyValue;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Notify;

use crate::backend::Backend;
use crate::provider::Provider;
use crate::provider::acme::AcmeProvider;
use crate::provider::dynamic::DynamicProvider;
use crate::reconciler::Reconciler;
use crate::telemetry::Metrics;

/// HMAC-SHA256 based token index for O(1) timing-safe authentication.
///
/// At construction, a random HMAC key is generated. Each token is hashed with
/// this key, and the hex digest is stored as the `HashMap` key. At lookup time,
/// the incoming token is hashed the same way and looked up in the map.
///
/// This avoids O(n) constant-time comparisons while remaining timing-safe:
/// the HMAC output is fixed-length, so `HashMap`'s string comparison is
/// effectively constant-time, and even if there were timing variance,
/// the HMAC output reveals nothing about the original token.
pub(crate) struct TokenIndex {
    key: Hmac<Sha256>,
    /// Maps `hex(hmac(token))` → client name
    index: HashMap<String, String>,
}

impl TokenIndex {
    /// Build a new token index from a map of client name → raw token.
    pub(crate) fn new(tokens: HashMap<String, String>) -> Self {
        let key = {
            let random_key: [u8; 32] = rand::random();
            Hmac::<Sha256>::new_from_slice(&random_key).expect("HMAC can accept any key length")
        };

        let mut index = HashMap::with_capacity(tokens.len());
        for (client_name, raw_token) in tokens {
            let mut mac = key.clone();
            mac.update(raw_token.as_bytes());
            let digest = hex::encode(mac.finalize().into_bytes());
            index.insert(digest, client_name);
        }

        Self { key, index }
    }

    /// Look up a bearer token and return the client name if found.
    pub(crate) fn lookup(&self, token: &str) -> Option<&str> {
        let mut mac = self.key.clone();
        mac.update(token.as_bytes());
        let digest = hex::encode(mac.finalize().into_bytes());
        self.index.get(&digest).map(String::as_str)
    }
}

/// Shared state for the API server.
///
/// Holds references to all components needed by API handlers: ACME provider,
/// token index for authentication, provider list, reconciler, and backends.
pub(crate) struct AppState {
    pub acme_provider: Option<Arc<AcmeProvider>>,
    pub dynamic_provider: Option<Arc<DynamicProvider>>,
    pub token_index: TokenIndex,
    pub providers: Vec<Arc<dyn Provider>>,
    pub reconciler: Arc<Reconciler>,
    pub backends: Vec<Arc<dyn Backend>>,
    pub reconcile_notify: Arc<Notify>,
    pub metrics: Metrics,
    pub rate_limiter: Option<Arc<crate::rate_limit::RateLimiterRegistry>>,
}

/// Middleware that records HTTP request metrics (count and duration).
async fn metrics_middleware(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();
    state.metrics.http_requests.add(
        1,
        &[
            KeyValue::new("method", method),
            KeyValue::new("path", path.clone()),
            KeyValue::new("status", status),
        ],
    );
    state
        .metrics
        .http_duration
        .record(elapsed, &[KeyValue::new("path", path)]);
    response
}

/// Creates the API router with all endpoints.
///
/// Mounts handlers for health check, ACME challenge management, record listing,
/// and manual reconciliation triggering.
pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .route("/api/v1/acme/challenge", post(acme::set_challenge))
        .route("/api/v1/acme/challenge/clear", post(acme::clear_challenge))
        .route("/api/v1/dns/record", post(dns::set_dns_record))
        .route("/api/v1/dns/record/delete", post(dns::delete_dns_record))
        .route("/api/v1/records", get(records::get_records))
        .route("/api/v1/reconcile", post(reconcile::trigger_reconcile))
        .route("/nic/update", get(dyndns::dyndns_update))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            metrics_middleware,
        ))
        .with_state(state)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::backend::{Change, ExistingRecord};
    use crate::config::{AcmeClientConfig, AcmeProviderConfig};
    use crate::provider::{DesiredRecord, Named};
    use crate::telemetry::Metrics;
    use axum_test::TestServer;
    use std::future::Future;
    use std::pin::Pin;

    pub(crate) struct StubProvider {
        pub(crate) label: &'static str,
        pub(crate) desired: Vec<DesiredRecord>,
        pub(crate) fail: bool,
    }

    impl Named for StubProvider {
        fn name(&self) -> &str {
            self.label
        }
    }

    impl Provider for StubProvider {
        fn records(
            &self,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<DesiredRecord>>> + Send + '_>> {
            let fail = self.fail;
            let desired = self.desired.clone();
            Box::pin(async move {
                if fail {
                    anyhow::bail!("stub provider error");
                }
                Ok(desired)
            })
        }
    }

    pub(crate) struct StubBackend {
        pub(crate) existing: Vec<ExistingRecord>,
    }

    impl Named for StubBackend {
        fn name(&self) -> &str {
            "stub"
        }
    }

    impl Backend for StubBackend {
        fn zones(&self) -> Vec<String> {
            vec!["example.com".to_string()]
        }

        fn get_records(
            &self,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<ExistingRecord>>> + Send + '_>>
        {
            let existing = self.existing.clone();
            Box::pin(async move { Ok(existing) })
        }

        fn apply_change<'a>(
            &'a self,
            _change: &'a Change,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
            Box::pin(async move { Ok(()) })
        }
    }

    pub(crate) fn test_token_index() -> TokenIndex {
        let mut tokens = HashMap::new();
        tokens.insert("testclient".to_string(), "test-token-123".to_string());
        TokenIndex::new(tokens)
    }

    pub(crate) fn test_server() -> TestServer {
        let mut acme_clients = HashMap::new();
        acme_clients.insert(
            "testclient".to_string(),
            AcmeClientConfig {
                allowed_domains: vec!["test.example.com".to_string()],
                rate_limit: None,
            },
        );
        let acme_provider = Arc::new(
            AcmeProvider::new(
                AcmeProviderConfig {
                    clients: acme_clients,
                },
                None,
                Metrics::noop(),
            )
            .unwrap(),
        );

        let providers: Vec<Arc<dyn Provider>> =
            vec![Arc::clone(&acme_provider) as Arc<dyn Provider>];

        let state = Arc::new(AppState {
            acme_provider: Some(acme_provider),
            dynamic_provider: None,
            token_index: test_token_index(),
            providers,
            reconciler: Arc::new(Reconciler::new(false, Metrics::noop())),
            backends: vec![Arc::new(StubBackend { existing: vec![] })],
            reconcile_notify: Arc::new(Notify::new()),
            metrics: Metrics::noop(),
            rate_limiter: None,
        });

        let app = router(state);
        TestServer::new(app.into_make_service()).unwrap()
    }

    pub(crate) fn test_dynamic_state() -> Arc<AppState> {
        let mut dynamic_clients = HashMap::new();
        dynamic_clients.insert(
            "testclient".to_string(),
            crate::config::DynamicClientConfig {
                allowed_domains: vec!["*.example.com".to_string()],
                allowed_zones: vec!["example.com".to_string()],
                rate_limit: None,
            },
        );
        let dynamic_provider = Arc::new(
            DynamicProvider::new(
                crate::config::DynamicProviderConfig {
                    clients: dynamic_clients,
                },
                None,
                Metrics::noop(),
            )
            .unwrap(),
        );

        Arc::new(AppState {
            acme_provider: None,
            dynamic_provider: Some(Arc::clone(&dynamic_provider)),
            token_index: test_token_index(),
            providers: vec![Arc::clone(&dynamic_provider) as Arc<dyn Provider>],
            reconciler: Arc::new(Reconciler::new(false, Metrics::noop())),
            backends: vec![Arc::new(StubBackend { existing: vec![] })],
            reconcile_notify: Arc::new(Notify::new()),
            metrics: Metrics::noop(),
            rate_limiter: None,
        })
    }
}
