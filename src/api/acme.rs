use axum::{extract::State, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;

use super::auth::AuthenticatedClient;
use super::{ApiError, AppState};

/// Request body for setting an ACME challenge.
#[derive(Deserialize)]
pub(super) struct ChallengeRequest {
    /// The domain the challenge is for (e.g., "proxy.example.com")
    domain: String,
    /// The challenge TXT record value
    value: String,
}

/// Request body for clearing an ACME challenge.
#[derive(Deserialize)]
pub(super) struct ClearChallengeRequest {
    /// The domain to clear the challenge for
    domain: String,
}

/// Handler for `POST /api/v1/acme/challenge`.
///
/// Sets an ACME DNS-01 challenge TXT record. The client must be authenticated
/// and have permission for the requested domain.
///
/// Constructs the FQDN as `_acme-challenge.{domain}` and delegates to the
/// ACME provider.
pub(super) async fn set_challenge(
    AuthenticatedClient(client): AuthenticatedClient,
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<ChallengeRequest>,
) -> Result<StatusCode, ApiError> {
    let acme = state
        .acme_provider
        .as_ref()
        .ok_or_else(|| ApiError::NotConfigured("ACME provider is not configured".into()))?;

    let fqdn = format!("_acme-challenge.{}", req.domain);

    acme.set_challenge(&client, &fqdn, &req.value)
        .await
        .map_err(|e| ApiError::Forbidden(e.to_string()))?;

    state.reconcile_notify.notify_one();
    Ok(StatusCode::OK)
}

/// Handler for `POST /api/v1/acme/challenge/clear`.
///
/// Clears an ACME DNS-01 challenge TXT record. Only the client that created
/// the challenge can clear it.
pub(super) async fn clear_challenge(
    AuthenticatedClient(client): AuthenticatedClient,
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<ClearChallengeRequest>,
) -> Result<StatusCode, ApiError> {
    let acme = state
        .acme_provider
        .as_ref()
        .ok_or_else(|| ApiError::NotConfigured("ACME provider is not configured".into()))?;

    let fqdn = format!("_acme-challenge.{}", req.domain);

    acme.clear_challenge(&client, &fqdn)
        .await
        .map_err(|e| ApiError::Forbidden(e.to_string()))?;

    state.reconcile_notify.notify_one();
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use crate::api::tests::{StubBackend, test_token_index};
    use crate::api::{AppState, router};
    use crate::config::{AcmeClientConfig, AcmeProviderConfig};
    use crate::provider::Provider;
    use crate::provider::acme::AcmeProvider;
    use crate::reconciler::Reconciler;
    use crate::telemetry::Metrics;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Notify;

    fn test_state() -> Arc<AppState> {
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

        Arc::new(AppState {
            acme_provider: Some(acme_provider),
            dynamic_provider: None,
            token_index: test_token_index(),
            providers,
            reconciler: Arc::new(Reconciler::new(false, Metrics::noop())),
            backends: vec![Arc::new(StubBackend { existing: vec![] })],
            reconcile_notify: Arc::new(Notify::new()),
            metrics: Metrics::noop(),
            rate_limiter: None,
        })
    }

    fn test_acme_server() -> TestServer {
        let state = test_state();
        let app = router(state);
        TestServer::new(app.into_make_service()).unwrap()
    }

    #[tokio::test]
    async fn test_set_challenge_success() {
        let server = test_acme_server();
        let response = server
            .post("/api/v1/acme/challenge")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "domain": "test.example.com",
                "value": "acme-validation-digest"
            }))
            .await;

        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_set_challenge_no_auth() {
        let server = test_acme_server();
        let response = server
            .post("/api/v1/acme/challenge")
            .json(&serde_json::json!({
                "domain": "test.example.com",
                "value": "token"
            }))
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn test_set_challenge_bad_token() {
        let server = test_acme_server();
        let response = server
            .post("/api/v1/acme/challenge")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer wrong-token"),
            )
            .json(&serde_json::json!({
                "domain": "test.example.com",
                "value": "token"
            }))
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn test_set_challenge_forbidden() {
        let server = test_acme_server();
        let response = server
            .post("/api/v1/acme/challenge")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "domain": "unauthorized.example.com",
                "value": "token"
            }))
            .await;

        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "FORBIDDEN");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not allowed")
        );
    }

    #[tokio::test]
    async fn test_clear_challenge_success() {
        let server = test_acme_server();
        // First set a challenge
        server
            .post("/api/v1/acme/challenge")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "domain": "test.example.com",
                "value": "acme-validation-digest"
            }))
            .await
            .assert_status_ok();

        // Then clear it
        let response = server
            .post("/api/v1/acme/challenge/clear")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "domain": "test.example.com"
            }))
            .await;

        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_clear_challenge_no_auth() {
        let server = test_acme_server();
        let response = server
            .post("/api/v1/acme/challenge/clear")
            .json(&serde_json::json!({
                "domain": "test.example.com"
            }))
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn test_acme_without_provider() {
        let state = Arc::new(AppState {
            acme_provider: None,
            dynamic_provider: None,
            token_index: test_token_index(),
            providers: vec![],
            reconciler: Arc::new(Reconciler::new(false, Metrics::noop())),
            backends: vec![Arc::new(StubBackend { existing: vec![] })],
            reconcile_notify: Arc::new(Notify::new()),
            metrics: Metrics::noop(),
            rate_limiter: None,
        });

        let server = TestServer::new(router(state).into_make_service()).unwrap();

        // Test set_challenge without ACME configured
        let response = server
            .post("/api/v1/acme/challenge")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "domain": "test.example.com",
                "value": "token"
            }))
            .await;

        response.assert_status(StatusCode::NOT_IMPLEMENTED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "NOT_CONFIGURED");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not configured")
        );

        // Test clear_challenge without ACME configured
        let response = server
            .post("/api/v1/acme/challenge/clear")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "domain": "test.example.com"
            }))
            .await;

        response.assert_status(StatusCode::NOT_IMPLEMENTED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "NOT_CONFIGURED");
    }
}
