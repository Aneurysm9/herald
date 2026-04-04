use axum::extract::State;
use axum::http::StatusCode;
use std::sync::Arc;

use super::auth::AuthenticatedClient;
use super::{ApiError, AppState};

/// Handler for `POST /api/v1/reconcile`.
///
/// Triggers an immediate reconciliation pass.
/// Useful for debugging or forcing a sync outside the normal reconciliation interval.
pub(super) async fn trigger_reconcile(
    _auth: AuthenticatedClient,
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, ApiError> {
    state
        .reconciler
        .reconcile(&state.providers, &state.backends)
        .await
        .map_err(ApiError::Internal)?;

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use crate::api::tests::{StubBackend, StubProvider, test_server, test_token_index};
    use crate::api::{AppState, router};
    use crate::provider::Provider;
    use crate::reconciler::Reconciler;
    use crate::telemetry::Metrics;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use std::sync::Arc;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn test_reconcile_success() {
        let providers: Vec<Arc<dyn Provider>> = vec![Arc::new(StubProvider {
            label: "static",
            desired: vec![crate::provider::DesiredRecord {
                name: "new.example.com".to_string(),
                value: crate::provider::RecordValue::parse("A", "1.2.3.4").unwrap(),
                ttl: 300,
            }],
            fail: false,
        })];

        let state = Arc::new(AppState {
            acme_provider: None,
            dynamic_provider: None,
            token_index: test_token_index(),
            providers,
            reconciler: Arc::new(Reconciler::new(true, Metrics::noop())), // dry_run so apply isn't called
            backends: vec![Arc::new(StubBackend { existing: vec![] })],
            reconcile_notify: Arc::new(Notify::new()),
            metrics: Metrics::noop(),
        });

        let server = TestServer::new(router(state).into_make_service()).unwrap();

        let response = server
            .post("/api/v1/reconcile")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .await;

        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_reconcile_no_auth() {
        let server = test_server();
        let response = server.post("/api/v1/reconcile").await;

        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
    }
}
