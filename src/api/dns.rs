use axum::{extract::State, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;

use super::auth::AuthenticatedClient;
use super::{ApiError, AppState};
use crate::zone_util;

/// Request body for setting a dynamic DNS record.
///
/// The zone field is optional - if not provided, Herald will derive it from the
/// FQDN using longest-suffix matching against available backend zones.
#[derive(Deserialize)]
pub(crate) struct DnsRecordRequest {
    /// Optional zone - will be derived from name if omitted
    zone: Option<String>,
    name: String,
    #[serde(rename = "type")]
    r#type: String,
    value: String,
    ttl: u32,
}

/// Request body for deleting a dynamic DNS record.
///
/// The zone field is optional - if not provided, Herald will derive it from the
/// FQDN using longest-suffix matching against available backend zones.
#[derive(Deserialize)]
pub(crate) struct DeleteDnsRecordRequest {
    /// Optional zone - will be derived from name if omitted
    zone: Option<String>,
    name: String,
    #[serde(rename = "type")]
    r#type: String,
}

/// Handler for `POST /api/v1/dns/record`.
///
/// Creates or updates a dynamic DNS record. The client must be authenticated
/// and have permission for both the domain and the zone.
pub(crate) async fn set_dns_record(
    AuthenticatedClient(client): AuthenticatedClient,
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<DnsRecordRequest>,
) -> Result<StatusCode, ApiError> {
    let dynamic = state
        .dynamic_provider
        .as_ref()
        .ok_or_else(|| ApiError::NotConfigured("dynamic provider is not configured".into()))?;

    let zone = if let Some(z) = req.zone {
        z
    } else {
        let (z, _backend_idx) = zone_util::derive_zone(&req.name, &state.backends)
            .map_err(|e| ApiError::BadRequest(format!("could not derive zone from FQDN: {e}")))?;
        z
    };

    dynamic
        .set_record(&client, &zone, &req.name, &req.r#type, &req.value, req.ttl)
        .await
        .map_err(|e| ApiError::Forbidden(e.to_string()))?;

    state.reconcile_notify.notify_one();
    Ok(StatusCode::OK)
}

/// Handler for `POST /api/v1/dns/record/delete`.
///
/// Deletes a dynamic DNS record. Only the client that created the record
/// can delete it.
pub(crate) async fn delete_dns_record(
    AuthenticatedClient(client): AuthenticatedClient,
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<DeleteDnsRecordRequest>,
) -> Result<StatusCode, ApiError> {
    let dynamic = state
        .dynamic_provider
        .as_ref()
        .ok_or_else(|| ApiError::NotConfigured("dynamic provider is not configured".into()))?;

    let zone = if let Some(z) = req.zone {
        z
    } else {
        let (z, _backend_idx) = zone_util::derive_zone(&req.name, &state.backends)
            .map_err(|e| ApiError::BadRequest(format!("could not derive zone from FQDN: {e}")))?;
        z
    };

    dynamic
        .delete_record(&client, &zone, &req.name, &req.r#type)
        .await
        .map_err(|e| ApiError::Forbidden(e.to_string()))?;

    state.reconcile_notify.notify_one();
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use crate::api::tests::{StubBackend, test_dynamic_state, test_token_index};
    use crate::api::{AppState, router};
    use crate::reconciler::Reconciler;
    use crate::telemetry::Metrics;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use std::sync::Arc;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn test_set_dns_record_success() {
        let state = test_dynamic_state();
        let server = TestServer::new(router(state).into_make_service()).unwrap();

        let response = server
            .post("/api/v1/dns/record")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "zone": "example.com",
                "name": "wan.example.com",
                "type": "A",
                "value": "198.51.100.1",
                "ttl": 60
            }))
            .await;

        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_set_dns_record_no_auth() {
        let state = test_dynamic_state();
        let server = TestServer::new(router(state).into_make_service()).unwrap();

        let response = server
            .post("/api/v1/dns/record")
            .json(&serde_json::json!({
                "zone": "example.com",
                "name": "wan.example.com",
                "type": "A",
                "value": "198.51.100.1",
                "ttl": 60
            }))
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn test_set_dns_record_forbidden() {
        let state = test_dynamic_state();
        let server = TestServer::new(router(state).into_make_service()).unwrap();

        let response = server
            .post("/api/v1/dns/record")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "zone": "example.com",
                "name": "bad.example.org",
                "type": "A",
                "value": "198.51.100.1",
                "ttl": 60
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
    async fn test_delete_dns_record_success() {
        let state = test_dynamic_state();
        let server = TestServer::new(router(state).into_make_service()).unwrap();

        // First set a record
        server
            .post("/api/v1/dns/record")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "zone": "example.com",
                "name": "wan.example.com",
                "type": "A",
                "value": "198.51.100.1",
                "ttl": 60
            }))
            .await
            .assert_status_ok();

        // Then delete it
        let response = server
            .post("/api/v1/dns/record/delete")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "zone": "example.com",
                "name": "wan.example.com",
                "type": "A"
            }))
            .await;

        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_dns_without_provider() {
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

        let response = server
            .post("/api/v1/dns/record")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .json(&serde_json::json!({
                "zone": "example.com",
                "name": "wan.example.com",
                "type": "A",
                "value": "198.51.100.1",
                "ttl": 60
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
    }
}
