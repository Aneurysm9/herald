use axum::Json;
use axum::extract::State;
use serde::Serialize;
use std::sync::Arc;

use super::auth::AuthenticatedClient;
use super::{ApiError, AppState};
use crate::provider::DesiredRecord;

/// Response body for the records listing endpoint.
#[derive(Serialize)]
pub(super) struct RecordsResponse {
    records: Vec<ProviderRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// A DNS record with its provider name.
///
/// Flattens the `DesiredRecord` fields into the same level as `provider`.
#[derive(Serialize)]
struct ProviderRecord {
    provider: String,
    #[serde(flatten)]
    record: DesiredRecord,
}

/// Handler for `GET /api/v1/records`.
///
/// Returns all desired records from all providers. Each record is tagged with
/// its provider name. Provider errors are collected as warnings and included
/// in the response rather than failing the entire request.
pub(super) async fn get_records(
    _auth: AuthenticatedClient,
    State(state): State<Arc<AppState>>,
) -> Result<Json<RecordsResponse>, ApiError> {
    let mut all_records = Vec::new();
    let mut warnings = Vec::new();

    for provider in &state.providers {
        match provider.records().await {
            Ok(records) => {
                let provider_name = provider.name().to_string();
                all_records.extend(records.into_iter().map(|record| ProviderRecord {
                    provider: provider_name.clone(),
                    record,
                }));
            }
            Err(e) => {
                tracing::error!(provider = provider.name(), error = %e, "failed to collect records for API");
                warnings.push(format!("provider '{}' failed: {e}", provider.name()));
            }
        }
    }

    Ok(Json(RecordsResponse {
        records: all_records,
        warnings,
    }))
}

#[cfg(test)]
mod tests {
    use crate::api::tests::{StubProvider, test_token_index};
    use crate::api::{AppState, router};
    use crate::provider::{DesiredRecord, Provider, RecordValue};
    use crate::reconciler::Reconciler;
    use crate::telemetry::Metrics;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use std::sync::Arc;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn test_get_records_success() {
        let static_records = vec![
            DesiredRecord {
                name: "www.example.com".to_string(),
                value: RecordValue::parse("CNAME", "example.com").unwrap(),
                ttl: 300,
            },
            DesiredRecord {
                name: "example.com".to_string(),
                value: RecordValue::parse("A", "1.2.3.4").unwrap(),
                ttl: 300,
            },
        ];

        let providers: Vec<Arc<dyn Provider>> = vec![Arc::new(StubProvider {
            label: "static",
            desired: static_records,
            fail: false,
        })];

        let state = Arc::new(AppState {
            acme_provider: None,
            dynamic_provider: None,
            token_index: test_token_index(),
            providers,
            reconciler: Arc::new(Reconciler::new(false, Metrics::noop())),
            backends: vec![Arc::new(crate::api::tests::StubBackend {
                existing: vec![],
            })],
            reconcile_notify: Arc::new(Notify::new()),
            metrics: Metrics::noop(),
        });

        let server = TestServer::new(router(state).into_make_service()).unwrap();

        let response = server
            .get("/api/v1/records")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .await;

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        let records = body["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["provider"], "static");
        assert_eq!(records[0]["name"], "www.example.com");
        assert_eq!(records[0]["record_type"], "CNAME");
        assert_eq!(records[1]["name"], "example.com");
        // warnings should be absent when empty
        assert!(body.get("warnings").is_none());
    }

    #[tokio::test]
    async fn test_get_records_no_auth() {
        let server = crate::api::tests::test_server();
        let response = server.get("/api/v1/records").await;

        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn test_get_records_provider_error_returns_warnings() {
        let providers: Vec<Arc<dyn Provider>> = vec![
            Arc::new(StubProvider {
                label: "failing",
                desired: vec![],
                fail: true,
            }),
            Arc::new(StubProvider {
                label: "healthy",
                desired: vec![DesiredRecord {
                    name: "ok.example.com".to_string(),
                    value: RecordValue::parse("A", "1.2.3.4").unwrap(),
                    ttl: 300,
                }],
                fail: false,
            }),
        ];

        let state = Arc::new(AppState {
            acme_provider: None,
            dynamic_provider: None,
            token_index: test_token_index(),
            providers,
            reconciler: Arc::new(Reconciler::new(false, Metrics::noop())),
            backends: vec![Arc::new(crate::api::tests::StubBackend {
                existing: vec![],
            })],
            reconcile_notify: Arc::new(Notify::new()),
            metrics: Metrics::noop(),
        });

        let server = TestServer::new(router(state).into_make_service()).unwrap();

        let response = server
            .get("/api/v1/records")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer test-token-123"),
            )
            .await;

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        // Only the healthy provider's record should be present
        let records = body["records"].as_array().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["provider"], "healthy");
        // Warnings array should contain the failing provider's error
        let warnings = body["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].as_str().unwrap().contains("failing"));
    }
}
