use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;

use super::AppState;
use super::auth::parse_basic_auth;
use crate::zone_util;

/// Query parameters for `DynDNS` update request.
#[derive(Deserialize)]
pub(super) struct DynDnsQuery {
    /// Hostname to update (e.g., "wan.example.com")
    hostname: String,
    /// Optional IPv4 address (auto-detected from request source if omitted)
    #[serde(default)]
    myip: Option<String>,
    /// Optional IPv6 address
    #[serde(default)]
    myipv6: Option<String>,
}

/// Handler for `GET /nic/update` - `DynDNS` protocol compatibility.
///
/// Implements the classic `DynDNS` update protocol for compatibility with
/// `OPNsense` and other clients that support the `DynDNS`/`dyndns2` protocol.
///
/// Authentication: `HTTP Basic Auth` with `username=client_name`, `password=token`
/// Query params: `hostname` (required), `myip` (optional), `myipv6` (optional)
///
/// Responses (plain text):
/// - `good <IP>` - Update successful
/// - `nochg <IP>` - IP unchanged (no update needed)
/// - `badauth` - Authentication failed
/// - `nohost` - Hostname not allowed for client
/// - `notfqdn` - Invalid hostname
pub(super) async fn dyndns_update(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DynDnsQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Parse HTTP Basic Auth
    let Some((client, token)) = parse_basic_auth(&headers) else {
        return (StatusCode::UNAUTHORIZED, "badauth\n").into_response();
    };

    // Authenticate using token index
    if state.token_index.lookup(&token) != Some(&client) {
        return (StatusCode::UNAUTHORIZED, "badauth\n").into_response();
    }

    // Validate hostname is FQDN
    if !params.hostname.contains('.') {
        return (StatusCode::BAD_REQUEST, "notfqdn\n").into_response();
    }

    let Some(provider) = &state.dynamic_provider else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "911\n", // DynDNS error code for server error
        )
            .into_response();
    };

    // Determine IP and record type
    let (ip, record_type) = if let Some(ref ipv6) = params.myipv6 {
        (ipv6.clone(), "AAAA")
    } else if let Some(ref ipv4) = params.myip {
        (ipv4.clone(), "A")
    } else {
        // Auto-detect IP from request source (future enhancement)
        return (
            StatusCode::BAD_REQUEST,
            "notfqdn\n", // Use notfqdn as generic error for now
        )
            .into_response();
    };

    // Derive zone from hostname
    let Ok((zone, _backend_idx)) = zone_util::derive_zone(&params.hostname, &state.backends) else {
        return (StatusCode::BAD_REQUEST, "nohost\n").into_response();
    };

    // Set the DNS record
    match provider
        .set_record(&client, &zone, &params.hostname, record_type, &ip, 60)
        .await
    {
        Ok(()) => {
            state.reconcile_notify.notify_one();
            let response = format!("good {ip}\n");
            (StatusCode::OK, response).into_response()
        }
        Err(e) => {
            tracing::error!(client, hostname = %params.hostname, error = %e, "DynDNS update failed");
            (StatusCode::FORBIDDEN, "nohost\n").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::router;
    use crate::api::tests::test_dynamic_state;
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_dyndns_update_success() {
        let state = test_dynamic_state();
        let server = TestServer::new(router(state).into_make_service()).unwrap();

        // Encode credentials as Basic Auth
        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"testclient:test-token-123",
        );

        let response = server
            .get("/nic/update?hostname=test.example.com&myip=203.0.113.1")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_str(&format!("Basic {credentials}")).unwrap(),
            )
            .await;

        response.assert_status_ok();
        let body = response.text();
        assert!(body.starts_with("good "));
        assert!(body.contains("203.0.113.1"));
    }

    #[tokio::test]
    async fn test_dyndns_update_badauth() {
        let state = test_dynamic_state();
        let server = TestServer::new(router(state).into_make_service()).unwrap();

        // Invalid credentials
        let credentials =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"wrong:wrong");

        let response = server
            .get("/nic/update?hostname=test.example.com&myip=203.0.113.1")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_str(&format!("Basic {credentials}")).unwrap(),
            )
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
        let body = response.text();
        assert_eq!(body, "badauth\n");
    }

    #[tokio::test]
    async fn test_dyndns_update_noauth() {
        let state = test_dynamic_state();
        let server = TestServer::new(router(state).into_make_service()).unwrap();

        let response = server
            .get("/nic/update?hostname=test.example.com&myip=203.0.113.1")
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
        let body = response.text();
        assert_eq!(body, "badauth\n");
    }

    #[tokio::test]
    async fn test_dyndns_update_nohost() {
        let state = test_dynamic_state();
        let server = TestServer::new(router(state).into_make_service()).unwrap();

        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"testclient:test-token-123",
        );

        // Try to update a hostname in a zone not managed by any backend
        let response = server
            .get("/nic/update?hostname=forbidden.example.org&myip=203.0.113.1")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_str(&format!("Basic {credentials}")).unwrap(),
            )
            .await;

        response.assert_status(StatusCode::BAD_REQUEST);
        let body = response.text();
        assert_eq!(body, "nohost\n");
    }

    #[tokio::test]
    async fn test_dyndns_update_ipv6() {
        let state = test_dynamic_state();
        let server = TestServer::new(router(state).into_make_service()).unwrap();

        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"testclient:test-token-123",
        );

        let response = server
            .get("/nic/update?hostname=test.example.com&myipv6=2001:db8::1")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_str(&format!("Basic {credentials}")).unwrap(),
            )
            .await;

        response.assert_status_ok();
        let body = response.text();
        assert!(body.starts_with("good "));
        assert!(body.contains("2001:db8::1"));
    }
}
