use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use base64::Engine;

use super::ApiError;

/// Authenticate the request by extracting the Bearer token and looking it up in the token index.
///
/// Expects an `Authorization: Bearer <token>` header. The token is hashed with
/// HMAC-SHA256 and looked up in the precomputed index for O(1) timing-safe auth.
///
/// Returns the client name on success, or an `ApiError` on failure.
pub(super) fn authenticate(
    state: &super::AppState,
    auth_header: Option<&str>,
) -> Result<String, ApiError> {
    let token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    state
        .token_index
        .lookup(token)
        .map(str::to_owned)
        .ok_or(ApiError::Unauthorized)
}

/// Axum extractor for authenticated requests.
///
/// Automatically extracts and validates the `Authorization: Bearer <token>` header,
/// looks up the client name in the token index, and provides it to the handler.
///
/// # Usage
///
/// ```ignore
/// async fn handler(
///     AuthenticatedClient(client): AuthenticatedClient,
///     // ... other extractors
/// ) -> impl IntoResponse {
///     // client is now available as a String
/// }
/// ```
///
/// If authentication fails, the extractor returns an error response and the handler
/// is not called.
pub(crate) struct AuthenticatedClient(pub(crate) String);

impl<S> FromRequestParts<S> for AuthenticatedClient
where
    S: Send + Sync,
    std::sync::Arc<super::AppState>: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state: std::sync::Arc<super::AppState> = FromRef::from_ref(state);

        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let client = authenticate(&state, auth_header)?;

        // Check rate limit after successful auth
        if let Some(ref limiter) = state.rate_limiter
            && limiter.check(&client).is_err()
        {
            state
                .metrics
                .rate_limit_rejected
                .add(1, &[opentelemetry::KeyValue::new("client", client.clone())]);
            return Err(ApiError::RateLimited);
        }

        Ok(AuthenticatedClient(client))
    }
}

/// Parse HTTP Basic Auth header.
///
/// Returns (username, password) if header is present and valid.
pub(super) fn parse_basic_auth(headers: &axum::http::HeaderMap) -> Option<(String, String)> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;
    let basic_prefix = "Basic ";
    if !auth_header.starts_with(basic_prefix) {
        return None;
    }

    let encoded = auth_header.strip_prefix(basic_prefix)?;
    let decoded = Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let credentials = String::from_utf8(decoded).ok()?;
    let mut parts = credentials.splitn(2, ':');
    let username = parts.next()?.to_string();
    let password = parts.next()?.to_string();

    Some((username, password))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Notify;

    /// Build an `AppState` that has a token index but nothing else wired up.
    fn make_state(tokens: HashMap<String, String>) -> super::super::AppState {
        use crate::reconciler::Reconciler;
        use crate::telemetry::Metrics;
        super::super::AppState {
            acme_provider: None,
            dynamic_provider: None,
            token_index: super::super::TokenIndex::new(tokens),
            providers: vec![],
            reconciler: Arc::new(Reconciler::new(false, Metrics::noop())),
            backends: vec![],
            reconcile_notify: Arc::new(Notify::new()),
            metrics: Metrics::noop(),
            rate_limiter: None,
        }
    }

    fn basic_auth_header(user: &str, pass: &str) -> HeaderMap {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Basic {encoded}").parse().unwrap());
        headers
    }

    // ── authenticate() ────────────────────────────────────────────────────────

    #[test]
    fn test_authenticate_valid_bearer_token() {
        let state = make_state(HashMap::from([(
            "alice".to_string(),
            "secret-token".to_string(),
        )]));
        let result = authenticate(&state, Some("Bearer secret-token"));
        assert_eq!(result.unwrap(), "alice");
    }

    #[test]
    fn test_authenticate_missing_header_is_unauthorized() {
        let state = make_state(HashMap::new());
        assert!(matches!(
            authenticate(&state, None),
            Err(ApiError::Unauthorized)
        ));
    }

    #[test]
    fn test_authenticate_non_bearer_scheme_is_unauthorized() {
        let state = make_state(HashMap::new());
        // Basic auth header should not be accepted by bearer authenticate()
        assert!(matches!(
            authenticate(&state, Some("Basic dXNlcjpwYXNz")),
            Err(ApiError::Unauthorized)
        ));
    }

    #[test]
    fn test_authenticate_wrong_token_is_unauthorized() {
        let state = make_state(HashMap::from([(
            "alice".to_string(),
            "correct-token".to_string(),
        )]));
        assert!(matches!(
            authenticate(&state, Some("Bearer wrong-token")),
            Err(ApiError::Unauthorized)
        ));
    }

    #[test]
    fn test_authenticate_empty_bearer_value_is_unauthorized() {
        let state = make_state(HashMap::new());
        // "Bearer " followed by nothing is still parsed as an empty string token
        assert!(matches!(
            authenticate(&state, Some("Bearer ")),
            Err(ApiError::Unauthorized)
        ));
    }

    // ── parse_basic_auth() ────────────────────────────────────────────────────

    #[test]
    fn test_parse_basic_auth_valid() {
        let headers = basic_auth_header("myuser", "mypassword");
        let (user, pass) = parse_basic_auth(&headers).unwrap();
        assert_eq!(user, "myuser");
        assert_eq!(pass, "mypassword");
    }

    #[test]
    fn test_parse_basic_auth_password_with_colons() {
        // Only the first colon is the username/password separator
        let headers = basic_auth_header("user", "pass:with:colons");
        let (user, pass) = parse_basic_auth(&headers).unwrap();
        assert_eq!(user, "user");
        assert_eq!(pass, "pass:with:colons");
    }

    #[test]
    fn test_parse_basic_auth_missing_header_returns_none() {
        assert!(parse_basic_auth(&HeaderMap::new()).is_none());
    }

    #[test]
    fn test_parse_basic_auth_bearer_scheme_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sometoken".parse().unwrap());
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_invalid_base64_returns_none() {
        let mut headers = HeaderMap::new();
        // '!' is not in the base64 alphabet, so this should fail to decode
        headers.insert("authorization", "Basic !!!notvalid!!!".parse().unwrap());
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_no_colon_returns_none() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
        headers.insert("authorization", format!("Basic {encoded}").parse().unwrap());
        // splitn(2, ':') on "nocolon" yields only one part, so password is None
        assert!(parse_basic_auth(&headers).is_none());
    }
}
