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
