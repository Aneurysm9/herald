use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;

/// Structured API error type.
///
/// Each variant maps to an HTTP status code and a JSON error response:
/// ```json
/// {"error": {"code": "FORBIDDEN", "message": "..."}}
/// ```
///
/// Internal errors are logged server-side but only "internal error" is
/// returned to clients — no stack traces or implementation details leak.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    /// 401 — missing or invalid auth credentials.
    #[error("missing or invalid authorization")]
    Unauthorized,

    /// 403 — authenticated but not permitted for the requested action.
    #[error("{0}")]
    Forbidden(String),

    /// 400 — invalid input (bad FQDN, zone not found, malformed request).
    #[error("{0}")]
    BadRequest(String),

    /// 501 — required provider not configured.
    #[error("{0}")]
    NotConfigured(String),

    /// 429 — too many requests from this client.
    #[error("rate limit exceeded")]
    RateLimited,

    /// 500 — unexpected internal failure.
    /// The wrapped error is logged server-side but not exposed to clients.
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

/// JSON body for error responses.
#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

/// Inner error object with machine-readable code and human-readable message.
#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl ApiError {
    /// Returns the HTTP status code for this error variant.
    fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotConfigured(_) => StatusCode::NOT_IMPLEMENTED,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Returns the machine-readable error code string.
    fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::NotConfigured(_) => "NOT_CONFIGURED",
            Self::RateLimited => "RATE_LIMITED",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        if let Self::Internal(ref e) = self {
            tracing::error!(error = ?e, "internal API error");
        }

        let status = self.status();
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code(),
                message: self.to_string(),
            },
        };

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn error_json(error: ApiError) -> (StatusCode, serde_json::Value) {
        let response = error.into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn test_unauthorized_response() {
        let (status, body) = error_json(ApiError::Unauthorized).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
        assert_eq!(body["error"]["message"], "missing or invalid authorization");
    }

    #[tokio::test]
    async fn test_forbidden_response() {
        let (status, body) = error_json(ApiError::Forbidden("not allowed".to_string())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "FORBIDDEN");
        assert_eq!(body["error"]["message"], "not allowed");
    }

    #[tokio::test]
    async fn test_bad_request_response() {
        let (status, body) = error_json(ApiError::BadRequest("invalid FQDN".to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "BAD_REQUEST");
        assert_eq!(body["error"]["message"], "invalid FQDN");
    }

    #[tokio::test]
    async fn test_not_configured_response() {
        let (status, body) =
            error_json(ApiError::NotConfigured("ACME not configured".to_string())).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(body["error"]["code"], "NOT_CONFIGURED");
    }

    #[tokio::test]
    async fn test_internal_error_hides_details() {
        let inner = anyhow::anyhow!("database connection failed: timeout after 30s");
        let (status, body) = error_json(ApiError::Internal(inner)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "INTERNAL_ERROR");
        assert_eq!(body["error"]["message"], "internal error");
    }
}
