use axum::{http::StatusCode, response::IntoResponse};

/// Health check endpoint.
///
/// Returns `200 ok` unconditionally. No authentication required.
pub(super) async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

#[cfg(test)]
mod tests {
    use crate::api::tests::test_server;

    #[tokio::test]
    async fn test_health() {
        let server = test_server();
        let response = server.get("/health").await;
        response.assert_status_ok();
        response.assert_text("ok");
    }
}
