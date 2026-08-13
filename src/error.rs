//! Error types for `docker-socket-proxy`.
//!
//! All errors follow the [Railway Oriented Programming](https://fsharpforfunandprofit.com/rop/)
//! pattern: every fallible operation returns `Result<T, ProxyError>`.
//!
//! # Contract
//! - **Pre-condition**: Callers must propagate errors via `?`, never `.unwrap()`.
//! - **Post-condition**: Every error variant carries enough context for precise
//!   logging and debugging.
//! - **Invariant**: No error variant silently discards its source error.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Top-level error for all proxy operations.
///
/// # Contract
/// - **Invariant**: Rendering produces the Docker Engine API error shape,
///   `{"message": "…"}`, so Docker clients deserialize proxy errors with the
///   type they already use for daemon errors.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Configuration parsing or validation failure.
    #[error("configuration error: {0}")]
    Config(String),

    /// Request blocked by the security filter.
    #[error("access denied: {0}")]
    Forbidden(String),

    /// Request could not be parsed, as opposed to refused by policy.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Request body exceeded the configured limit.
    #[error("payload too large: {0}")]
    TooLarge(String),

    /// Failed to forward the request to the Docker socket.
    #[error("docker socket error: {0}")]
    Docker(String),

    /// Unexpected internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ProxyError::Config(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ProxyError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            ProxyError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ProxyError::TooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg.clone()),
            ProxyError::Docker(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            ProxyError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        let body = json!({ "message": message });

        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_of(err: ProxyError) -> (StatusCode, serde_json::Value) {
        let response = err.into_response();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn renders_docker_shaped_error_body() {
        let (status, body) = body_of(ProxyError::Forbidden("blocked endpoint".into())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["message"], "blocked endpoint");
        assert!(body.get("error").is_none());
        assert!(body.get("status").is_none());
    }

    #[tokio::test]
    async fn maps_variants_to_expected_status_codes() {
        assert_eq!(
            body_of(ProxyError::Config("bad".into())).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            body_of(ProxyError::Docker("down".into())).await.0,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            body_of(ProxyError::Internal("boom".into())).await.0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn bad_request_maps_to_400() {
        assert_eq!(
            body_of(ProxyError::BadRequest("garbage".into())).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn internal_error_body_carries_only_the_message() {
        let (_, body) = body_of(ProxyError::Internal("boom".into())).await;
        assert_eq!(body["message"], "boom");
    }
}
