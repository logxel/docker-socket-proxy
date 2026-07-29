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
/// Each variant maps to a known HTTP status code for the client-facing
/// error response. Internal errors produce 502 Bad Gateway.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Configuration parsing or validation failure.
    #[error("configuration error: {0}")]
    Config(String),

    /// Request blocked by the security filter.
    #[error("access denied: {0}")]
    Forbidden(String),

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
            ProxyError::Docker(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            ProxyError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = json!({
            "error": message,
            "status": status.as_u16(),
        });

        (status, Json(body)).into_response()
    }
}
