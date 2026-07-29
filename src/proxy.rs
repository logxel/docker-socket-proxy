//! Proxy engine that accepts HTTP requests on TCP and forwards
//! them to the Docker Unix socket after security filtering.
//!
//! # Contract
//! - **Pre-condition**: A valid `Config` and `SecurityFilter` must be provided.
//! - **Post-condition**: The proxy binds to the configured TCP port and
//!   serves requests until a shutdown signal is received.
//! - **Invariant**: Every request passes through the `SecurityFilter` check
//!   before reaching the Docker socket.
//!
//! # Architecture
//! ```text
//! Client → TCP :2375 → Axum Router → SecurityFilter.check()
//!                                         │
//!                               ┌─ Deny ─┴─ Allow ─┐
//!                               ▼                   ▼
//!                             403          hyperlocal-next
//!                                          Unix socket → Docker
//! ```

use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyperlocal_next::{UnixConnector, Uri};
use tokio::net::TcpListener;
use tracing::info;

use crate::config::Config;
use crate::error::ProxyError;
use crate::security::SecurityFilter;

/// Shared application state passed to every request handler.
#[derive(Clone)]
pub struct AppState {
    docker_socket: PathBuf,
    security: SecurityFilter,
}

/// Build the Axum router with all routes.
fn build_router(state: AppState) -> Router {
    Router::new().fallback(proxy_handler).with_state(state)
}

/// Start the proxy server.
///
/// Binds to the configured TCP port and runs until a shutdown signal
/// (SIGTERM or Ctrl+C) is received.
pub async fn serve(config: Config) -> Result<(), ProxyError> {
    let state = AppState {
        docker_socket: config.socket.clone(),
        security: SecurityFilter::from_file_and_profile(
            config.allowlist.as_deref(),
            &config.profile,
        ),
    };

    let router = build_router(state);
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| ProxyError::Docker(format!("failed to bind to {addr}: {e}")))?;

    info!(
        "Listening on {addr}, forwarding to {}",
        config.socket.display()
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| ProxyError::Internal(e.to_string()))
}

/// Create a router for integration testing.
#[doc(hidden)]
pub fn test_router(docker_socket: PathBuf, security: SecurityFilter) -> Router {
    let state = AppState {
        docker_socket,
        security,
    };
    build_router(state)
}

/// Catch-all proxy handler.
///
/// 1. Extracts method, path, headers, and body from the incoming request.
/// 2. Runs the security filter.
/// 3. Forwards the request to the Docker socket via hyperlocal-next.
/// 4. Returns the Docker response to the client.
async fn proxy_handler(
    State(state): State<AppState>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProxyError> {
    let path = uri.path();
    let query = uri.query().unwrap_or("");

    // ── Security check ────────────────────────────────────────
    state.security.check_request(method.as_str(), path, &body)?;

    // ── Build target URI ──────────────────────────────────────
    let path_and_query = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    let target_uri: hyper::Uri = Uri::new(&state.docker_socket, &path_and_query).into();

    // ── Build forwarded request ───────────────────────────────
    let mut req_builder = hyper::Request::builder()
        .method(method.as_str())
        .uri(&target_uri);

    for (key, value) in headers.iter() {
        let key_lower = key.as_str().to_lowercase();
        if key_lower != "host" {
            req_builder = req_builder.header(key.as_str(), value.as_bytes());
        }
    }

    let req = req_builder
        .body(Full::new(body))
        .map_err(|e| ProxyError::Internal(format!("failed to build request: {e}")))?;

    // ── Forward via Unix socket ───────────────────────────────
    // Docker's Unix HTTP server may close keep-alive connections between API
    // calls. Avoid reusing a stale pooled socket for the next request.
    let client: Client<UnixConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(UnixConnector);
    let resp = client.request(req).await.map_err(|e| {
        tracing::error!(error = %e, path, "Docker upstream request failed");
        ProxyError::Docker(format!("forward failed: {e}"))
    })?;
    tracing::debug!(status = %resp.status(), path, "Docker upstream response received");

    // ── Convert response ──────────────────────────────────────
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = Response::builder().status(status);

    for (key, value) in resp.headers() {
        if matches!(
            key.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        ) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            response_builder = response_builder.header(key.as_str(), v);
        }
    }

    let body_bytes = resp
        .collect()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, path, "Docker upstream response read failed");
            ProxyError::Docker(format!("failed to read response: {e}"))
        })?
        .to_bytes();

    response_builder
        .body(Body::from(body_bytes))
        .map_err(|e| ProxyError::Internal(format!("failed to build response: {e}")))
}

/// Wait for a shutdown signal (SIGTERM or Ctrl+C).
async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Shutdown signal received, draining connections…");
        }
        Err(e) => {
            tracing::error!("Failed to install Ctrl+C handler: {e}. ");
        }
    }
}
