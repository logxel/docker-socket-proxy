//! Transport adapter: accepts HTTP over TCP and relays it to the Docker Unix
//! socket. Policy lives in [`crate::middleware`] and [`crate::security`].
//!
//! # Contract
//! - **Post-condition**: The proxy binds to the configured TCP port and serves
//!   until a shutdown signal is received.
//! - **Invariant**: The handler is reachable only through
//!   [`crate::middleware::SecurityLayer`], so no request reaches the socket
//!   unevaluated.
//!
//! # Architecture
//! ```text
//! Client → TCP :2375 → Timeout → SecurityLayer (PEP) → proxy_handler
//!                                      │                     │
//!                            ┌─ Deny ─┴─ Allow ─┐            ▼
//!                            ▼                   ▼    hyperlocal-next
//!                          403/413          (inward)  Unix socket → Docker
//! ```

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

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
use tower_http::timeout::TimeoutLayer;
use tracing::info;

use crate::config::Config;
use crate::error::ProxyError;
use crate::middleware::SecurityLayer;
use crate::policy::PolicyLoader;
use crate::security::SecurityFilter;

/// Headers an intermediary must not forward, per RFC 9110 §7.6.1.
const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Shared application state passed to every request handler.
#[derive(Clone)]
pub struct AppState {
    docker_socket: PathBuf,
}

/// Collect the header names listed in `Connection`.
///
/// The list is extensible: a sender may name any header as connection-specific,
/// and those must be stripped alongside [`HOP_BY_HOP_HEADERS`].
fn connection_specific_headers(headers: &HeaderMap) -> HashSet<String> {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

/// Whether a header must be dropped when relaying a message across a hop.
fn is_hop_by_hop(name: &str, connection_specific: &HashSet<String>) -> bool {
    let lower = name.to_ascii_lowercase();
    HOP_BY_HOP_HEADERS.contains(&lower.as_str()) || connection_specific.contains(&lower)
}

/// Build the router, wrapping the handler in the enforcement layers.
///
/// The timeout is outermost so it bounds policy evaluation as well as the
/// upstream call.
fn build_router(state: AppState, security: SecurityLayer, timeout: Option<Duration>) -> Router {
    let router = Router::new()
        .fallback(proxy_handler)
        .with_state(state)
        .layer(security);

    match timeout {
        // 504 rather than 408: the deadline that expired is ours to the daemon,
        // not the client's to us.
        Some(timeout) => router.layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            timeout,
        )),
        None => router,
    }
}

/// Start the proxy server, serving until a shutdown signal arrives.
pub async fn serve(config: Config) -> Result<(), ProxyError> {
    let filter = PolicyLoader::new(config.allowlist.as_deref(), &config.profile).load()?;
    let state = AppState {
        docker_socket: config.socket.clone(),
    };

    let router = build_router(
        state,
        SecurityLayer::new(filter, config.max_body_bytes),
        (config.timeout_secs > 0).then(|| Duration::from_secs(config.timeout_secs)),
    );
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
    build_router(
        AppState { docker_socket },
        SecurityLayer::new(security, 1024 * 1024),
        None,
    )
}

/// Forward an already-authorized request to the Docker socket.
///
/// # Contract
/// - **Pre-condition**: [`crate::middleware::SecurityLayer`] has allowed the
///   request. This handler performs no policy checks of its own.
async fn proxy_handler(
    State(state): State<AppState>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProxyError> {
    let path = uri.path();
    let query = uri.query().unwrap_or("");

    let path_and_query = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    let target_uri: hyper::Uri = Uri::new(&state.docker_socket, &path_and_query).into();

    let mut req_builder = hyper::Request::builder()
        .method(method.as_str())
        .uri(&target_uri);

    // `Host` is supplied by the Unix-socket transport.
    let client_connection_headers = connection_specific_headers(&headers);
    for (key, value) in headers.iter() {
        let key_lower = key.as_str().to_ascii_lowercase();
        if key_lower == "host" || is_hop_by_hop(&key_lower, &client_connection_headers) {
            continue;
        }
        req_builder = req_builder.header(key.as_str(), value.as_bytes());
    }

    let req = req_builder
        .body(Full::new(body))
        .map_err(|e| ProxyError::Internal(format!("failed to build request: {e}")))?;

    // Docker's Unix HTTP server may close keep-alive connections between calls,
    // so a pooled socket can be stale by the time it is reused.
    let client: Client<UnixConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(UnixConnector);
    let resp = client.request(req).await.map_err(|e| {
        tracing::error!(error = %e, path, "Docker upstream request failed");
        ProxyError::Docker(format!("forward failed: {e}"))
    })?;
    tracing::debug!(status = %resp.status(), path, "Docker upstream response received");

    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = Response::builder().status(status);

    let upstream_connection_headers = connection_specific_headers(resp.headers());
    for (key, value) in resp.headers() {
        if is_hop_by_hop(key.as_str(), &upstream_connection_headers) {
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

/// Wait for a shutdown signal (SIGTERM or SIGINT).
///
/// SIGTERM is what `docker stop` and Kubernetes send. A branch whose handler
/// fails to install parks forever rather than resolving, so a failed handler
/// cannot present itself as a shutdown request.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "failed to install SIGINT handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => info!(signal = "SIGINT", "Shutdown signal received, draining connections…"),
        () = terminate => info!(signal = "SIGTERM", "Shutdown signal received, draining connections…"),
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn strips_well_known_hop_by_hop_headers() {
        let listed = connection_specific_headers(&HeaderMap::new());
        for name in HOP_BY_HOP_HEADERS {
            assert!(is_hop_by_hop(name, &listed), "{name} should be stripped");
        }
        assert!(!is_hop_by_hop("content-type", &listed));
    }

    #[test]
    fn strips_headers_named_by_connection() {
        let map = headers(&[("connection", "keep-alive, X-Secret")]);
        let listed = connection_specific_headers(&map);
        assert!(is_hop_by_hop("x-secret", &listed));
        assert!(
            is_hop_by_hop("X-Secret", &listed),
            "match is ASCII-case-insensitive"
        );
        assert!(!is_hop_by_hop("x-public", &listed));
    }

    #[test]
    fn collects_tokens_across_repeated_connection_headers() {
        let map = headers(&[("connection", "X-One"), ("connection", "X-Two , X-Three")]);
        let listed = connection_specific_headers(&map);
        for name in ["x-one", "x-two", "x-three"] {
            assert!(is_hop_by_hop(name, &listed), "{name} should be stripped");
        }
    }

    #[test]
    fn ignores_empty_connection_tokens() {
        let map = headers(&[("connection", "close,,  ,")]);
        let listed = connection_specific_headers(&map);
        assert!(listed.contains("close"));
        assert_eq!(listed.len(), 1);
    }
}
