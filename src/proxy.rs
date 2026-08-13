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
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use hyper::upgrade::OnUpgrade;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyperlocal_next::{UnixConnector, Uri};
use tokio::net::TcpListener;
use tower_http::timeout::TimeoutLayer;
use tracing::info;

use crate::config::Config;
use crate::error::ProxyError;
use crate::middleware::SecurityLayer;
use crate::observability::{self, Metrics, ObservabilityState};
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
    upgrade_tasks: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
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
fn build_router(
    state: AppState,
    security: SecurityLayer,
    timeout: Option<Duration>,
    observability: ObservabilityState,
) -> Router {
    let proxied = Router::new()
        .fallback(proxy_handler)
        .with_state(state)
        .layer(security);

    // Merged over the proxy rather than layered under it: these are answered
    // here, so the filter has no endpoint to decide about.
    let router = Router::new()
        .route("/metrics", get(observability::metrics))
        .route("/healthz", get(observability::health))
        .with_state(observability)
        .merge(proxied);

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
        upgrade_tasks: Arc::new(tokio::sync::Mutex::new(Vec::new())),
    };
    let upgrade_tasks = Arc::clone(&state.upgrade_tasks);
    let metrics = Arc::new(Metrics::default());

    let router = build_router(
        state,
        SecurityLayer::new(filter, config.max_body_bytes, Arc::clone(&metrics)),
        (config.timeout_secs > 0).then(|| Duration::from_secs(config.timeout_secs)),
        ObservabilityState {
            metrics,
            docker_socket: config.socket.clone(),
        },
    );
    let addr = SocketAddr::new(config.bind, config.port);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| ProxyError::Docker(format!("failed to bind to {addr}: {e}")))?;

    info!(
        "Listening on {addr}, forwarding to {}",
        config.socket.display()
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| ProxyError::Internal(e.to_string()))?;

    drain_upgrades(&upgrade_tasks).await;
    Ok(())
}

/// Create a router for integration testing.
#[doc(hidden)]
pub fn test_router(docker_socket: PathBuf, security: SecurityFilter) -> Router {
    let metrics = Arc::new(Metrics::default());
    build_router(
        AppState {
            docker_socket: docker_socket.clone(),
            upgrade_tasks: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        },
        SecurityLayer::new(security, 1024 * 1024, Arc::clone(&metrics)),
        None,
        ObservabilityState {
            metrics,
            docker_socket,
        },
    )
}

/// Forward an already-authorized request to the Docker socket.
///
/// # Contract
/// - **Pre-condition**: [`crate::middleware::SecurityLayer`] has allowed the
///   request. This handler performs no policy checks of its own.
async fn proxy_handler(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ProxyError> {
    let (mut parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();

    let path_and_query = match parts.uri.query() {
        Some(query) if !query.is_empty() => format!("{path}?{query}"),
        _ => path.clone(),
    };
    let target_uri: hyper::Uri = Uri::new(&state.docker_socket, &path_and_query).into();

    let mut req_builder = hyper::Request::builder()
        .method(parts.method.as_str())
        .uri(&target_uri);

    // `Host` is supplied by the Unix-socket transport.
    let client_connection_headers = connection_specific_headers(&parts.headers);
    for (key, value) in parts.headers.iter() {
        let key_lower = key.as_str().to_ascii_lowercase();
        if key_lower == "host" || is_hop_by_hop(&key_lower, &client_connection_headers) {
            continue;
        }
        req_builder = req_builder.header(key.as_str(), value.as_bytes());
    }

    // Regenerated rather than forwarded: the upgrade is negotiated per hop, so
    // the offer this proxy makes upstream is its own.
    let upgrade_offer = requested_upgrade(&parts.headers, &client_connection_headers);
    let client_upgrade = parts.extensions.remove::<OnUpgrade>();
    if let Some(protocol) = upgrade_offer {
        req_builder = req_builder
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, protocol);
    }

    let req = req_builder
        .body(body)
        .map_err(|e| ProxyError::Internal(format!("failed to build request: {e}")))?;

    // Docker's Unix HTTP server may close keep-alive connections between calls,
    // so a pooled socket can be stale by the time it is reused.
    let client: Client<UnixConnector, Body> = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(UnixConnector);
    let resp = client.request(req).await.map_err(|e| {
        if is_length_limit_error(&e) {
            return ProxyError::TooLarge("request body exceeded the configured limit".into());
        }
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
        response_builder = response_builder.header(key.as_str(), value.as_bytes());
    }

    if status == StatusCode::SWITCHING_PROTOCOLS {
        return switch_protocols(
            response_builder,
            resp,
            client_upgrade,
            Arc::clone(&state.upgrade_tasks),
        )
        .await;
    }

    // Relayed frame by frame rather than collected: `/events` and follow-mode
    // logs never end, so buffering them would withhold the whole response.
    response_builder
        .body(Body::new(resp.into_body()))
        .map_err(|e| ProxyError::Internal(format!("failed to build response: {e}")))
}

/// Whether a failed upstream send is the streamed body-size limit firing.
///
/// A `BodyRule::None` body is wrapped in [`http_body_util::Limited`] by the
/// enforcement layer and streamed through, so an over-limit chunked body fails
/// inside the hyper client as a nested [`http_body_util::LengthLimitError`]
/// rather than as a 413 the middleware set itself.
fn is_length_limit_error(mut err: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if err.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        match err.source() {
            Some(source) => err = source,
            None => return false,
        }
    }
}

/// The protocol a client offered to upgrade to.
///
/// RFC 9110 §7.8 requires the `Connection` field to name `upgrade` as well, so
/// an `Upgrade` header alone is not an offer.
fn requested_upgrade(
    headers: &HeaderMap,
    connection_specific: &HashSet<String>,
) -> Option<HeaderValue> {
    connection_specific
        .contains("upgrade")
        .then(|| headers.get(header::UPGRADE).cloned())
        .flatten()
}

/// Accept a 101 by splicing the client and upstream connections together.
///
/// The client half only becomes available once this response has been written,
/// so the copy has to outlive the handler.
async fn switch_protocols(
    mut response_builder: axum::http::response::Builder,
    mut upstream: hyper::Response<hyper::body::Incoming>,
    client_upgrade: Option<OnUpgrade>,
    upgrade_tasks: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
) -> Result<Response, ProxyError> {
    let client_upgrade = client_upgrade.ok_or_else(|| {
        ProxyError::Docker("upstream switched protocols without a client offer".into())
    })?;

    if let Some(protocol) = upstream.headers().get(header::UPGRADE).cloned() {
        response_builder = response_builder
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, protocol);
    }
    let upstream_upgrade = hyper::upgrade::on(&mut upstream);

    // Tracked so graceful shutdown can drain (then bound) live exec/attach
    // sessions instead of severing them when the runtime is dropped.
    let handle = tokio::spawn(async move {
        let (client, upstream) = match tokio::try_join!(client_upgrade, upstream_upgrade) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(error = %e, "connection upgrade failed");
                return;
            }
        };

        let mut client = TokioIo::new(client);
        let mut upstream = TokioIo::new(upstream);
        if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
            tracing::debug!(error = %e, "upgraded connection ended");
        }
    });
    upgrade_tasks.lock().await.push(handle);

    response_builder
        .body(Body::empty())
        .map_err(|e| ProxyError::Internal(format!("failed to build response: {e}")))
}

/// Let in-flight upgraded (101) connections finish, then abort any that outstay
/// a bounded drain so `docker stop` still terminates.
async fn drain_upgrades(tasks: &tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>) {
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

    let handles = std::mem::take(&mut *tasks.lock().await);
    if handles.is_empty() {
        return;
    }
    info!(count = handles.len(), "draining upgraded connections");
    for handle in handles {
        if tokio::time::timeout(DRAIN_TIMEOUT, handle).await.is_err() {
            tracing::debug!("upgraded connection outlasted the drain window");
        }
    }
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
    fn reads_an_upgrade_offer_only_when_connection_names_it() {
        let offered = headers(&[("connection", "upgrade"), ("upgrade", "tcp")]);
        let listed = connection_specific_headers(&offered);
        assert_eq!(
            requested_upgrade(&offered, &listed).unwrap().as_bytes(),
            b"tcp"
        );

        let bare = headers(&[("upgrade", "tcp")]);
        let listed = connection_specific_headers(&bare);
        assert!(requested_upgrade(&bare, &listed).is_none());
    }

    #[test]
    fn ignores_empty_connection_tokens() {
        let map = headers(&[("connection", "close,,  ,")]);
        let listed = connection_specific_headers(&map);
        assert!(listed.contains("close"));
        assert_eq!(listed.len(), 1);
    }
}
