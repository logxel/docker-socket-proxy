//! Metrics and health endpoints.
//!
//! Answered by this process rather than forwarded, so they are routed ahead of
//! the proxy fallback and outside the security filter. Docker's API defines
//! neither path, so nothing is shadowed.
//!
//! # Contract
//! - **Invariant**: Neither endpoint reaches the Docker socket, so neither can
//!   be used to probe it beyond the reachability that `/healthz` reports.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// How long `--health-check` waits on the loopback probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Request outcomes, counted for the OpenMetrics exposition.
#[derive(Debug, Default)]
pub struct Metrics {
    allowed: AtomicU64,
    denied: AtomicU64,
}

impl Metrics {
    pub fn record_allowed(&self) {
        self.allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_denied(&self) {
        self.denied.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn render(&self) -> String {
        let allowed = self.allowed.load(Ordering::Relaxed);
        let denied = self.denied.load(Ordering::Relaxed);
        format!(
            "# HELP docker_socket_proxy_requests_total Requests by policy outcome.\n\
             # TYPE docker_socket_proxy_requests_total counter\n\
             docker_socket_proxy_requests_total{{outcome=\"allowed\"}} {allowed}\n\
             docker_socket_proxy_requests_total{{outcome=\"denied\"}} {denied}\n"
        )
    }
}

/// State for the endpoints this module serves.
#[derive(Clone)]
pub struct ObservabilityState {
    pub metrics: Arc<Metrics>,
    pub docker_socket: PathBuf,
}

pub async fn metrics(State(state): State<ObservabilityState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
        .into_response()
}

/// Report whether the Docker socket still accepts a connection.
///
/// Shaped per the IETF API health check draft. Connecting is the whole check —
/// sending a request would need a policy decision about an endpoint the
/// operator may not have allowed.
pub async fn health(State(state): State<ObservabilityState>) -> Response {
    let (status, body) = match UnixStream::connect(&state.docker_socket).await {
        Ok(_) => (StatusCode::OK, r#"{"status":"pass"}"#),
        Err(e) => {
            tracing::warn!(error = %e, socket = %state.docker_socket.display(),
                           "health check could not reach the Docker socket");
            (StatusCode::SERVICE_UNAVAILABLE, r#"{"status":"fail"}"#)
        }
    };

    (
        status,
        [(header::CONTENT_TYPE, "application/health+json")],
        body,
    )
        .into_response()
}

/// Probe a running proxy over loopback and report whether it answered `pass`.
///
/// Exists because the `scratch` image carries no shell or curl, so a container
/// `HEALTHCHECK` has nothing else to call. Hand-rolled rather than pulling in an
/// HTTP client, since one request against a known server does not need one.
pub async fn probe(port: u16) -> Result<(), String> {
    let request =
        format!("GET /healthz HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");

    let exchange = async {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|e| format!("connect failed: {e}"))?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        Ok::<_, String>(response)
    };

    let response = tokio::time::timeout(PROBE_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("no response within {PROBE_TIMEOUT:?}"))??;

    let head = String::from_utf8_lossy(&response);
    if head.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(head.lines().next().unwrap_or("empty response").to_owned())
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn renders_both_outcomes_in_openmetrics_form() {
        let metrics = Metrics::default();
        metrics.record_allowed();
        metrics.record_allowed();
        metrics.record_denied();

        let rendered = metrics.render();
        assert!(rendered.contains(r#"docker_socket_proxy_requests_total{outcome="allowed"} 2"#));
        assert!(rendered.contains(r#"docker_socket_proxy_requests_total{outcome="denied"} 1"#));
        assert!(
            rendered.contains("# TYPE docker_socket_proxy_requests_total counter"),
            "a counter must declare its type"
        );
    }

    #[tokio::test]
    async fn probe_reports_a_closed_port() {
        // Port 1 is privileged and unbound in the test environment.
        assert!(probe(1).await.is_err());
    }
}
