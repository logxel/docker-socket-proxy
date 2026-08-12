//! Policy enforcement point.
//!
//! A [`tower::Layer`] that buffers the request body under a size limit, submits
//! the request to the decision point in [`crate::security`], and either passes
//! it inward or answers with the denial.
//!
//! # Contract
//! - **Invariant**: The inner service is called only for requests the filter
//!   allowed.
//! - **Invariant**: No more than `max_body_bytes` are buffered per request.

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use http_body_util::{BodyExt, Limited};
use tower::{Layer, Service};
use tracing::warn;

use crate::error::ProxyError;
use crate::security::SecurityFilter;

/// Applies [`SecurityFilter`] to every request.
#[derive(Clone)]
pub struct SecurityLayer {
    filter: SecurityFilter,
    max_body_bytes: usize,
}

impl SecurityLayer {
    pub fn new(filter: SecurityFilter, max_body_bytes: usize) -> Self {
        Self {
            filter,
            max_body_bytes,
        }
    }
}

impl<S> Layer<S> for SecurityLayer {
    type Service = SecurityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityService {
            inner,
            filter: self.filter.clone(),
            max_body_bytes: self.max_body_bytes,
        }
    }
}

#[derive(Clone)]
pub struct SecurityService<S> {
    inner: S,
    filter: SecurityFilter,
    max_body_bytes: usize,
}

impl<S> Service<Request> for SecurityService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // The clone is not the instance `poll_ready` readied, so swap rather
        // than calling the clone directly.
        let pending = self.inner.clone();
        let ready_inner = std::mem::replace(&mut self.inner, pending);
        let filter = self.filter.clone();
        let max_body_bytes = self.max_body_bytes;

        Box::pin(async move {
            let mut inner = ready_inner;
            let (parts, body) = request.into_parts();

            let body = match Limited::new(body, max_body_bytes).collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(error) => return Ok(body_error(error, max_body_bytes).into_response()),
            };

            let method = parts.method.as_str();
            let path = parts.uri.path();
            if let Err(denial) = filter.check_request(method, path, &body) {
                warn!(
                    method,
                    path,
                    profile = ?filter.profile(),
                    reason = %denial,
                    "request denied by security policy"
                );
                return Ok(denial.into_response());
            }

            inner
                .call(Request::from_parts(parts, Body::from(body)))
                .await
        })
    }
}

fn body_error(error: axum::BoxError, max_body_bytes: usize) -> ProxyError {
    if error
        .downcast_ref::<http_body_util::LengthLimitError>()
        .is_some()
    {
        ProxyError::TooLarge(format!("request body exceeds {max_body_bytes} bytes"))
    } else {
        ProxyError::Internal(format!("failed to read request body: {error}"))
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::any;
    use tower::ServiceExt;

    fn router(max_body_bytes: usize) -> Router {
        Router::new()
            .fallback(any(|| async { "reached upstream" }))
            .layer(SecurityLayer::new(SecurityFilter::new(), max_body_bytes))
    }

    async fn send(router: Router, method: &str, uri: &str, body: &str) -> StatusCode {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body.to_owned()))
            .unwrap();
        router.oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn allows_permitted_requests_through() {
        assert_eq!(
            send(router(1024), "GET", "/version", "").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn denies_before_reaching_the_inner_service() {
        assert_eq!(
            send(router(1024), "POST", "/containers/create", "{}").await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn rejects_bodies_over_the_limit() {
        let oversized = "x".repeat(64);
        assert_eq!(
            send(router(16), "POST", "/containers/create", &oversized).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn normalizes_paths_before_deciding() {
        assert_eq!(
            send(router(1024), "GET", "/containers/../version", "").await,
            StatusCode::OK
        );
        assert_eq!(
            send(router(1024), "GET", "/v1.55/version", "").await,
            StatusCode::OK
        );
    }
}
