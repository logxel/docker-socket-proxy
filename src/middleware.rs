//! Policy enforcement point.
//!
//! A [`tower::Layer`] that submits each request to the decision point in
//! [`crate::security`], then either passes it inward or answers with the denial.
//!
//! Only bodies the decision actually rests on are buffered; the rest stream
//! through, which is what lets `/build` and the other large uploads work.
//!
//! # Contract
//! - **Invariant**: The inner service is called only for requests the filter
//!   allowed.
//! - **Invariant**: No more than `max_body_bytes` pass through per request,
//!   buffered or streamed.

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use http_body_util::{BodyExt, Limited};
use tower::{Layer, Service};
use tracing::warn;

use crate::error::ProxyError;
use crate::security::{BodyRule, SecurityFilter};

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
            let audit = |denial: ProxyError| {
                warn!(
                    method = parts.method.as_str(),
                    path = parts.uri.path(),
                    profile = ?filter.profile(),
                    reason = %denial,
                    "request denied by security policy"
                );
                denial.into_response()
            };

            let rule = match filter.check_head(parts.method.as_str(), parts.uri.path()) {
                Ok(rule) => rule,
                Err(denial) => return Ok(audit(denial)),
            };

            let body = match rule {
                BodyRule::None => match oversized_declaration(&parts.headers, max_body_bytes) {
                    Some(error) => return Ok(error.into_response()),
                    None => Body::new(Limited::new(body, max_body_bytes)),
                },
                rule => {
                    let collected = match Limited::new(body, max_body_bytes).collect().await {
                        Ok(collected) => collected.to_bytes(),
                        Err(error) => {
                            return Ok(body_error(error, max_body_bytes).into_response());
                        }
                    };
                    if let Err(denial) = SecurityFilter::check_body(rule, &collected) {
                        return Ok(audit(denial));
                    }
                    Body::from(collected)
                }
            };

            inner.call(Request::from_parts(parts, body)).await
        })
    }
}

/// Refuse an over-limit body before reading it, when the sender declared a size.
///
/// A streamed body has no declared length, so [`Limited`] stays the backstop —
/// it can only abort mid-transfer, which is why a declaration is worth checking.
fn oversized_declaration(headers: &HeaderMap, max_body_bytes: usize) -> Option<ProxyError> {
    let declared = headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()?;

    (declared > max_body_bytes as u64)
        .then(|| ProxyError::TooLarge(format!("request body exceeds {max_body_bytes} bytes")))
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
    use axum::body::Bytes;
    use axum::http::StatusCode;
    use axum::routing::any;
    use tower::ServiceExt;

    use crate::config::SecurityProfile;

    /// Answers with the body length, so a test can tell what actually arrived.
    fn router_with(filter: SecurityFilter, max_body_bytes: usize) -> Router {
        Router::new()
            .fallback(any(async |body: Bytes| body.len().to_string()))
            .layer(SecurityLayer::new(filter, max_body_bytes))
    }

    fn router(max_body_bytes: usize) -> Router {
        router_with(SecurityFilter::new(), max_body_bytes)
    }

    async fn respond(
        router: Router,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Response {
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        router
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap()
    }

    async fn send(router: Router, method: &str, uri: &str, body: &str) -> StatusCode {
        respond(router, method, uri, &[], body).await.status()
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
    async fn rejects_an_oversized_inspected_body() {
        let filter = SecurityFilter::for_profile(&SecurityProfile::ContainerRuntime);
        assert_eq!(
            send(
                router_with(filter, 16),
                "POST",
                "/containers/create",
                &"x".repeat(64)
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn refuses_a_declared_oversize_before_reading_it() {
        let response = respond(
            router(16),
            "GET",
            "/version",
            &[("content-length", "64")],
            &"x".repeat(64),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn passes_uninspected_bodies_through_intact() {
        let response = respond(router(1024), "GET", "/version", &[], &"x".repeat(64)).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"64", "the whole body reached the handler");
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
