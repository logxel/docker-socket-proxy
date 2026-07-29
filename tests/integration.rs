//! Integration tests for `docker-socket-proxy`.
//!
//! Tests the full pipeline: request → security filter → Unix socket
//! forwarding → response. Uses a mock Docker server on a temp socket.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use docker_socket_proxy::proxy::test_router;
use docker_socket_proxy::security::SecurityFilter;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;
use tower::ServiceExt;

// ── Mock Docker ─────────────────────────────────────────────────

/// Spawns a minimal mock Docker daemon on a Unix socket.
async fn spawn_mock(socket_path: PathBuf) {
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind mock socket");

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(mock_handler))
                    .await;
            });
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

async fn mock_handler(
    _req: HyperRequest<Incoming>,
) -> Result<HyperResponse<Full<Bytes>>, hyper::Error> {
    Ok(HyperResponse::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(
            r#"{"Version":"20.10.0-mock","ApiVersion":"1.41"}"#,
        )))
        .unwrap())
}

// ── Tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn forwards_allowed_request_to_docker() {
    let socket = std::env::temp_dir().join("test-proxy-forward.sock");
    spawn_mock(socket.clone()).await;

    let router = test_router(socket, SecurityFilter::new());

    let req = Request::builder()
        .method(Method::GET)
        .uri("/version")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["Version"], "20.10.0-mock");
}

#[tokio::test]
async fn blocks_denied_endpoint_with_403() {
    let socket = std::env::temp_dir().join("test-proxy-block.sock");
    spawn_mock(socket.clone()).await;

    let router = test_router(socket, SecurityFilter::new());

    let req = Request::builder()
        .method(Method::POST)
        .uri("/containers/create")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"Image":"nginx"}"#))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], 403);
}

#[tokio::test]
async fn returns_502_when_docker_unreachable() {
    let router = test_router(
        PathBuf::from("/nonexistent/docker.sock"),
        SecurityFilter::new(),
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri("/version")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}
