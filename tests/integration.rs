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

/// Echoes the headers it received back to the caller so tests can assert on
/// what the proxy actually forwarded.
async fn mock_handler(
    req: HyperRequest<Incoming>,
) -> Result<HyperResponse<Full<Bytes>>, hyper::Error> {
    let received: Vec<String> = req
        .headers()
        .keys()
        .map(|k| k.as_str().to_ascii_lowercase())
        .collect();

    // Echo the caller-supplied id so a test can match each response to the
    // request that produced it; a crossed connection would carry the wrong one.
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let body = serde_json::json!({
        "Version": "20.10.0-mock",
        "ApiVersion": "1.41",
        "RequestId": request_id,
        "ReceivedHeaders": received,
    });

    Ok(HyperResponse::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
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

    // Docker Engine API error contract: `{"message": ...}`.
    let message = json["message"].as_str().expect("message field");
    assert!(message.contains("/containers/create"), "got: {message}");
    assert!(json.get("error").is_none());
    assert!(json.get("status").is_none());
}

#[tokio::test]
async fn does_not_forward_hop_by_hop_headers_upstream() {
    let socket = std::env::temp_dir().join("test-proxy-hop-by-hop.sock");
    spawn_mock(socket.clone()).await;

    let router = test_router(socket, SecurityFilter::new());

    let req = Request::builder()
        .method(Method::GET)
        .uri("/version")
        // Naming `X-Secret` here makes it connection-specific per RFC 9110 §7.6.1.
        .header("Connection", "keep-alive, X-Secret")
        .header("X-Secret", "do-not-forward")
        .header("Keep-Alive", "timeout=5")
        .header("X-Public", "forward-me")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let seen: Vec<&str> = json["ReceivedHeaders"]
        .as_array()
        .expect("ReceivedHeaders")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

    for stripped in ["connection", "keep-alive", "x-secret"] {
        assert!(
            !seen.contains(&stripped),
            "{stripped} leaked upstream: {seen:?}"
        );
    }
    assert!(
        seen.contains(&"x-public"),
        "end-to-end header dropped: {seen:?}"
    );
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

/// Fire 100 requests concurrently through one router and prove each response
/// answers its own request: every allowed GET must come back with the mock
/// body, every denied POST with the Docker-shaped 403. No request may be
/// dropped or served twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handles_100_simultaneous_requests_with_per_response_integrity() {
    let socket = std::env::temp_dir().join("test-proxy-parallel-100.sock");
    spawn_mock(socket.clone()).await;

    let router = test_router(socket, SecurityFilter::new());
    const ALLOWED: usize = 50;
    const DENIED: usize = 50;

    // Every future owns a clone of the same router; join_all polls them all
    // in flight rather than awaiting one request at a time.
    let requests = (0..ALLOWED + DENIED).map(|i| {
        let router = router.clone();
        async move {
            let req = if i < ALLOWED {
                Request::builder()
                    .method(Method::GET)
                    .uri(if i % 2 == 0 { "/version" } else { "/info" })
                    .body(Body::empty())
                    .unwrap()
            } else {
                Request::builder()
                    .method(Method::POST)
                    .uri("/containers/create")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"Image":"nginx"}"#))
                    .unwrap()
            };
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (i, status, body)
        }
    });

    let responses: Vec<_> = futures_util::future::join_all(requests).await;
    assert_eq!(
        responses.len(),
        ALLOWED + DENIED,
        "no request may be dropped"
    );

    let ok = responses
        .iter()
        .filter(|(_, status, _)| *status == StatusCode::OK)
        .count();
    let forbidden = responses
        .iter()
        .filter(|(_, status, _)| *status == StatusCode::FORBIDDEN)
        .count();
    assert_eq!(ok, ALLOWED, "every allowed GET must return 200");
    assert_eq!(forbidden, DENIED, "every denied POST must return 403");

    for (i, status, body) in responses {
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if i < ALLOWED {
            assert_eq!(status, StatusCode::OK, "response {i} corrupted");
            assert_eq!(json["Version"], "20.10.0-mock", "response {i} body");
            assert_eq!(json["ApiVersion"], "1.41", "response {i} body");
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "response {i} corrupted");
            let message = json["message"].as_str().expect("message field");
            assert!(message.contains("/containers/create"), "got: {message}");
            assert!(json.get("error").is_none(), "response {i} error shape");
            assert!(json.get("status").is_none(), "response {i} error shape");
        }
    }
}

/// 50 concurrent requests each carrying a unique X-Request-Id, all through the
/// same router. The mock echoes the id back, so any crossed or bled response
/// would be caught by the mismatch between the id a response carries and the
/// one its index expects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_requests_keep_their_own_headers() {
    let socket = std::env::temp_dir().join("test-proxy-parallel-headers.sock");
    spawn_mock(socket.clone()).await;

    let router = test_router(socket, SecurityFilter::new());
    const CONCURRENT: usize = 50;

    let requests = (0..CONCURRENT).map(|i| {
        let router = router.clone();
        async move {
            let request_id = format!("req-{i:04}");
            let req = Request::builder()
                .method(Method::GET)
                .uri("/version")
                .header("X-Request-Id", &request_id)
                .body(Body::empty())
                .unwrap();
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (i, status, body)
        }
    });

    let responses: Vec<_> = futures_util::future::join_all(requests).await;
    assert_eq!(responses.len(), CONCURRENT, "no request may be dropped");

    for (i, status, body) in responses {
        assert_eq!(status, StatusCode::OK, "response {i} corrupted");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["RequestId"],
            format!("req-{i:04}"),
            "response {i} crossed with another request"
        );
        let seen: Vec<&str> = json["ReceivedHeaders"]
            .as_array()
            .expect("ReceivedHeaders")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert!(
            seen.contains(&"x-request-id"),
            "response {i} lost its own header: {seen:?}"
        );
    }
}

/// A malformed percent-encoding is a syntactically invalid request (400), not a
/// policy denial (403): the path never reached the matching stage.
#[tokio::test]
async fn returns_400_for_malformed_path() {
    // The socket is never contacted; normalization rejects before forwarding.
    let router = test_router(
        PathBuf::from("/nonexistent/docker.sock"),
        SecurityFilter::new(),
    );

    // `%FF` is well-formed percent-encoding that decodes to an invalid UTF-8
    // byte, so it passes URI parsing and is refused by the normalizer as a bad
    // request rather than an authorization failure.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/info%FF")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["message"].as_str().is_some(),
        "Docker-shaped error body"
    );
}

/// Body inspection must run for any policy that permits `POST /containers/create`,
/// not only the `container-runtime` profile.
#[tokio::test]
async fn create_body_inspection_runs_for_non_runtime_profiles() {
    let socket = std::env::temp_dir().join("test-proxy-inspect-none.sock");
    spawn_mock(socket.clone()).await;

    let mut filter = SecurityFilter::deny_all();
    filter.allow_mut().push(
        Some(vec!["POST".to_owned()]),
        Some(vec!["/containers/create".to_owned()]),
    );
    let router = test_router(socket, filter);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/containers/create")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"Image":"x","HostConfig":{"Privileged":true}}"#,
        ))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
