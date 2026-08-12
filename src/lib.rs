//! `docker-socket-proxy` — A secure, minimal Docker socket proxy.
//!
//! Exposes the Docker API over TCP while filtering dangerous endpoints.
//! Built on Tokio and Axum.
//!
//! # Architecture
//!
//! ```text
//! Request → Parse → Security Filter → Forward → Response
//!           |            |                |
//!           Fail → 400   Deny → 403       Error → 502
//! ```

pub mod config;
pub mod error;
pub mod middleware;
pub mod policy;
pub mod proxy;
pub mod security;
