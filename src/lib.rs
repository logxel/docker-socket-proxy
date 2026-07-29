//! `docker-socket-proxy` — A secure, minimal Docker socket proxy.
//!
//! Exposes the Docker API over TCP while filtering dangerous endpoints.
//! Built on Tokio, Axum, and Bollard.
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
pub mod proxy;
pub mod security;
