//! Application configuration.
//!
//! Parsed from CLI arguments and environment variables via `clap`. Every field
//! has a default.
//!
//! # Contract
//! - **Post-condition**: A returned `Config` is fully valid; invalid input exits
//!   the process before the runtime starts rather than yielding partial state.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::Parser;

/// Secure Docker socket proxy.
#[derive(Debug, Clone, Parser)]
#[command(name = "docker-socket-proxy", version, about)]
pub struct Config {
    /// TCP port to listen on.
    #[arg(long, env = "DOCKER_PROXY_PORT", default_value = "2375")]
    pub port: u16,

    /// Address to listen on.
    ///
    /// Loopback by default: the port has no authentication, so reaching it is
    /// the whole authorization story. The image sets `0.0.0.0` because there
    /// the container boundary and published ports control exposure instead.
    /// `::` requires IPv6 to be enabled on the host.
    #[arg(long, env = "DOCKER_PROXY_BIND", default_value = "127.0.0.1")]
    pub bind: IpAddr,

    /// Path to the Docker Unix socket.
    #[arg(long, env = "DOCKER_SOCKET", default_value = "/var/run/docker.sock")]
    pub socket: PathBuf,

    /// Path to a TOML or YAML allowlist file, merged over the profile.
    ///
    /// The format is taken from the extension: `.toml`, `.yaml`, or `.yml`.
    #[arg(long, env = "DOCKER_PROXY_ALLOWLIST")]
    pub allowlist: Option<PathBuf>,

    /// Built-in security profile.
    #[arg(long, env = "DOCKER_PROXY_PROFILE", default_value = "default")]
    pub profile: SecurityProfile,

    /// Maximum request body size in bytes.
    ///
    /// Image build contexts are the large case; raise this where `/build` is
    /// permitted and used.
    #[arg(long, env = "DOCKER_PROXY_MAX_BODY_BYTES", default_value = "16777216")]
    pub max_body_bytes: usize,

    /// Request timeout in seconds; `0` disables it.
    ///
    /// Disabled by default because `/containers/{id}/wait` and follow-mode logs
    /// legitimately block for as long as the workload runs, and a timeout short
    /// enough to bound an attacker would sever them.
    #[arg(long, env = "DOCKER_PROXY_TIMEOUT_SECS", default_value = "0")]
    pub timeout_secs: u64,

    /// Probe a running proxy on `--port` and exit 0 if it reports healthy.
    ///
    /// For a container `HEALTHCHECK`: the `scratch` image has no shell or curl
    /// to call `/healthz` with.
    #[arg(long)]
    pub health_check: bool,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_level: String,

    /// Log format: "json" or "pretty".
    #[arg(long, env = "DOCKER_PROXY_LOG_FORMAT", default_value = "json")]
    pub log_format: LogFormat,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum SecurityProfile {
    Default,
    ReadOnly,
    ContainerRuntime,
    /// Grants nothing, so an allowlist is the whole policy rather than an
    /// addition to one.
    None,
}

impl Config {
    /// Parse configuration from the environment.
    ///
    /// # Panics
    /// On invalid CLI input, by design: this runs before the async runtime, so
    /// Fail-Fast applies.
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
}
