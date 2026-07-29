//! Application configuration.
//!
//! Configuration is parsed from CLI arguments and environment variables
//! using `clap`. Every field has a sensible default.
//!
//! # Contract
//! - **Pre-condition**: `Config::parse()` must succeed; invalid values cause
//!   the process to exit early with a descriptive message.
//! - **Post-condition**: Returned `Config` is always valid (no partial state).
//! - **Invariant**: All paths are `PathBuf`, never raw strings.

use std::path::PathBuf;

use clap::Parser;

/// Secure Docker socket proxy.
#[derive(Debug, Clone, Parser)]
#[command(name = "docker-socket-proxy", version, about)]
pub struct Config {
    /// TCP port to listen on.
    #[arg(long, env = "DOCKER_PROXY_PORT", default_value = "2375")]
    pub port: u16,

    /// Path to the Docker Unix socket.
    #[arg(long, env = "DOCKER_SOCKET", default_value = "/var/run/docker.sock")]
    pub socket: PathBuf,

    /// Path to a TOML allowlist configuration file.
    ///
    /// When provided, the allowlist overrides built-in defaults.
    #[arg(long, env = "DOCKER_PROXY_ALLOWLIST")]
    pub allowlist: Option<PathBuf>,

    /// Built-in security profile.
    #[arg(long, env = "DOCKER_PROXY_PROFILE", default_value = "default")]
    pub profile: SecurityProfile,

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
}

impl Config {
    /// Parse configuration from the environment.
    ///
    /// # Panics
    /// Panics on invalid CLI input (by design — this is the entry point
    /// before the async runtime starts, and Fail-Fast applies).
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
}
