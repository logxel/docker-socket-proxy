//! Entry point for `docker-socket-proxy`.
//!
//! Parses configuration, initialises structured logging, and starts
//! the proxy server. On any error, logs the cause and exits with code 1
//! (Fail-Fast).

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() {
    // Parsed before logging is initialised so a bad config fails fast.
    let config = docker_socket_proxy::config::Config::parse();
    init_logging(&config);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fatal: failed to create tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    rt.block_on(async {
        if config.health_check {
            if let Err(e) =
                docker_socket_proxy::observability::probe(config.bind, config.port).await
            {
                tracing::error!(port = config.port, reason = %e, "health check failed");
                std::process::exit(1);
            }
            return;
        }

        if let Err(e) = docker_socket_proxy::proxy::serve(config).await {
            tracing::error!(%e, "proxy server exited with error");
            std::process::exit(1);
        }
    });
}

fn init_logging(config: &docker_socket_proxy::config::Config) {
    // `log_level` already reflects `RUST_LOG` via clap's `env` binding (with the
    // CLI winning), so reading the environment again here would shadow an
    // explicit `--log-level`.
    let env_filter = EnvFilter::new(&config.log_level);

    match config.log_format {
        docker_socket_proxy::config::LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        docker_socket_proxy::config::LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }
}
