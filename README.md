# docker-socket-proxy

[![CI/CD](https://github.com/logxel/docker-socket-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/logxel/docker-socket-proxy/actions/workflows/ci.yml)

A secure, minimal Docker socket proxy written in Rust. Exposes the Docker API over TCP while filtering dangerous endpoints.

## Quick Start

### From GHCR

```bash
docker run -d \
  --name docker-socket-proxy \
  -p 2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/logxel/docker-socket-proxy:latest
```

### From Source

```bash
cargo build --release
./target/release/docker-socket-proxy --port 2375
```

### Configuration

```
docker-socket-proxy [OPTIONS]

Options:
  --port <PORT>          TCP port to listen on [env: DOCKER_PROXY_PORT] [default: 2375]
  --socket <PATH>        Docker Unix socket path [env: DOCKER_SOCKET] [default: /var/run/docker.sock]
  --allowlist <FILE>     Path to TOML allowlist configuration file
  --log-level <LEVEL>    Log level [env: RUST_LOG] [default: info]
  --log-format <FORMAT>  Log format: json, pretty [default: json]
```

### Profiles

Built-in profiles are `default`, `read-only`, and `container-runtime`. `read-only` is a standard descriptive name for Docker API consumers that need inspection only. `container-runtime` is the generic profile for trusted workload orchestrators such as Dagster's official `DockerRunLauncher`.

### Example Allowlist

```toml
[allow]
endpoints = ["/containers/json", "/info", "/version"]
methods = ["GET", "HEAD"]

[deny]
endpoints = ["/containers/create", "/exec"]
methods = ["POST"]
```

Rules are merged with the selected profile. `allow` and `deny` are additive aliases matching common Docker socket proxy terminology. Prefer `include` and `exclude` for explicit modifiers; `exclude` always wins and is applied last.

```toml
[include]
endpoints = ["/images/*/json"]
methods = ["GET"]

[exclude]
endpoints = ["/containers/*/logs"]
```

The same modifiers are available as comma-separated environment variables:

```bash
DOCKER_PROXY_PROFILE=container-runtime \
DOCKER_PROXY_INCLUDE_ENDPOINTS=/images/search \
DOCKER_PROXY_EXCLUDE_ENDPOINTS=/build,/commit \
DOCKER_PROXY_ALLOW_METHODS=GET,POST \
docker-socket-proxy
```

Supported variables are `DOCKER_PROXY_ALLOW_ENDPOINTS`, `DOCKER_PROXY_INCLUDE_ENDPOINTS`, `DOCKER_PROXY_DENY_ENDPOINTS`, `DOCKER_PROXY_EXCLUDE_ENDPOINTS`, and corresponding `*_METHODS` variables. Environment rules are merged after TOML rules; exclusions remain decisive.

## Security Model

**Default deny** — all endpoints are blocked unless explicitly allowed.

Allowed by default: read-only endpoints (`/containers/json`, `/images/json`, `/info`, `/version`, etc.)

Blocked by default: mutation endpoints (`/containers/create`, `/exec`, `/build`, `/commit`), privileged flags, capability additions, device mounts.

### Dagster Docker Profile

Use the opt-in `container-runtime` profile for the complete Docker-backed Dagster workspace. It supports DockerRunLauncher lifecycle calls, KNIME custom containers, image builds and loads, bind/volume mounts, network connections, wait/log/archive operations, and exec sessions. Privileged mode, capability changes, host devices, and namespace overrides remain blocked. Expose this profile only to trusted orchestrator services.

```bash
DOCKER_PROXY_PROFILE=container-runtime docker-socket-proxy
```

## License

MIT — See [LICENSE](LICENSE)
