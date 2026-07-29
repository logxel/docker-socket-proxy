# AGENTS.md — Final Expected State

## docker-socket-proxy

A secure, minimal Docker socket proxy written in Rust. Exposes the Docker API over TCP while filtering dangerous endpoints. Published as a multi-arch static binary in a scratch container image.

## Architecture

### Runtime Behavior
- Listens on TCP port 2375 (configurable via `--port` / `DOCKER_PROXY_PORT`)
- Forwards whitelisted requests to the Docker Unix socket (`/var/run/docker.sock`, configurable)
- Filters requests through a security middleware that blocks dangerous endpoints
- Supports an allowlist/denylist configuration file for fine-grained access control

### Technology Stack
- **Runtime**: Tokio async runtime
- **HTTP Server**: Axum (hyper-based)
- **HTTP Client**: hyperlocal-next for Unix socket forwarding
- **Docker Client**: Bollard for typed Docker API interactions
- **Configuration**: Clap for CLI args + environment variables
- **Observability**: Tracing for structured JSON logging

## Build & Delivery

### Binary
- Statically compiled with `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` targets
- Single binary, no runtime dependencies
- Size target: <8MB

### Container Image
- Multi-arch: `linux/amd64` + `linux/arm64`
- Base image: `scratch` (static binary, no libc needed)
- Image size target: <10MB
- Published to: `ghcr.io/logxel/docker-socket-proxy`
- Tags: `latest`, `v{version}`, `v{major}.{minor}`, `sha-{short_commit}`

### CI/CD (GitHub Actions)
- Triggered on: push to `main`, tags `v*`, pull requests
- Builds for both architectures
- Jobs: lint (clippy strict), format check (rustfmt), test, security audit
- On tag push: builds multi-arch Docker image, pushes to GHCR

## Security Model

### Default Deny
All endpoints are denied by default. Only explicitly allowed endpoints pass through.

### Blocked Endpoints (default)
- `/containers/create` — container creation
- `/containers/{id}/exec` — command execution
- `/exec/{id}/start` — exec start
- `/build` — image builds via Dockerfile
- `/commit` — container commits
- Any request body containing `"Privileged": true`, `CapAdd`, `SecurityOpt`, `Devices`, `Mounts`

### Allowed Endpoints (default)
- `/containers/json` — list containers
- `/containers/{id}/json` — inspect container
- `/containers/{id}/logs` — container logs (read-only)
- `/images/json` — list images
- `/info` — Docker system info
- `/version` — Docker version
- `/networks` — network inspection
- `/volumes` — volume inspection

## Code Quality Standards

### Design Principles
- **Design by Contract (DbC)**: Every public function documents pre-conditions, post-conditions, and invariants in doc comments
- **Fail-Fast**: Invalid state or unmet pre-conditions return `Err` immediately at the interface boundary. No silent fallbacks.
- **Railway Oriented Programming (ROP)**: Functions return `Result<T, Error>`, never panic on recoverable errors. Error path is explicit and separated from the happy path.
- **Result Pattern**: No `unwrap()` or `expect()` in production code (enforced by clippy lints). All fallible operations return `Result`.
- **DRY**: Common patterns are extracted into shared utilities. Configuration parsing, error mapping, and middleware are centralized.

### Testing
- Unit tests for all modules (error types, security filter, config parsing)
- Integration tests against a real Docker daemon socket
- Security tests verifying blocked endpoints return 403

### Linting
- `clippy::unwrap_used` — denied
- `clippy::expect_used` — denied
- `clippy::panic` — denied
- `unsafe_code` — forbidden

## Configuration

### CLI (clap)
```
docker-socket-proxy [OPTIONS]

Options:
  --port <PORT>              TCP port to listen on [env: DOCKER_PROXY_PORT] [default: 2375]
  --socket <PATH>            Docker Unix socket path [env: DOCKER_SOCKET] [default: /var/run/docker.sock]
  --allowlist <FILE>         Path to TOML allowlist configuration file
  --profile <PROFILE>        Built-in profile: default, read-only, container-runtime
  --log-level <LEVEL>        Log level [env: RUST_LOG] [default: info]
  --log-format <FORMAT>      Log format: json, pretty [default: json]
```

### Allowlist File (TOML)
```toml
[allow]
endpoints = ["/containers/json", "/info", "/version"]
methods = ["GET", "HEAD"]

[deny]
endpoints = ["/containers/create", "/exec"]
methods = ["POST"]
```

## Contract: Proxy Pipeline
```
Request → Parse → Security Filter → Forward → Response
          |            |                |
          Fail → 400   Deny → 403       Error → 502
```
- **Pre-condition**: Valid HTTP request received on configured port
- **Post-condition**: Either a valid Docker API response is returned, or an appropriate error status (400/403/502) with a JSON error body
- **Invariant**: No request reaches the Docker socket without passing the security filter
