# docker-socket-proxy

[![CI/CD](https://github.com/grupo-farinter-oss/docker-socket-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/grupo-farinter-oss/docker-socket-proxy/actions/workflows/ci.yml)

A secure, minimal Docker socket proxy written in Rust. Exposes the Docker API over TCP while filtering dangerous endpoints.

## Quick Start

### From GHCR

```bash
docker run -d \
  --name docker-socket-proxy \
  -p 127.0.0.1:2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/grupo-farinter-oss/docker-socket-proxy:latest
```

> **Bind to a private interface.** The proxy has no authentication — any client
> that reaches the port gets whatever the active profile permits. See
> [Trust Boundary](#trust-boundary).

### From Source

```bash
cargo build --release --locked
./target/release/docker-socket-proxy --port 2375
```

### Configuration

```
docker-socket-proxy [OPTIONS]

Options:
  --port <PORT>              TCP port to listen on [env: DOCKER_PROXY_PORT] [default: 2375]
  --socket <PATH>            Docker Unix socket path [env: DOCKER_SOCKET] [default: /var/run/docker.sock]
  --allowlist <FILE>         Path to TOML allowlist configuration file
  --profile <PROFILE>        Built-in profile: default, read-only, container-runtime
  --max-body-bytes <BYTES>   Maximum request body size [default: 16777216]
  --timeout-secs <SECS>      Request timeout; 0 disables [default: 0]
  --log-level <LEVEL>        Log level [env: RUST_LOG] [default: info]
  --log-format <FORMAT>      Log format: json, pretty [default: json]
```

A request body over `--max-body-bytes` is answered with `413`. Raise it where
`/build` is permitted and used — image build contexts are the large case.

`--timeout-secs` is off by default because `/containers/{id}/wait` and
follow-mode logs legitimately block for as long as the workload runs. Set it
where the permitted endpoints are all short-lived.

An `--allowlist` file that cannot be read or parsed is fatal. The proxy will not
start on profile defaults you did not ask for.

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

Complete profile example: [`examples/container-runtime.toml`](examples/container-runtime.toml).

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

Allowed by default: read-only endpoints (`/containers/json`, `/images/json`, `/info`, `/version`, etc.) on GET and HEAD.

Blocked by default: mutation endpoints (`/containers/create`, `/exec`, `/build`, `/commit`), and everything not explicitly listed.

### Trust Boundary

This proxy **reduces** the blast radius of socket exposure. It does not eliminate it.

- **There is no authentication.** Anyone who can reach the listening port receives everything the active profile permits. Keep the port on a private network or a container-internal bridge.
- **Mounting the socket `:ro` does nothing for security.** The read-only flag applies to the inode, not the protocol — the socket stays fully bidirectional. This is a widespread misconception; do not rely on it.
- **`container-runtime` grants real power.** It permits container creation, image builds, and bind mounts. A caller with this profile can, with effort, reach the host. Expose it only to services you already trust.
- **The image has no `USER`.** A fixed unprivileged UID cannot open a `root:docker 0660` socket, so it would fail on most hosts. To run non-root, supply the host's docker GID yourself:

  ```bash
  docker run --user 65534:$(getent group docker | cut -d: -f3) ...
  ```

  The image carries no shell, package manager, or setuid binary, so UID 0 inside it grants nothing beyond the socket you mounted.

### Container Runtime Profile

Use the opt-in `container-runtime` profile for Docker-backed orchestrators. It supports `DockerRunLauncher` lifecycle calls, custom containers, image builds and loads, bind/volume mounts, network connections, and wait/log/archive operations. Privileged mode, capability changes, host devices, and namespace overrides remain blocked.

```bash
DOCKER_PROXY_PROFILE=container-runtime docker-socket-proxy
```

For profiles that permit `/containers/create`, the request body is inspected and rejected if it sets `Privileged`, `CapAdd`, `SecurityOpt`, `Devices`, `PidMode`, `IpcMode`, or `UsernsMode`. Bind and volume mounts are permitted — orchestrators need them, and this profile is trusted-caller-only by design.

## Known Limitations

Tracked in [`STATUS.md`](STATUS.md) with a remediation plan in [`docs/standards.md`](docs/standards.md).

- **Streaming and exec do not work yet.** Request and response bodies are fully buffered, and HTTP connection upgrade (101) is not passed through. This affects `/events`, `/containers/{id}/logs?follow=1`, `/build` output streaming, and `/exec/{id}/start`. The `container-runtime` profile *permits* these endpoints at the policy layer, but the transport cannot currently carry them.
- **No authentication.** See [Trust Boundary](#trust-boundary).
- **No `/metrics` or health endpoint.**

## Auditing

Every denied request emits a structured `warn` event with the method, the path as received, the active profile, and the reason:

```json
{"level":"WARN","fields":{"message":"request denied by security policy",
 "method":"POST","path":"/containers/create","profile":"Default",
 "reason":"access denied: blocked endpoint: POST /containers/create"}}
```

Error responses follow the Docker Engine API contract, so Docker clients deserialize them with the same type they use for daemon errors:

```json
{"message": "blocked endpoint: POST /containers/create"}
```

## Standards

Conformance targets, adoption decisions, and their measured dependency cost are documented in [`docs/standards.md`](docs/standards.md). The target state is described in [`AGENTS.md`](AGENTS.md).

## Contributing

Security issues: see [`SECURITY.md`](SECURITY.md). Release history: [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT — See [LICENSE](LICENSE)
