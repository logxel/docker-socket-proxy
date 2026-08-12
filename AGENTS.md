# AGENTS.md — Final Expected State

## docker-socket-proxy

A secure, minimal Docker socket proxy written in Rust. Exposes the Docker API over TCP while filtering dangerous endpoints. Published as a multi-arch static binary in a scratch container image.

Standards selection and cost analysis live in [`docs/standards.md`](docs/standards.md). Current progress lives in [`STATUS.md`](STATUS.md).

## Architecture

### Ports & Adapters

The service is a **Policy Enforcement Point** in front of a **Policy Decision Point**, using the NIST SP 800-162 vocabulary. The decision core is pure; all I/O lives in adapters.

```text
        ┌─────────────── inbound adapters ───────────────┐
        │  TCP listener (axum)                           │
        │  Docker AuthZ plugin endpoint   [feature]      │
        └────────────────────┬───────────────────────────┘
                             ▼
                   tower::Layer  ── PEP
                             ▼
                  SecurityFilter ── PDP  (pure, no I/O)
                             ▼
        ┌─────────────── outbound adapters ──────────────┐
        │  Unix socket transport → Docker daemon         │
        └────────────────────────────────────────────────┘
                             ▲
                   PolicyLoader ── PAP
                   (TOML file, environment, built-in profiles)
```

- **PDP** (`SecurityFilter`) is constructed only from an in-memory policy set. It never touches the filesystem or the environment.
- **PAP** (`PolicyLoader`) owns all policy I/O and merge semantics.
- **PEP** is a `tower::Layer`, not a call inside the handler — so it composes with `tower-http`'s limit, timeout, and trace layers.

### Runtime Behavior
- Listens on TCP port 2375 (configurable via `--port` / `DOCKER_PROXY_PORT`)
- Forwards allowed requests to the Docker Unix socket (`/var/run/docker.sock`, configurable)
- Every request passes the security filter before reaching the socket — no exceptions
- Streams request and response bodies rather than buffering, and supports HTTP connection upgrade (101) so exec and attach work
- Supports TOML files, environment variables, and built-in profiles for access control
- Terminates gracefully on **SIGTERM** and SIGINT

### Technology Stack
- **Runtime**: Tokio async runtime
- **HTTP Server**: Axum (hyper-based)
- **Middleware**: tower for the enforcement layer, tower-http for `timeout`
- **HTTP Client**: hyperlocal-next for Unix socket forwarding
- **Configuration**: Clap for CLI args + environment variables; TOML for policy files
- **Observability**: Tracing for structured JSON logging

No typed Docker client is used — the proxy forwards raw HTTP and never deserializes the Docker API beyond the policy checks it performs itself.

## Build & Delivery

### Binary
- Statically compiled with `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` targets
- Single binary, no runtime dependencies
- **Size budget: < 8 MB binary, < 10 MB image, < 130 crates in the default dependency tree**
- Anything exceeding the budget ships behind a Cargo feature or is not adopted

### Container Image
- Multi-arch: `linux/amd64` + `linux/arm64`
- Base image: `scratch` (static binary, no libc needed)
- Builder base pinned by digest; `cargo build --locked`
- Carries `org.opencontainers.image.*` labels in the Dockerfile itself
- Ships without a `USER` directive: the socket is typically `root:docker 0660`,
  so a fixed unprivileged UID would fail on most hosts. Operators supply their
  own UID and the host's docker GID at run time. The image holds no shell,
  package manager, or setuid binary, so UID 0 grants nothing beyond the mounted
  socket
- Published to: `ghcr.io/grupo-farinter-oss/docker-socket-proxy`
- Tags: `latest`, `v{version}`, `v{major}.{minor}`, `sha-{short_commit}`

### CI/CD (GitHub Actions)
- Triggered on: push to `main`, tags `v*`, pull requests
- All actions pinned by commit SHA
- Jobs: format check, clippy (strict), test, `cargo-deny`, OpenSSF Scorecard
- On tag push: multi-arch image build, push to GHCR, with
  - **SLSA v1.0 provenance** (`actions/attest-build-provenance`)
  - **SBOM** in SPDX/CycloneDX (`sbom: true`, `provenance: mode=max`)
  - **Sigstore/cosign** keyless signature via GitHub OIDC

## Security Model

### Trust boundary
The proxy reduces the blast radius of socket exposure; it does not eliminate it. Any client that can reach the listening port receives whatever the active profile permits. Deployments must either keep the port on a private network or enable the `tls` feature for mTLS.

> Mounting the socket with `:ro` provides no security benefit. The flag applies to the inode, not the protocol — the socket remains fully bidirectional.

### Default deny
All endpoints are denied unless explicitly allowed.

### Combining algorithm
Precedence is **`deny-overrides`** (XACML terminology), evaluated in a fixed order:

1. `exclude` — always wins, applied last in configuration but first in evaluation
2. `deny` — blocks on match
3. `allow` / `include` — permits on match
4. otherwise — denied

`exclude` and `deny` use identical match semantics (method AND endpoint).

### Allowed endpoints (`default` profile)
`/containers/json`, `/containers/{id}/json`, `/containers/{id}/logs`, `/images/json`, `/images/{id}/json`, `/info`, `/version`, `/networks`, `/volumes`, `/_ping` — on GET and HEAD only.

### Blocked endpoints (`default` profile)
Container creation, exec, lifecycle mutation, `/build`, `/commit`, and everything not listed above.

### Body inspection
For profiles that permit `/containers/create`, the request body is inspected and rejected if it sets `Privileged`, `CapAdd`, `SecurityOpt`, `Devices`, `PidMode`, `IpcMode`, or `UsernsMode`. Bind and volume mounts are permitted — orchestrators legitimately need them, and the profile is documented as trusted-caller-only.

### Profiles
| Profile | Intent |
|---|---|
| `default` | Read-only inspection on GET/HEAD |
| `read-only` | As above, with all mutating methods explicitly blocked |
| `container-runtime` | Full workload-orchestrator lifecycle for trusted callers (Dagster `DockerRunLauncher` and similar) |

### Audit
Every denial emits a structured `warn` event carrying the method, the request path as the client sent it, the active profile, and the reason — satisfying NIST SP 800-53 AU-2/AU-3. The path is logged unnormalized on purpose: forensics needs what was actually received, not what the matcher reduced it to.

### Control mapping
Each blocked endpoint is mapped to its NIST SP 800-190 and CIS Docker Benchmark control ID in the security documentation.

## Protocol Conformance

- **RFC 9110 / 9112** — hop-by-hop headers named in `Connection` are stripped in *both* directions
- **RFC 3986 §6** — paths are percent-decoded, dot-segments removed, and duplicate slashes collapsed before policy matching
- **Docker Engine API** — error bodies use Docker's `{"message": ...}` shape so `bollard` and the Docker CLI can parse them; **RFC 9457** `application/problem+json` is offered under content negotiation
- Docker API version prefixes (`/v1.55/...`) are normalized away before matching

## Observability

- Structured JSON logs via `tracing`, named per **OpenTelemetry semantic conventions**
- **W3C Trace Context** — an inbound `traceparent` is propagated upstream
- `/metrics` in **OpenMetrics/Prometheus** text format: allow and deny counters by endpoint and profile, plus request latency
- Health endpoint, reachable from a `--health-check` subcommand since the scratch image has no shell

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

Merge semantics follow **RFC 7386** (JSON Merge Patch) rather than ad-hoc precedence.

### Compatibility
A shim accepts the Tecnativa/linuxserver `docker-socket-proxy` environment variables (`CONTAINERS=1`, `IMAGES=1`, `POST=0`, …) and translates them into endpoint patterns, making this a drop-in replacement for the incumbent.

## Code Quality Standards

### Documentation & Comments

Concise, compact, precise, clear — and only when needed.

Code carries its own meaning. A reader follows it without consulting comments or
external documents; naming and structure do that work. If code needs a comment to
be followed at all, fix the code.

**Comment the "why", never the "what" or "how".** A comment that restates the
code beneath it is deleted. Write one when a decision is non-obvious and its
reason is not recoverable from the code:

- a specification requirement, with its citation
- a workaround for external behaviour
- a deliberate trade-off
- a constraint a future edit would otherwise silently violate

**No forensic notes.** Comments and docs describe the current state, not how it
got there. "Previously", "changed from", "used to", "legacy" belong in commit
messages, pull requests, and `CHANGELOG.md`.

**One home per fact.** `AGENTS.md` target state · `STATUS.md` current state ·
`CHANGELOG.md` what changed · `docs/standards.md` why a standard was chosen.
Cross-link rather than restate.

Doc comments on public items keep their DbC contract — that is an interface
specification, not narration. Omit contract sections that would state nothing.

### Design Principles
- **Hexagonal / Ports & Adapters**: the decision core is pure; all I/O is in adapters
- **Functional core, imperative shell**: policy evaluation is a total function of its inputs
- **Design by Contract (DbC)**: every public function documents pre-conditions, post-conditions, and invariants
- **Fail-Fast**: invalid state returns `Err` immediately at the interface boundary. No silent fallbacks
- **Railway Oriented Programming (ROP)**: functions return `Result<T, Error>`, never panic on recoverable errors
- **Result Pattern**: no `unwrap()` or `expect()` in production code (enforced by clippy)
- **DRY**: configuration parsing, error mapping, and middleware are centralized
- **Rust API Guidelines**: newtypes over `String` for methods and endpoint patterns

### Testing
- Unit tests for all modules (error types, security filter, config parsing)
- Integration tests against a mock Docker socket
- Security tests verifying blocked endpoints return 403
- Property-based tests over the path matcher — pattern matching is the primary bypass surface

### Linting
- `clippy::unwrap_used` — denied
- `clippy::expect_used` — denied
- `clippy::panic` — denied
- `unsafe_code` — forbidden

## Contract: Proxy Pipeline
```
Request → Normalize → PEP Layer → PDP Decision → Forward → Response
             |            |            |             |
          Fail → 400   Limit → 413   Deny → 403    Error → 502
                       Timeout → 504
```
- **Pre-condition**: Valid HTTP request received on configured port
- **Post-condition**: Either a valid Docker API response is returned, or an appropriate error status (400/403/413/502/504) with a Docker-shaped JSON error body
- **Invariant**: No request reaches the Docker socket without passing the security filter
- **Invariant**: Every denial produces an audit event
