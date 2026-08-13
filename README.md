# docker-socket-proxy

[![CI/CD](https://github.com/logxel/docker-socket-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/logxel/docker-socket-proxy/actions/workflows/ci.yml)
[![Scorecard](https://github.com/logxel/docker-socket-proxy/actions/workflows/scorecard.yml/badge.svg)](https://github.com/logxel/docker-socket-proxy/actions/workflows/scorecard.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/logxel/docker-socket-proxy/badge)](https://scorecard.dev/viewer/?uri=github.com/logxel/docker-socket-proxy)

A secure, minimal Docker socket proxy written in Rust. Exposes the Docker API over TCP while filtering dangerous endpoints.

## Quick Start

### From GHCR

```bash
docker run -d \
  --name docker-socket-proxy \
  -p 127.0.0.1:2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/logxel/docker-socket-proxy:latest
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
  --bind <ADDR>              Address to listen on [env: DOCKER_PROXY_BIND] [default: 127.0.0.1]
  --socket <PATH>            Docker Unix socket path [env: DOCKER_SOCKET] [default: /var/run/docker.sock]
  --allowlist <FILE>         Path to TOML or YAML allowlist file (.toml, .yaml, .yml)
  --profile <PROFILE>        Built-in profile: default, read-only, container-runtime, none
  --max-body-bytes <BYTES>   Maximum request body size [default: 16777216]
  --timeout-secs <SECS>      Request timeout; 0 disables [default: 0]
  --health-check             Probe a running proxy on --port and exit 0 if healthy
  --log-level <LEVEL>        Log level [env: RUST_LOG] [default: info]
  --log-format <FORMAT>      Log format: json, pretty [default: json]
```

A request body over `--max-body-bytes` is answered with `413`. Raise it where
`/build` is permitted and used — image build contexts are the large case.

`--timeout-secs` is off by default because `/containers/{id}/wait` and
follow-mode logs legitimately block for as long as the workload runs. Set it
where the permitted endpoints are all short-lived.

An `--allowlist` file that cannot be read or parsed is fatal. The proxy will not
start on profile defaults you did not ask for. The parser is chosen by
extension — `.toml`, `.yaml`, or `.yml` — and any other extension is refused
rather than guessed at.

`--bind` defaults to loopback. The port has no authentication, so reaching it is
the whole authorization story, and a default reachable from the network would
hand the daemon to anyone who found it. The published image sets
`DOCKER_PROXY_BIND=0.0.0.0`, because there the container boundary and your
published ports control exposure instead. Binding `::` requires IPv6 enabled on
the host.

### Profiles

| Profile | Grants |
|---|---|
| `default` | Read-only endpoints on GET and HEAD; mutation blocked |
| `read-only` | The same reads, with every write method denied on every endpoint |
| `container-runtime` | Launching and managing containers, with create bodies inspected |
| `none` | Nothing — your allowlist is the whole policy |

`read-only` is a standard descriptive name for Docker API consumers that need inspection only. `container-runtime` is the generic profile for trusted workload orchestrators such as Dagster's official `DockerRunLauncher`.

`none` exists because every other profile *merges* its grants with your file, so a file alone cannot express "this and nothing more". Start from `none` when the policy must be exactly what you wrote.

### Build Features

`yaml` is on by default and can be dropped for a smaller build:

```bash
cargo build --release --no-default-features   # TOML allowlists only
```

A YAML allowlist given to a build without it is refused by name, not silently ignored.

Both variants are published on every release. **The default image is the minimal one** — YAML is opt-in by tag, since it costs 458 KiB and 10 crates that most deployments never use:

| Tag | Allowlist formats | Image |
|---|---|---|
| `:0.3.0`, `:0.3`, `:0`, `:latest` | TOML | 1.88 MiB |
| `:0.3.0-minimal`, `:0.3-minimal`, `:0-minimal`, `:latest-minimal` | TOML | 1.88 MiB |
| `:0.3.0-yaml`, `:0.3-yaml`, `:0-yaml`, `:latest-yaml` | TOML, YAML | 2.33 MiB |

The first two rows are the same image; the `-minimal` tags exist so a deployment can pin the feature set rather than inherit whichever one is default.

**A `.yaml` allowlist needs a `-yaml` tag.** On the default image it is refused by name at startup and the proxy will not run.

Pulled by digest, `docker inspect` reports which you have under the `io.logxel.features` label.

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

Worked examples, each covered by [`tests/examples.rs`](tests/examples.rs):

| File | Format | Shows |
|---|---|---|
| [`container-runtime.toml`](examples/container-runtime.toml) | TOML | A complete workload-launcher policy |
| [`create-inspection.toml`](examples/create-inspection.toml) | TOML | Which create bodies are refused, and why endpoint rules cannot say it |
| [`tecnativa-equivalent.toml`](examples/tecnativa-equivalent.toml) | TOML | The section variables written out, under `--profile none` |
| [`sections-read-only.yaml`](examples/sections-read-only.yaml) | YAML | Section-style grants, with prefix rules narrowed by `exclude` — needs a `-yaml` image |
| [`env-modifiers.env`](examples/env-modifiers.env) | env | Policy set entirely through the environment |
| [`compose/tecnativa-compat.yml`](examples/compose/tecnativa-compat.yml) | compose | Drop-in replacement using the section variables |
| [`compose/container-runtime.yml`](examples/compose/container-runtime.yml) | compose | Deployment with an allowlist, health check, and loopback-only port |

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

Supported variables are `DOCKER_PROXY_ALLOW_ENDPOINTS`, `DOCKER_PROXY_INCLUDE_ENDPOINTS`, `DOCKER_PROXY_DENY_ENDPOINTS`, `DOCKER_PROXY_EXCLUDE_ENDPOINTS`, and corresponding `*_METHODS` variables. Environment rules are merged after file rules; exclusions remain decisive.

### Typos

Rules are checked against the Docker Engine API surface at startup, and anything matching no real endpoint is logged:

```
WARN policy endpoint matches no known Docker API path; it will never take effect
     source="exclude" endpoint="/containres/*/logs" api_version="1.55"
WARN policy method matches no request
     source="include" method="get" hint="HTTP methods are case-sensitive, so this matches no request"
```

This matters most in `deny` and `exclude`: a mistyped path there is stored, never fires, and leaves a resource reachable that you believe you blocked.

Warnings, not errors — the endpoint list is a snapshot, and a newer daemon may serve paths this build predates. Grep startup logs for `WARN` after a policy change.

### Drop-in Compatibility

A compose file written for [Tecnativa's socket proxy](https://github.com/Tecnativa/docker-socket-proxy) runs here unchanged:

```yaml
services:
  proxy:
    image: ghcr.io/logxel/docker-socket-proxy:0.3.0
    environment:
      CONTAINERS: 1
      IMAGES: 1
      POST: 1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

Section variables (`AUTH`, `BUILD`, `COMMIT`, `CONFIGS`, `CONTAINERS`, `DISTRIBUTION`, `EVENTS`, `EXEC`, `GRPC`, `IMAGES`, `INFO`, `NETWORKS`, `NODES`, `PING`, `PLUGINS`, `SECRETS`, `SERVICES`, `SESSION`, `SWARM`, `SYSTEM`, `TASKS`, `VERSION`, `VOLUMES`) grant one API section each. `EVENTS`, `PING`, and `VERSION` are granted unless set to `0`. `ALLOW_RESTARTS`, `ALLOW_START`, `ALLOW_STOP`, `ALLOW_PAUSE`, and `ALLOW_UNPAUSE` grant single container operations without opening `/containers`. `POST` gates every write; `GET` and `HEAD` pass regardless.

Only `1`, `true`, `yes`, and `on` enable a variable, so a typo fails closed.

These variables describe a complete policy, so they **replace** the profile defaults rather than merge with them — `CONTAINERS=1` grants containers and nothing else. Setting them alongside `--profile` is refused rather than silently resolved. `DOCKER_PROXY_*` modifiers and an `--allowlist` file still apply on top.

Verdicts are checked against the reference implementation directly; see `compatibility_filter` in [`src/policy.rs`](src/policy.rs).

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

Use the opt-in `container-runtime` profile for Docker-backed orchestrators. It supports `DockerRunLauncher` lifecycle calls, custom containers, image builds and loads, bind/volume mounts, network connections, `docker exec`, and wait/log/archive operations. Privileged mode, capability changes, host devices, and namespace overrides remain blocked.

```bash
DOCKER_PROXY_PROFILE=container-runtime docker-socket-proxy
```

For profiles that permit `/containers/create`, the request body is inspected and rejected if it sets `Privileged`, `CapAdd`, `SecurityOpt`, `Devices`, `PidMode`, `IpcMode`, or `UsernsMode`. Bind and volume mounts are permitted — orchestrators need them, and this profile is trusted-caller-only by design.

## Known Limitations

Tracked in [`STATUS.md`](STATUS.md) with a remediation plan in [`docs/standards.md`](docs/standards.md).

- **`/containers/{id}/attach` is blocked in every profile.** `docker exec` is the supported path and works; attach has no policy allowing it.
- **No authentication.** See [Trust Boundary](#trust-boundary).
- **No Tecnativa/linuxserver environment-variable compatibility.** Policy is configured through this project's own TOML and `DOCKER_PROXY_*` variables.

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

## Observability

Two endpoints are answered by the proxy itself and never forwarded to Docker.
Neither path exists in the Docker Engine API, so nothing is shadowed.

| Endpoint | Purpose |
|---|---|
| `GET /metrics` | Prometheus text exposition: `docker_socket_proxy_requests_total{outcome="allowed"\|"denied"}` |
| `GET /healthz` | `application/health+json`; `200` when the Docker socket accepts a connection, `503` otherwise |

**Both bypass the security policy and are unauthenticated**, like every other
endpoint on this port — see [Trust Boundary](#trust-boundary). They expose
aggregate counts and socket reachability, nothing about individual requests.

The image ships a `HEALTHCHECK`. Because `scratch` has no shell to call
`/healthz` with, the binary probes itself:

```bash
docker-socket-proxy --health-check    # exits 0 when healthy, 1 otherwise
```

## Standards

Conformance targets, adoption decisions, and their measured dependency cost are documented in [`docs/standards.md`](docs/standards.md). The target state is described in [`AGENTS.md`](AGENTS.md).

## Scorecard

[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/logxel/docker-socket-proxy)
grades repository practices rather than code. It runs weekly and on `main`
pushes via [`.github/workflows/scorecard.yml`](.github/workflows/scorecard.yml).

Code-fixable checks, in place:

- **SAST** — CodeQL for Rust runs from
  [`.github/workflows/codeql.yml`](.github/workflows/codeql.yml) (`language: rust`).
- **Fuzzing** — a cargo-fuzz / libfuzzer-sys harness in [`fuzz/`](fuzz/) targets the
  request-path decision surface and policy parsing (`path_normalizer`,
  `policy_parse`), exercised by a scheduled job in
  [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml).

The remaining checks need repository or account settings, not code:

- **Code-Review** — a PR review policy that gates merges on approved reviews.
- **Branch-Protection** — branch-protection rules enabled on `main`.
- **Maintained** — time-gated; the repository ages into this one.
- **Contributors** — contributors from more than one organization.
- **Signed-Releases** — a published release; signing is already wired into the
  release workflow.
- **CII-Best-Practices** — self-certification at
  [bestpractices.dev](https://www.bestpractices.dev).

The numeric score refreshes only when the scorecard action re-runs — weekly, or
on a `main` push.

## Contributing

Security issues: see [`SECURITY.md`](SECURITY.md). Release history: [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT — See [LICENSE](LICENSE)
