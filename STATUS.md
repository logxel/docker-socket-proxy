# STATUS.md — Current State

Target state is defined in [`AGENTS.md`](AGENTS.md). Standards selection and cost
analysis are in [`docs/standards.md`](docs/standards.md).

## Project Phase: Implemented — hardening for conformance

The proxy is functional. Policy filtering, profiles, TOML and environment
configuration, and Unix-socket forwarding all work and are covered by tests.
The remaining work is standards conformance, not features.

## In Place

**Policy** — default-deny filter with `default`, `read-only`,
`container-runtime`, and `none` profiles; wildcard matcher; TOML or YAML
`allow`/`deny`/
`include`/`exclude`; environment modifiers; API-version normalization;
create-body inspection. `deny` and `exclude` hold independent rules, so
separate sources cannot merge into one narrower condition.

**Compatibility** — the section variables Tecnativa's socket proxy uses
(`CONTAINERS`, `POST`, `ALLOW_START`, …) configure the filter directly, checked
differentially against that proxy rather than against a reading of its config.

Paths are normalized per RFC 3986 §6 — percent-decoded, dot segments resolved,
empty segments collapsed — before matching, and encoded path separators are
refused.

**Architecture** — the three policy roles are separate: `security` decides
(pure, no I/O), `policy` loads from file and environment, `middleware` enforces
as a `tower::Layer`. `proxy` is the transport adapter and decides nothing.

**Transport** — Axum server forwarding to the Docker Unix socket, hop-by-hop
headers stripped in both directions (RFC 9110 §7.6.1), Docker-shaped error
bodies, graceful shutdown on SIGTERM and SIGINT. Bodies are relayed as they
arrive, so `/events`, `logs?follow=1`, and `/build` stream, and a 101 upgrade is
spliced through so `docker exec` works.

**Limits** — request bodies bounded by `--max-body-bytes` (413 when exceeded);
a declared over-limit `Content-Length` is refused before any bytes are read.
Optional `--timeout-secs` deadline, disabled by default.

**Audit** — every denial emits a structured `warn` with method, path, profile,
and reason (NIST SP 800-53 AU-2/AU-3).

**Observability** — `GET /metrics` in Prometheus text exposition and
`GET /healthz` in `application/health+json`, both answered locally and outside
the policy filter. `--health-check` probes a running proxy for the image's
`HEALTHCHECK`, which `scratch` has no shell to do.

**Delivery** — multi-stage musl → scratch image (1.92 MiB), multi-arch,
digest-pinned builder, OCI labels; CI runs fmt, clippy, tests, and `cargo-deny`
with SHA-pinned actions and `--locked`; releases carry an SBOM, max-mode
provenance, and a signed SLSA attestation; OpenSSF Scorecard runs weekly;
Dependabot covers cargo, actions, and docker.

**Tests** — 75 passing (64 unit, 4 integration against a mock socket, 5
asserting the shipped examples still behave as documented, 2 checking every
shipped endpoint pattern against the real Docker Engine API surface).

## Known Gaps
Ordered by the waves in [`docs/standards.md`](docs/standards.md#next-steps).
Identifiers are stable; closed gaps are not renumbered.

| # | Gap | Location |
|---|-----|----------|
| 12 | No authentication of any kind on the listening port (OWASP API2) | `src/proxy.rs` |
| 17 | Denied endpoints are not mapped to NIST SP 800-190 / CIS control IDs | `docs/` |

## In Progress
Nothing.

## Next Steps
**Wave 3** (capability): gaps 11, 15, and 16 are closed. Remaining are 17, then 12.
See [`docs/standards.md`](docs/standards.md#next-steps).

## Blockers
None.

## Size Budget
Binary measured on the host glibc target with the release profile. Rationale for
the metric is in [`docs/standards.md`](docs/standards.md#selection-criteria).

| Metric | Current | Budget |
|---|---:|---:|
| Release binary | 2.24 MiB | < 8 MB |
| Image | 1.92 MiB | < 10 MB |
| Dependency tree | 125 crates | < 130 |

`--no-default-features` drops the YAML parser: 1.79 MiB and 115 crates, so the
`yaml` feature costs 458 KiB and 10 crates.

## Decisions Log
| Date | Decision | Choice | Rationale |
|------|----------|--------|-----------|
| bootstrap | Project / crate / binary name | `docker-socket-proxy` | Descriptive, kebab-case Rust style |
| bootstrap | Container image | `ghcr.io/logxel/docker-socket-proxy` | GHCR with org namespace |
| bootstrap | License | MIT | Permissive, standard for the Rust ecosystem |
| bootstrap | Rust edition | 2024 | Latest stable edition |
| bootstrap | Async runtime | Tokio | De facto standard, required by axum |
| bootstrap | HTTP server | Axum | Ergonomic, tower-based, hyper underneath |
| bootstrap | Base image | scratch | Minimal attack surface; static musl binary |
| bootstrap | Lint strictness | deny unwrap/expect/panic | Enforces Result Pattern and Fail-Fast |
| 2026-08-12 | Typed Docker client | Drop `bollard` | Never referenced; the proxy forwards raw HTTP and must not deserialize the Docker API |
| 2026-08-12 | Size budget | < 8 MB, < 130 crates | Makes dependency decisions falsifiable rather than a matter of taste |
| 2026-08-12 | Policy engine | Keep the hand-rolled matcher | `cedar-policy` costs +59 crates to replace ~30 lines. Revisit if expressiveness becomes the bottleneck |
| 2026-08-12 | Telemetry export | Semantic conventions only, no OTLP | `opentelemetry-otlp` costs +77 crates; naming conventions are free and carry most of the value |
| 2026-08-12 | Body validation | Declarative field constraints, not JSON Schema | `jsonschema` costs +83 crates |
| 2026-08-12 | mTLS | Cargo feature `tls`, off by default | +11 crates; most deployments are on a private network, but the option must exist |
| 2026-08-12 | Combining algorithm | `deny-overrides` (XACML) | Names the existing intent and resolves the `exclude`/`deny` inconsistency |
| 2026-08-12 | Middleware | `tower-http` for timeout only | The body limit lives in the enforcement layer, which must buffer to inspect anyway |
| 2026-08-12 | Request timeout | Off by default | `/containers/{id}/wait` and follow-mode logs block for the life of the workload; a bound tight enough to stop an attacker would sever them |
| 2026-08-12 | Invalid allowlist file | Fatal | Falling back to profile defaults applied a policy the operator never wrote |
| 2026-08-12 | Encoded path separators | Reject | RFC 3986 §2.2 makes `%2F` distinct from `/`; either reading could disagree with the daemon's |
| 2026-08-12 | Container `USER` | None, documented | The socket is `root:docker 0660`, so a fixed UID fails on most hosts. Operators pass their own UID and docker GID |
| 2026-08-13 | YAML parser | `serde-saphyr` | The only serde-native YAML crate that is pure Rust, 1.0, and maintained; panic-free, which the `panic = "abort"` profile requires |
| 2026-08-13 | Section variables vs profiles | Replace, and refuse the combination | They describe a whole policy; merging them over a profile would grant more than the operator asked for |
| 2026-08-13 | Empty default profile | No — added `none` instead | Default-deny is already satisfied by a curated allow list. Shipping a proxy that permits nothing pushes every operator to write a policy from scratch, and copied-in over-broad rules are the likelier outcome than a considered narrow one. `none` serves those who want it |
| 2026-08-13 | Listen address | `--bind`, loopback default | The port has no authentication, so a network-reachable default hands over the daemon. The image overrides it, where exposure is already mediated by published ports |
| 2026-08-13 | YAML as a feature | Optional, on by default | Costs 458 KiB and 10 crates. Default-on so a documented format cannot vanish with a build flag |
