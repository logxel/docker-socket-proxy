# STATUS.md — Current State

Target state is defined in [`AGENTS.md`](AGENTS.md). Standards selection and cost
analysis are in [`docs/standards.md`](docs/standards.md).

## Project Phase: Implemented — hardening for conformance

The proxy is functional. Policy filtering, profiles, TOML and environment
configuration, and Unix-socket forwarding all work and are covered by tests.
The remaining work is standards conformance, not features.

## In Place

**Policy** — default-deny filter with `default`, `read-only`, and
`container-runtime` profiles; wildcard matcher; TOML `allow`/`deny`/
`include`/`exclude`; environment modifiers; API-version normalization;
create-body inspection.

**Transport** — Axum server forwarding to the Docker Unix socket, hop-by-hop
headers stripped in both directions (RFC 9110 §7.6.1), Docker-shaped error
bodies, graceful shutdown on SIGTERM and SIGINT.

**Audit** — every denial emits a structured `warn` with method, path, profile,
and reason (NIST SP 800-53 AU-2/AU-3).

**Delivery** — multi-stage musl → scratch image, multi-arch; CI runs fmt,
clippy, tests, and `cargo-deny` with SHA-pinned actions and `--locked`;
Dependabot covers cargo, actions, and docker.

**Tests** — 29 passing (25 unit, 4 integration against a mock socket).

## Known Gaps
Ordered by the waves in [`docs/standards.md`](docs/standards.md#next-steps).
Identifiers are stable; closed gaps are not renumbered.

| # | Gap | Location |
|---|-----|----------|
| 6 | Security filter is called inside the handler rather than being a `tower::Layer` | `src/proxy.rs` |
| 7 | `SecurityFilter` performs its own `std::fs` and `std::env` I/O, mixing domain and infrastructure. The `apply_environment(&HashMap)` test seam shows where the port belongs | `src/security.rs` |
| 8 | No body-size limit and no request timeout (OWASP API4) | `src/proxy.rs` |
| 9 | Combining semantics are inconsistent: `exclude` matches method OR endpoint, `deny` requires method AND endpoint | `src/security.rs` |
| 10 | `normalize_api_path` strips only the version prefix — no RFC 3986 percent-decoding, dot-segment removal, or slash collapsing | `src/security.rs` |
| 11 | Bodies are fully buffered and `upgrade`/`connection` are stripped from responses, so streaming (`/events`, `logs?follow=1`, `/build`) and 101-upgrade endpoints (`/exec/*/start`, `attach`) cannot work, though `container-runtime` permits them | `src/proxy.rs` |
| 12 | No authentication of any kind on the listening port (OWASP API2) | `src/proxy.rs` |
| 13 | No SBOM, SLSA provenance, or cosign signing on published images | `.github/workflows/ci.yml` |
| 14 | Dockerfile has no `USER`, no OCI `LABEL`s, and an unpinned `rust:alpine` base | `Dockerfile` |

## In Progress
Nothing.

## Next Steps
See [`docs/standards.md`](docs/standards.md#next-steps) for the full three-wave plan.

**Wave 2** (structure, then the layers it unlocks): gaps 6, 7, 8, 9, 10, 13, 14.
Start with 6 — the `tower::Layer` split makes the body-limit and timeout layers
in gap 8 nearly free.
**Wave 3** (capability): gaps 11, 12, plus metrics, health, and the Tecnativa
compatibility shim.

## Blockers
None.

## Size Budget
Measured on the host glibc target with the release profile. Rationale for the
metric is in [`docs/standards.md`](docs/standards.md#selection-criteria).

| Metric | Current | Budget |
|---|---:|---:|
| Release binary | 1.74 MiB | < 8 MB |
| Dependency tree | 118 crates | < 130 |

## Decisions Log
| Date | Decision | Choice | Rationale |
|------|----------|--------|-----------|
| bootstrap | Project / crate / binary name | `docker-socket-proxy` | Descriptive, kebab-case Rust style |
| bootstrap | Container image | `ghcr.io/grupo-farinter-oss/docker-socket-proxy` | GHCR with org namespace |
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
| 2026-08-12 | Middleware | Adopt `tower-http` | +2 crates for body limit, timeout, and trace layers |
