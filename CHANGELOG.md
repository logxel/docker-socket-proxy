# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Graceful shutdown on **SIGTERM** as well as SIGINT. SIGTERM is what
  `docker stop` and Kubernetes send, so shutdown draining previously never ran
  in production.
- **Audit logging for policy denials.** Every blocked request emits a structured
  `warn` event with method, path, active profile, and reason
  (NIST SP 800-53 AU-2/AU-3).
- `cargo-deny` policy (`deny.toml`) covering advisories, licences, banned and
  duplicate crates, and permitted source registries.
- Dependabot configuration for cargo, GitHub Actions, and Docker.
- `docs/standards.md` — industry standards catalogue with adoption decisions and
  measured dependency cost for each candidate.
- `SECURITY.md` with a disclosure process and an explicit scope statement.
- Documented trust boundary, known limitations, and the size budget.
- `--max-body-bytes` (default 16 MiB) bounding buffered request bodies, answered
  with `413` when exceeded, and `--timeout-secs` (default disabled) applying a
  request deadline answered with `504`.
- RFC 3986 §6 path normalization before policy matching: dot segments resolved,
  empty segments collapsed, percent-encoding decoded. Encoded path separators
  are rejected, since RFC 3986 §2.2 makes `%2F` distinct from `/`.
- **`GET /metrics`** in Prometheus text exposition, counting requests by policy
  outcome, and **`GET /healthz`** in `application/health+json` reporting whether
  the Docker socket accepts a connection. Both are answered locally, outside the
  policy filter, and are unauthenticated like the rest of the port.
- **`--health-check`**, which probes a running proxy over loopback and exits
  0 or 1, plus a container `HEALTHCHECK` that calls it. The `scratch` image has
  no shell or curl to health-check with otherwise.
- **101-upgrade passthrough**, so `docker exec` works through the proxy —
  stdin, stdout, and the exit status. `container-runtime` gained
  `GET /exec/*/json` and `POST /exec/*/resize`, without which the CLI cannot
  read the exit status of an exec it just ran.
- Release images now carry an SBOM, max-mode provenance, and a signed SLSA
  build-provenance attestation; OpenSSF Scorecard runs weekly.
- OCI image labels and a digest-pinned builder base.

### Changed
- **Request and response bodies now stream.** `/events`,
  `/containers/{id}/logs?follow=1`, and `/build` output are relayed frame by
  frame instead of being collected first — endpoints that never end previously
  returned nothing at all. Only bodies a policy rule actually inspects are
  buffered.
- **Policy is now evaluated before the request body is read.** A blocked
  endpoint answers `403` without consuming the upload; it previously buffered
  the body first and could answer `413` for a request it was going to refuse
  anyway.
- A `Content-Length` above `--max-body-bytes` is refused before any bytes are
  read, rather than after the limit trips mid-transfer.
- **Policy is split into decision, administration, and enforcement.**
  `security` decides and is now pure, `policy` owns all policy I/O, and
  `middleware` enforces as a `tower::Layer` instead of a call inside the
  handler.
- **An unreadable or unparseable `--allowlist` file is now fatal.** It was
  warned about and skipped, which silently applied profile defaults the operator
  had not written. **Breaking** for deployments relying on that fallback.
- **`exclude` and `deny` now match consistently.** `exclude` matched on method
  OR endpoint while `deny` required method AND endpoint. Both now treat an empty
  side as a wildcard, and a rule with both sides empty is inert.
- **Error responses now follow the Docker Engine API contract** (`{"message": …}`
  instead of `{"error": …, "status": …}`), so `bollard` and the Docker CLI can
  deserialize proxy-generated errors. **Breaking** for any client parsing the
  previous shape.
- Hop-by-hop headers are now stripped in **both** directions per RFC 9110 §7.6.1,
  including any header named in a `Connection` field. Previously only `Host` was
  removed from forwarded requests, leaking connection-specific headers upstream.
- CI: all actions pinned by commit SHA, `--locked` on cargo invocations,
  least-privilege workflow permissions, `cargo-deny` in place of the bare
  advisory scan.

### Removed
- `bollard` and `tower` dependencies — both were declared but never referenced.
  Drops the dependency tree from 164 to 118 crates with no change in
  functionality and none in binary size.

### Known Issues
- `/containers/{id}/attach` is blocked in every profile; `docker exec` is the
  supported path. See [Known Limitations](README.md#known-limitations).

## [0.1.1] — 2026-08-12

### Added
- Environment policy modifiers: `DOCKER_PROXY_ALLOW_ENDPOINTS`,
  `DOCKER_PROXY_INCLUDE_ENDPOINTS`, `DOCKER_PROXY_DENY_ENDPOINTS`,
  `DOCKER_PROXY_EXCLUDE_ENDPOINTS` and their `*_METHODS` counterparts.

## [0.1.0] — 2026-08-12

### Added
- Default-deny security filter with wildcard endpoint matching.
- Built-in profiles: `default`, `read-only`, `container-runtime`.
- Composable TOML policy with `allow`/`deny`/`include`/`exclude` sections.
- Docker API version prefix normalization (`/v1.55/...`).
- Create-body inspection blocking `Privileged`, `CapAdd`, `SecurityOpt`,
  `Devices`, `PidMode`, `IpcMode`, and `UsernsMode`.
- Multi-arch (`linux/amd64`, `linux/arm64`) static musl build on `scratch`.
- CI/CD: format, clippy, tests, security audit, GHCR publish.

### Fixed
- arm64 release image build.

[Unreleased]: https://github.com/grupo-farinter-oss/docker-socket-proxy/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/grupo-farinter-oss/docker-socket-proxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/grupo-farinter-oss/docker-socket-proxy/releases/tag/v0.1.0
