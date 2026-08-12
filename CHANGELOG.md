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

### Changed
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
- Streaming and 101-upgrade endpoints remain unsupported; see
  [Known Limitations](README.md#known-limitations).

See [Known Limitations](README.md#known-limitations). Streaming and exec
passthrough, SIGTERM handling, denial auditing, and Docker-shaped error bodies
are all outstanding.

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
