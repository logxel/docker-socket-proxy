# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **`container-runtime` now allows graceful container stop and restart.** The
  profile claimed to support `DockerRunLauncher` lifecycle calls, but
  `POST /containers/{id}/stop` was still denied, so `DockerRunLauncher.terminate()`
  could not cancel runs. Stop and restart (stop+start) are now granted; kill,
  pause, unpause, rename, update, resize, attach, and commit remain denied.

## [0.3.1] — 2026-08-13

Security and correctness fixes from a full code review, plus a repaired
keyless release-signing step.

### Fixed
- **Container-create body inspection now checks the nested `HostConfig`.** The
  Docker daemon reads `Privileged`, `CapAdd`, `SecurityOpt`, `Devices`,
  `PidMode`, `IpcMode`, and `UsernsMode` from `HostConfig`, but the guard only
  inspected the top level, so `{"HostConfig":{"Privileged":true}}` slipped
  through and started a privileged container. Both levels are now inspected,
  `DeviceRequests` and `NetworkMode: host` are refused too, and explicit
  `false`/empty/`null` no longer over-block.
- **The `container-runtime` profile no longer cross-products methods ×
  endpoints.** Its read and write grants merged into one set, silently allowing
  every write method on every readable endpoint — including
  `DELETE /volumes/{id}` and `DELETE /networks/{id}`. Allow rules are now
  independent, so each grant stays method-AND-endpoint.
- **Create-body inspection follows the effective policy, not the profile enum.**
  `--profile none` plus an allowlist granting `POST /containers/create`, and the
  `CONTAINERS=1 POST=1` compatibility shim, now inspect create bodies instead of
  forwarding them unexamined.
- **Malformed request paths return 400**, not 403, matching the documented
  pipeline contract.
- **Chunked over-limit bodies return 413**, not 502, when the streamed size
  limit fires mid-forward.
- **`--log-level` is no longer shadowed by an ambient `RUST_LOG`.**
- **Upgraded (101) connections are drained on graceful shutdown**, so `docker
  exec` sessions get a bounded window to finish instead of being severed.

### Changed
- **Merge semantics documented as a monotonic union-append under
  `deny-overrides`**, not RFC 7386 JSON Merge Patch (which was documented but
  never implemented).
- **Release signing** writes a `.sigstore.json` Sigstore bundle via `cosign
  sign-blob --bundle`, replacing the deprecated `--output-signature`/
  `--output-certificate` flags that made the step fail.

## [0.3.0] — 2026-08-12

YAML allowlists, drop-in compatibility with the section variables other socket
proxies use, and a listen address that is no longer reachable from the network
by default. Four breaking changes are marked below.

### Added
- **YAML allowlists.** `--allowlist` accepts `.yaml` and `.yml` alongside
  `.toml`, with the parser chosen by extension. An unrecognised extension is
  refused rather than guessed at, so a mistyped name cannot quietly parse as the
  wrong format and yield a policy nobody wrote.
- **Compatibility with the section variables** other Docker socket proxies use:
  `CONTAINERS`, `IMAGES`, `POST`, `ALLOW_START`, and the rest configure the
  filter directly, so an existing compose file runs unchanged. They describe a
  whole policy, so they replace the profile defaults instead of layering over
  them; setting them alongside `--profile` is refused rather than silently
  resolved. Verdicts are checked differentially against the reference
  implementation.
- **`--bind`** (`DOCKER_PROXY_BIND`), defaulting to loopback. The port has no
  authentication, so a network-reachable default handed the daemon to anyone who
  found it. The image sets `0.0.0.0`, where published ports control exposure.
  Any IPv4 or IPv6 literal is accepted. **Breaking** for anyone running the
  binary directly and connecting from another host; set `--bind 0.0.0.0`.
- **`none` profile**, which grants nothing. Every other profile merges its
  grants with your file, so a file alone could not express "this and nothing
  more". Starting from `none` makes the allowlist the complete policy.
- **`yaml` build feature**, on by default. `--no-default-features` drops the
  parser for a build 458 KiB and 10 crates smaller; a YAML allowlist given to
  such a build is refused by name rather than silently ignored.
- **Two image variants**, built in parallel from one Dockerfile. Bare tags and
  `:latest` point at the minimal build (1.88 MiB), which is also reachable as
  `-minimal` so a deployment can pin the feature set rather than inherit
  whichever one is default. YAML is opt-in through `-yaml` (2.33 MiB). Both
  carry an `io.logxel.features` label, since a tag suffix is invisible once an
  image is pulled by digest. **Breaking** for anyone using a `.yaml` allowlist
  with `:latest` or a bare version tag: move to `-yaml`, or the proxy refuses
  the file by name and will not start.
- Worked examples for create-body inspection, section-style YAML grants,
  environment-only configuration, and two compose deployments — each asserted by
  `tests/examples.rs`, so a shipped example cannot drift from what it documents.
- `tests/api_surface.rs` checks every shipped endpoint pattern against the
  Docker Engine API path list, so a pattern that matches no real endpoint fails
  the build instead of reading as policy that does nothing.
- **Typo warnings for operator rules.** Methods and endpoints from an allowlist
  file or the environment are checked against the same API surface at startup,
  and anything matching nothing is logged with its source. A mistyped path in
  `deny` or `exclude` was previously silent: stored, never matched, leaving a
  resource reachable the operator believed was blocked. A lowercase method is
  called out specifically, since HTTP methods are case-sensitive.

### Fixed
- **`/containers/*/delete` was dead policy in the `default` profile.** Container
  removal is `DELETE /containers/{id}`, not a subpath, so the deny rule never
  matched. Nothing was reachable through it on its own — the default allow list
  has no `DELETE` — but adding `DELETE` to the allow methods would have exposed
  container removal that the deny list appeared to cover. Now `/containers/*`.

### Changed
- **`deny` and `exclude` now hold independent rules.** Each source contributed
  to one shared rule, and a rule matches on method *and* endpoint, so excluding
  all `POST` in a file and excluding `/secrets` in the environment collapsed
  into "exclude `POST /secrets`" — leaving `GET /secrets` reachable. Each source
  is now evaluated on its own. **Breaking** for any policy that relied on two
  sources intersecting.
- **`read-only` now denies writes on every endpoint**, not only on the mutating
  ones, so an `allow` rule added on top cannot reopen one. **Breaking** for a
  policy that layered a write allowance over this profile.

## [0.2.0] — 2026-08-12

Streaming, `docker exec`, and observability, on top of a policy engine split
into decision, administration, and enforcement. Two breaking changes are marked
below.

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

[Unreleased]: https://github.com/logxel/docker-socket-proxy/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/logxel/docker-socket-proxy/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/logxel/docker-socket-proxy/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/logxel/docker-socket-proxy/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/logxel/docker-socket-proxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/logxel/docker-socket-proxy/releases/tag/v0.1.0
