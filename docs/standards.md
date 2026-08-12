# Standards Catalogue

Which industry standards apply to `docker-socket-proxy`, which ones we adopt,
and — for anything that ships code — what it costs in binary size.

This file is the decision record. `AGENTS.md` describes the resulting target
state; `STATUS.md` tracks how far along we are.

---

## Selection criteria

The project has a hard size budget: **binary < 8 MB, image < 10 MB**. Every
standard is therefore classified by what it costs to satisfy:

| Class | Meaning |
|-------|---------|
| **Free** | Docs, CI, Dockerfile, or process only. No code, no dependencies. |
| **Cheap** | Code using crates already in the tree, or a thin addition. |
| **Gated** | Real dependency weight. Ships behind a Cargo feature, off by default. |
| **Rejected** | Cost exceeds the benefit at this project's scale. |

### Measured baseline

Measured on the host `x86_64-unknown-linux-gnu` target with the release profile
(`opt-level = "z"`, `lto = true`, `codegen-units = 1`, `strip = true`,
`panic = "abort"`). The musl static build will differ in absolute terms — treat
these as relative figures.

```
release binary          1,842,928 bytes  (1.76 MiB)   budget 8 MB → ~77% headroom
image                   1,965,408 bytes  (1.87 MiB)   budget 10 MB
dependency tree               121 crates              budget 130
```

**The budget is denominated in crates, not bytes.** Dropping two dependencies
that were declared but never referenced removed 46 crates — 28% of the tree —
and changed binary size by ~3 KB, because LTO was already eliminating them. A
declared-but-unlinked dependency is effectively free, so binary size does not
react until code actually links against a crate. Crate count moves first and is
therefore the number to budget against.

### Measured cost of candidate additions

Crate-count delta from the 118-crate baseline:

| Candidate | Δ crates | Class |
|---|---:|---|
| `tower-http` (`limit`, `timeout`, `trace`) | +2 | **Cheap** |
| `tokio-rustls` (mTLS) | +11 | **Gated** |
| `cedar-policy` | +59 | **Rejected** (default) |
| `opentelemetry-otlp` | +77 | **Rejected** (default) |
| `jsonschema` | +83 | **Rejected** |

The bottom three each add more crates than the entire tree they would join. None
of them ship in the default build.

**Budget rule going forward:** the default build stays under 8 MB and under
~130 crates. Anything heavier is a Cargo feature or is not adopted.

---

## Adopted — Free

Documentation, CI, and packaging. No effect on the binary.

### Security frameworks
| Standard | What we do |
|---|---|
| **NIST SP 800-190** — Application Container Security Guide | Map every denied endpoint to its control ID in the security model docs |
| **CIS Docker Benchmark** | Same mapping; cite control numbers rather than asserting safety |
| **OWASP API Security Top 10 (2023)** | Track API2 (authentication) and API4 (resource consumption) as named gaps |
| **NIST SP 800-53 AU-2 / AU-3** | Every policy denial emits a structured audit event |

### Supply chain
| Standard | What we do |
|---|---|
| **SLSA v1.0** provenance | `actions/attest-build-provenance`; Build L2 immediately, L3 via reusable workflow |
| **SPDX / CycloneDX** SBOM | `docker/build-push-action` with `sbom: true`, `provenance: mode=max` |
| **Sigstore / cosign** | Keyless signing via GitHub OIDC |
| **OpenSSF Scorecard** | Weekly run publishing to the OpenSSF API, with all actions pinned by commit SHA |
| **`cargo-deny`** | Replaces bare `cargo-audit` — adds licence policy and banned/duplicate crates |
| **Reproducible builds** | Pin `rust:alpine` by digest; `cargo build --locked` in CI and Dockerfile |

### Packaging & lifecycle
| Standard | What we do |
|---|---|
| **OCI Image Spec** annotations | `LABEL org.opencontainers.image.*` in the Dockerfile, not just CI-injected |
| **Least privilege** | Non-root `USER` in the runtime stage |
| **12-Factor App** | Already satisfied — config via CLI and environment |

### Project hygiene
**SemVer 2.0.0** (state it explicitly) · **Keep a Changelog** · **Conventional
Commits** · **`SECURITY.md`** · **`CONTRIBUTING.md`** · **Dependabot** ·
**RFC 9116 `security.txt`** if a site is ever hosted.

### Documentation structure
**ADR (Nygard / MADR)** — formalises the Decisions Log in `STATUS.md`; each
record immutable and dated, which fixes the staleness failure mode.
**C4 model** — `src/proxy.rs` already carries a C4-L2-style container diagram.

---

## Adopted — Cheap

Code changes using crates already present, or the +2-crate `tower-http`.

| Standard | Applies to | Cost |
|---|---|---|
| **RFC 9110 §7.6.1** — hop-by-hop header stripping | Request path strips only `Host`; must also strip headers named in the client's `Connection` field | Free (logic) |
| **Docker Engine API error contract** | Error body must be `{"message": ...}`, not `{"error", "status"}` | Free (logic) |
| **RFC 9457** — Problem Details | `application/problem+json` for proxy-originated errors, content-negotiated so Docker clients keep the native shape | Free (logic) |
| **Container lifecycle — SIGTERM** | `tokio::signal::unix`; already available via tokio's `full` feature | Free |
| **RFC 3986 §6** — URI normalization | Percent-decode, remove dot-segments, collapse duplicate slashes before policy matching | Free (hand-rolled) |
| **XACML combining algorithms** | Name and document the precedence as `deny-overrides`; fixes `exclude` matching method-OR-endpoint while `deny` requires method-AND-endpoint | Free (logic) |
| **Kubernetes RBAC** (as a model) | verbs × resources × resourceNames ≈ methods × patterns × wildcards | Free (design) |
| **RFC 7386** — JSON Merge Patch | Principled semantics for the `allow`/`deny`/`include`/`exclude` merge | Free (design) |
| **Tecnativa / linuxserver env convention** | `CONTAINERS=1`, `POST=0` compatibility shim → drop-in replacement | Free (logic) |
| **OWASP API4** — resource consumption | `tower-http` `RequestBodyLimitLayer` + `TimeoutLayer` | +2 crates |
| **OpenMetrics / Prometheus** | `/metrics` with allow/deny counters, hand-rolled text exposition over `AtomicU64` | Free |
| **OpenTelemetry semantic conventions** | Adopt the *naming* in existing `tracing` output — the conventions are free, only the OTLP exporter is not | Free |
| **W3C Trace Context** | Propagate an inbound `traceparent` upstream (propagate only, don't generate) | Free |
| **API health check** ([IETF draft](https://datatracker.ietf.org/doc/draft-inadarei-api-health-check/)) | Health endpoint; needs a `--health-check` subcommand since scratch has no shell | Free |
| **Docker Engine API streaming** | `/events`, `logs?follow=1`, `/build` streaming and 101-upgrade for `/exec/*/start`, `attach` — uses hyper facilities already linked | Free (significant work) |

### Architecture
| Standard | Applies to |
|---|---|
| **Hexagonal / Ports & Adapters** | Domain = policy decision; ports = inbound HTTP, outbound Docker transport, policy source. `SecurityFilter` currently does its own `std::fs` and `std::env` I/O |
| **Functional core / imperative shell** | The lighter framing, better suited at ~1,500 LOC. `check()` is already pure |
| **tower `Layer`** | The security filter becomes a real PEP layer instead of an in-handler call; unlocks the `tower-http` layers above |
| **PEP / PDP / PAP** (NIST SP 800-162) | tower Layer = PEP, `SecurityFilter` = PDP, policy loader = PAP — maps 1:1 onto the hexagonal ports |
| **Rust API Guidelines (C-\*)** | Newtypes over `String` for methods and patterns; `cargo-semver-checks` at 1.0 |

---

## Gated behind a Cargo feature

| Standard | Feature | Cost | Rationale |
|---|---|---|---|
| **mTLS** (Docker's TLS-on-2376 convention) | `tls` | +11 crates | The single largest security gap — there is no authentication today. But most deployments put this on a private network, so the default image stays lean and operators opt in |
| **[Docker AuthZ Plugin API](https://pkg.go.dev/github.com/docker/go-plugins-helpers/authorization)** | `authz-plugin` | ~0 crates | Reuses axum + serde. Second front-end for the same PDP, running in-daemon rather than as a network hop |
| **[AuthZEN Authorization API 1.0](https://openid.net/wg/authzen/specifications/)** | `authzen` | ~0 crates | Ratified March 2026. Standard JSON PDP↔PEP format; lets an external engine make decisions |

---

## Rejected for the default build

| Standard / library | Cost | Rationale |
|---|---|---|
| **Cedar** (`cedar-policy`) | +59 crates | Technically the best fit — Rust-native, formally verified — but adds half again the whole dependency tree to replace a matcher that is ~30 lines. Revisit only if policy expressiveness becomes the bottleneck |
| **OpenTelemetry SDK / OTLP** | +77 crates | The gRPC exporter stack is disproportionate. We take the semantic conventions for free and leave export to the log pipeline |
| **JSON Schema** (`jsonschema`) | +83 crates | Would make create-body inspection data instead of code — genuinely desirable, but not at this price. A small declarative field-constraint config covers the real use case |
| **OPA / Rego** | 0 binary, +1 container | Zero binary cost, but a sidecar contradicts the single-static-binary delivery model |
| **CEL** (`cel-interpreter`) | moderate | Middle ground for body predicates; no current need that the field-constraint config doesn't cover |
| **Full DDD** (aggregates, repositories) | — | Wrong scale for ~1,500 LOC |
| **OpenFGA / Zanzibar ReBAC** | — | No user↔resource relationship graph exists here |
| **XACML XML serialization** | — | Vocabulary and combining algorithms adopted; the wire format is not |
| **RateLimit header fields** | — | Still an [IETF draft](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/), not an RFC. Revisit on publication |

---

## Next steps

Three waves, ordered so each is independently shippable and verifiable.
Progress is tracked in [`STATUS.md`](../STATUS.md).

### Wave 1 — Correctness and hygiene, no architecture change — *done*
SIGTERM handling · denial auditing · Docker-shaped error bodies · hop-by-hop
request headers · dropped unused dependencies · `SECURITY.md`, `CHANGELOG.md`,
Dependabot, SHA-pinned actions, `cargo-deny`, `--locked`.

### Wave 2 — Structure, then the layers it unlocks — *done*
PEP/PDP/PAP split with the filter as a `tower::Layer` · policy I/O moved to a
loader · body-size limit and optional timeout · consistent `deny-overrides`
matching · RFC 3986 path normalization · SBOM, SLSA provenance, and Scorecard in
CI · digest-pinned builder with OCI labels.

### Wave 3 — Capability
1. **Streaming and 101-upgrade passthrough** — *done*. Bodies relay frame by
   frame and a 101 splices both connections, so `/events`, follow-mode logs,
   `/build`, and `docker exec` all work
2. **`/metrics` and health endpoint**
3. **Tecnativa env-var compatibility shim** — adoption unlock
4. **NIST 800-190 / CIS control mapping** in the security docs
5. **`tls` feature** for mTLS

---

## References

- [Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) · [linuxserver/socket-proxy](https://docs.linuxserver.io/images/docker-socket-proxy/)
- [Docker Authorization Plugin API](https://pkg.go.dev/github.com/docker/go-plugins-helpers/authorization) · [opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz)
- [OpenID AuthZEN specifications](https://openid.net/wg/authzen/specifications/) · [Cedar](https://crates.io/crates/cedar-policy)
- [SLSA](https://slsa.dev/) · [OpenSSF Scorecard](https://github.com/ossf/scorecard) · [Sigstore](https://www.sigstore.dev/)
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final) · [NIST SP 800-162](https://csrc.nist.gov/publications/detail/sp/800-162/final) · [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [Docker Engine API](https://docs.docker.com/reference/api/engine/)
