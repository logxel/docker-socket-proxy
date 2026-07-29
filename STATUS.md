# STATUS.md — Current State

## Project Phase: Bootstrap

The project has been initialized with the basic structure. No implementation exists yet.

## Completed
- [x] Project structure created (`cargo init`)
- [x] Cargo.toml configured with dependencies and strict lints
- [x] AGENTS.md defined with final expected state
- [x] STATUS.md created (this file)
- [x] LICENSE (MIT) added
- [x] `src/lib.rs` — public module declarations
- [x] `src/error.rs` — `ProxyError` enum with `thiserror` + `IntoResponse`
- [x] `src/config.rs` — CLI/ENV config via clap derive
- [x] `src/security.rs` — `SecurityFilter` skeleton with default-deny logic
- [x] `src/proxy.rs` — Axum server with graceful shutdown
- [x] `src/main.rs` — Entry point: config parsing → logging → proxy start
- [x] `tests/integration.rs` — integration test placeholder
- [x] Dockerfile created (multi-stage, musl → scratch, multi-arch)
- [x] CI/CD workflow created (`.github/workflows/ci.yml`): lint, test, audit, build-push
- [x] README.md created with quick-start and configuration docs
- [x] `.gitignore` configured
- [x] Build verified: `cargo check`, `cargo fmt`, `cargo clippy`, `cargo test` all pass

## In Progress
Nothing yet.

## Next Steps (in order)
1. Flesh out `src/security.rs` — Complete allowlist/denylist engine with TOML parsing
2. Flesh out `src/proxy.rs` — Implement raw HTTP forwarding via hyperlocal-next to Docker socket
3. Flesh out `src/config.rs` — Load and parse TOML allowlist file
4. Add `SecurityFilter` to the proxy handler pipeline (tower layer or manual check)
5. Write unit tests for all modules
6. Write integration tests against Docker socket
7. Verify Docker multi-arch build (`docker buildx`)
8. Verify CI/CD pipeline on GitHub

## Blockers
None.

## Decisions Log
| Decision | Choice | Rationale |
|----------|--------|-----------|
| Project name | `docker-socket-proxy` | Descriptive, follows kebab-case Rust style |
| Crate name | `docker-socket-proxy` | Same as project name |
| Binary name | `docker-socket-proxy` | Same as project name |
| Container image | `ghcr.io/logxel/docker-socket-proxy` | GHCR with org namespace |
| License | MIT | Permissive, standard for Rust ecosystem |
| Rust edition | 2024 | Latest stable edition |
| Async runtime | Tokio | De facto standard, needed by axum/bollard |
| HTTP server | Axum | Ergonomic, tower-based, hyper under the hood |
| Docker client | Bollard + hyperlocal-next | Bollard for typed API, hyperlocal for raw forwarding |
| Bollard features | `pipe` + `http` only (default-features = false) | Strips TLS, SSH, BuildKit, WebSocket, chrono/time — reduces binary size |
| Removed deps | tower-http, anyhow | tower-http not needed yet (can add when tracing is implemented); anyhow replaced with String for Internal errors |
| Base image | scratch | Minimal attack surface, relies on static musl binary |
| Lint strictness | deny unwrap/expect/panic | Enforces Result Pattern and Fail-Fast |
