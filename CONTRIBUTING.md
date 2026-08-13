# Contributing

Contributions are welcome via GitHub issues and pull requests.

## Reporting problems

- Bugs and feature requests: open an [issue](https://github.com/logxel/docker-socket-proxy/issues).
- Security vulnerabilities: do NOT open a public issue — see [`SECURITY.md`](SECURITY.md).

## Development workflow

1. Fork the repository and create a branch off `main`.
2. Make a focused, minimal change.
3. Verify it passes the checks enforced in CI:
   - `cargo fmt --all --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test --all-targets`
4. Add tests for new functionality.
5. Open a pull request.

Coding standards are documented in [`AGENTS.md`](AGENTS.md) ("Code Quality
Standards"): production code must not use `unwrap()`, `expect()`, or `panic!`,
`unsafe` is forbidden, and new functionality is expected to ship with tests.
