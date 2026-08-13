# Security Policy

## Supported Versions

This project is pre-1.0. Only the latest released version receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |
| < 0.1   | ❌ |

## Reporting a Vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/logxel/docker-socket-proxy/security/advisories/new).

Do not open a public issue for a suspected vulnerability.

Include where practical:

- Affected version, profile (`default`, `read-only`, `container-runtime`), and any custom policy file
- The HTTP method and path that produced the unexpected result
- Whether the issue is a **policy bypass** (a request reaching the Docker socket that the policy should have blocked) or a **denial of service**

We aim to acknowledge within 5 business days and to ship a fix or a documented
mitigation within 90 days of a confirmed report.

## Scope

### In scope
- Any request reaching the Docker socket that the active policy should have denied
- Path normalization or pattern-matching flaws that let a client evade a rule
- Policy merge or precedence errors that widen access beyond the configured intent
- Create-body inspection bypasses (`Privileged`, `CapAdd`, `SecurityOpt`, `Devices`, namespace overrides)
- Resource exhaustion reachable by an unauthenticated client

### Out of scope
These are documented properties of the current design, not vulnerabilities. See
[Trust Boundary](README.md#trust-boundary).

- **Absence of authentication.** The proxy does not authenticate clients. Reaching the port is expected to grant everything the active profile permits. Operators must restrict network access.
- **Capabilities granted by `container-runtime`.** This profile intentionally permits container creation, image builds, and bind mounts. A caller holding it can reach the host with effort. That is the documented trade-off; expose it only to trusted services.
- **Ineffectiveness of a `:ro` socket mount.** The read-only flag applies to the inode, not the protocol. Documented in the README.
- Vulnerabilities in the Docker daemon itself — report those to [Docker](https://github.com/moby/moby/security/policy).

## Known Gaps

Tracked openly in [`STATUS.md`](STATUS.md) rather than treated as embargoed
issues, since each is a documented limitation rather than an exploitable
regression:

- Policy denials produce no audit record
- No request timeout or body-size limit
- Path normalization does not yet implement RFC 3986 §6
