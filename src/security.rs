//! Security filter for the Docker API proxy.
//!
//! Implements a **default-deny** policy. Every incoming request is
//! inspected against the configured allowlist and denylist before
//! being forwarded to the Docker socket.
//!
//! # Contract
//! - **Pre-condition**: `SecurityFilter` must be initialised with a valid
//!   configuration before any request is inspected.
//! - **Post-condition**: `check()` returns `Ok(())` if the request is allowed,
//!   or `Err(ProxyError::Forbidden)` with a descriptive message.
//! - **Invariant**: No request escapes inspection — every HTTP method and
//!   path is evaluated.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;
use tracing::warn;

use crate::config::SecurityProfile;
use crate::error::ProxyError;

type SecurityResult = Result<(), ProxyError>;

// ── TOML config types ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AllowlistConfig {
    pub allow: Option<EndpointSet>,
    pub deny: Option<EndpointSet>,
    pub include: Option<EndpointSet>,
    pub exclude: Option<EndpointSet>,
}

#[derive(Debug, Deserialize)]
pub struct EndpointSet {
    pub endpoints: Option<Vec<String>>,
    pub methods: Option<Vec<String>>,
}

// ── SecurityFilter ──────────────────────────────────────────────

/// Endpoint filter that enforces allowlist/denylist rules.
///
/// Evaluation order:
/// 1. **Denylist** — if method AND endpoint match, block immediately.
/// 2. **Allowlist** — if method AND endpoint match, allow.
/// 3. **Default deny** — everything else is blocked.
///
/// Patterns support a `*` wildcard that matches exactly one path
/// segment (e.g. `/containers/*/json` matches `/containers/abc/json`).
#[derive(Debug, Clone)]
pub struct SecurityFilter {
    allowed_methods: HashSet<String>,
    allowed_endpoints: Vec<String>,
    denied_methods: HashSet<String>,
    denied_endpoints: Vec<String>,
    excluded_methods: HashSet<String>,
    excluded_endpoints: Vec<String>,
    profile: SecurityProfile,
}

impl SecurityFilter {
    // ── Constructors ─────────────────────────────────────────

    /// Create a filter with built-in defaults.
    ///
    /// Allows common read-only Docker endpoints on GET/HEAD.
    /// Blocks all mutation endpoints (container create, exec, build).
    pub fn new() -> Self {
        Self {
            allowed_methods: HashSet::from(["GET".into(), "HEAD".into()]),
            allowed_endpoints: vec![
                "/containers/json".into(),
                "/containers/*/json".into(),
                "/containers/*/logs".into(),
                "/images/json".into(),
                "/images/*/json".into(),
                "/info".into(),
                "/version".into(),
                "/networks".into(),
                "/networks/".into(),
                "/volumes".into(),
                "/volumes/".into(),
                "/_ping".into(),
            ],
            denied_methods: HashSet::from(["POST".into(), "PUT".into(), "DELETE".into()]),
            denied_endpoints: vec![
                "/containers/create".into(),
                "/containers/*/exec".into(),
                "/containers/*/start".into(),
                "/containers/*/stop".into(),
                "/containers/*/restart".into(),
                "/containers/*/kill".into(),
                "/containers/*/pause".into(),
                "/containers/*/unpause".into(),
                "/containers/*/rename".into(),
                "/containers/*/update".into(),
                "/containers/*/delete".into(),
                "/containers/*/resize".into(),
                "/containers/*/attach".into(),
                "/containers/*/wait".into(),
                "/exec/".into(),
                "/build".into(),
                "/commit".into(),
            ],
            excluded_methods: HashSet::new(),
            excluded_endpoints: Vec::new(),
            profile: SecurityProfile::Default,
        }
    }

    /// Create a filter for a built-in security profile.
    pub fn for_profile(profile: &SecurityProfile) -> Self {
        let mut filter = Self::new();
        filter.profile = profile.clone();
        if matches!(profile, SecurityProfile::ReadOnly) {
            filter.denied_methods =
                HashSet::from(["POST".into(), "PUT".into(), "DELETE".into(), "PATCH".into()]);
        }
        if matches!(profile, SecurityProfile::ContainerRuntime) {
            filter
                .allowed_methods
                .extend(["POST".into(), "PUT".into(), "DELETE".into()]);
            filter.allowed_endpoints.extend([
                "/containers/create".into(),
                "/containers/*/start".into(),
                "/containers/*/exec".into(),
                "/containers/*/wait".into(),
                "/containers/*/archive".into(),
                "/containers/*".into(),
                "/images/create".into(),
                "/images/load".into(),
                "/build".into(),
                "/networks/*/connect".into(),
                "/exec/*/start".into(),
            ]);
            filter.denied_endpoints.retain(|endpoint| {
                !matches!(
                    endpoint.as_str(),
                    "/containers/create"
                        | "/containers/*/start"
                        | "/containers/*/exec"
                        | "/containers/*/wait"
                        | "/containers/*/delete"
                        | "/exec/"
                        | "/build"
                )
            });
        }
        filter
    }

    /// Load rules from a TOML file. Falls back to built-in defaults
    /// if the file is missing or unparseable.
    pub fn from_file(path: Option<&Path>) -> Self {
        Self::from_file_and_profile(path, &SecurityProfile::Default)
    }

    /// Load rules on top of a named built-in profile.
    pub fn from_file_and_profile(path: Option<&Path>, profile: &SecurityProfile) -> Self {
        let path = match path {
            Some(p) => p,
            None => return Self::for_profile(profile),
        };

        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Cannot read allowlist file {}: {e}", path.display());
                return Self::for_profile(profile);
            }
        };

        match toml::from_str::<AllowlistConfig>(&contents) {
            Ok(cfg) => Self::from_config(cfg, profile),
            Err(e) => {
                warn!("Invalid allowlist file {}: {e}", path.display());
                Self::for_profile(profile)
            }
        }
    }

    fn from_config(cfg: AllowlistConfig, profile: &SecurityProfile) -> Self {
        let mut filter = Self::for_profile(profile);

        // `allow`/`deny` are additive modifiers for compatibility with the
        // common Docker socket proxy terminology. `include`/`exclude` are the
        // explicit modifier names and are applied after the base profile.
        for set in [cfg.allow, cfg.include].into_iter().flatten() {
            extend_unique(&mut filter.allowed_endpoints, set.endpoints);
            extend_set(&mut filter.allowed_methods, set.methods);
        }
        for set in [cfg.deny].into_iter().flatten() {
            extend_unique(&mut filter.denied_endpoints, set.endpoints);
            extend_set(&mut filter.denied_methods, set.methods);
        }
        for set in [cfg.exclude].into_iter().flatten() {
            extend_unique(&mut filter.excluded_endpoints, set.endpoints);
            extend_set(&mut filter.excluded_methods, set.methods);
        }

        filter
    }

    // ── Check ─────────────────────────────────────────────────

    /// Check whether a request is allowed through the proxy.
    ///
    /// # Arguments
    /// - `method` — HTTP method (e.g. `"GET"`, `"POST"`).
    /// - `path`   — Request URI path (e.g. `"/containers/json"`).
    pub fn check(&self, method: &str, path: &str) -> SecurityResult {
        if self.excluded_methods.contains(method)
            || self
                .excluded_endpoints
                .iter()
                .any(|p| matches_pattern(p, path))
        {
            return Err(ProxyError::Forbidden(format!(
                "excluded by policy: {method} {path}"
            )));
        }
        // 1. Denylist takes priority
        if self.denied_methods.contains(method)
            && self
                .denied_endpoints
                .iter()
                .any(|p| matches_pattern(p, path))
        {
            return Err(ProxyError::Forbidden(format!(
                "blocked endpoint: {method} {path}"
            )));
        }

        // 2. Allowlist
        if self.allowed_methods.contains(method)
            && self
                .allowed_endpoints
                .iter()
                .any(|p| matches_pattern(p, path))
        {
            return Ok(());
        }

        // 3. Default deny
        Err(ProxyError::Forbidden(format!(
            "not allowed: {method} {path}"
        )))
    }

    /// Check the request and validate profile-specific metadata.
    pub fn check_request(&self, method: &str, path: &str, body: &[u8]) -> SecurityResult {
        let policy_path = normalize_api_path(path);
        self.check(method, policy_path)?;
        if matches!(self.profile, SecurityProfile::ContainerRuntime)
            && method == "POST"
            && policy_path == "/containers/create"
        {
            check_dagster_create_body(body)?;
        }
        Ok(())
    }
}

fn extend_unique(target: &mut Vec<String>, values: Option<Vec<String>>) {
    for value in values.into_iter().flatten() {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn extend_set(target: &mut HashSet<String>, values: Option<Vec<String>>) {
    target.extend(values.into_iter().flatten());
}

fn normalize_api_path(path: &str) -> &str {
    let mut segments = path.split('/');
    let _root = segments.next();
    let version = segments.next().unwrap_or_default();
    if version.starts_with('v')
        && version[1..]
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    {
        let prefix_len = 1 + version.len();
        return &path[prefix_len..];
    }
    path
}

fn check_dagster_create_body(body: &[u8]) -> SecurityResult {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| {
        ProxyError::Forbidden("Dagster container create body must be valid JSON".into())
    })?;
    let object = value.as_object().ok_or_else(|| {
        ProxyError::Forbidden("Dagster container create body must be an object".into())
    })?;
    let image = object.get("Image").and_then(serde_json::Value::as_str);
    let labels = object.get("Labels").and_then(serde_json::Value::as_object);
    if image.is_none() || image == Some("") || object.get("Cmd").is_none() {
        return Err(ProxyError::Forbidden(
            "Dagster create requires Image and Cmd metadata".into(),
        ));
    }
    for key in [
        "Privileged",
        "CapAdd",
        "SecurityOpt",
        "Devices",
        "PidMode",
        "IpcMode",
        "UsernsMode",
    ] {
        if object.get(key).is_some_and(|value| !value.is_null()) {
            return Err(ProxyError::Forbidden(format!(
                "Dagster create field is not permitted: {key}"
            )));
        }
    }
    if let Some(labels) = labels {
        for label in ["dagster/run_id", "dagster/job_name"] {
            if object.get("Labels").is_some()
                && labels.get(label).is_none()
                && labels.keys().any(|key| key.starts_with("dagster/"))
            {
                return Err(ProxyError::Forbidden(format!(
                    "Dagster create requires label: {label}"
                )));
            }
        }
    }
    Ok(())
}

impl Default for SecurityFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Pattern matching ───────────────────────────────────────────

/// Match a path against a pattern that supports `*` as a single-segment wildcard.
///
/// - Exact: `"/containers/json"` matches `"/containers/json"`
/// - Wildcard: `"/containers/*/json"` matches `"/containers/abc123/json"`
/// - Prefix: `"/exec/"` matches `"/exec/anything/here"`
/// - Wildcard fails on wrong suffix: `"/containers/*/json"` does NOT match `"/containers/abc/exec"`
fn matches_pattern(pattern: &str, path: &str) -> bool {
    // Exact match
    if pattern == path {
        return true;
    }

    // Prefix match (pattern ends with '/')
    if pattern.ends_with('/') {
        return path.starts_with(pattern);
    }

    // Wildcard segment matching: /containers/*/json
    if pattern.contains('*') {
        let segs_pat: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
        let segs_path: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if segs_pat.len() != segs_path.len() {
            return false;
        }

        return segs_pat
            .iter()
            .zip(segs_path.iter())
            .all(|(p, a)| *p == "*" || p == a);
    }

    false
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn filter() -> SecurityFilter {
        SecurityFilter::new()
    }

    #[test]
    fn allows_read_only_endpoints() {
        let f = filter();
        assert!(f.check("GET", "/containers/json").is_ok());
        assert!(f.check("GET", "/images/json").is_ok());
        assert!(f.check("GET", "/info").is_ok());
        assert!(f.check("GET", "/version").is_ok());
        assert!(f.check("GET", "/_ping").is_ok());
    }

    #[test]
    fn allows_inspect_endpoints_with_wildcard() {
        let f = filter();
        assert!(f.check("GET", "/containers/abc123def456/json").is_ok());
        assert!(f.check("GET", "/containers/abc123def456/logs").is_ok());
        assert!(f.check("GET", "/images/sha256:abc123/json").is_ok());
    }

    #[test]
    fn blocks_mutation_endpoints() {
        let f = filter();
        assert!(f.check("POST", "/containers/create").is_err());
        assert!(f.check("POST", "/containers/abc123/exec").is_err());
        assert!(f.check("POST", "/build").is_err());
        assert!(f.check("POST", "/commit").is_err());
    }

    #[test]
    fn blocks_exec_prefix() {
        let f = filter();
        assert!(f.check("POST", "/exec/abc123/start").is_err());
        assert!(f.check("POST", "/exec/abc123/resize").is_err());
    }

    #[test]
    fn blocks_restart_stop_start() {
        let f = filter();
        assert!(f.check("POST", "/containers/abc123/start").is_err());
        assert!(f.check("POST", "/containers/abc123/stop").is_err());
        assert!(f.check("POST", "/containers/abc123/restart").is_err());
        assert!(f.check("POST", "/containers/abc123/kill").is_err());
    }

    #[test]
    fn allows_get_to_allowed_endpoints() {
        let f = filter();
        // Network list
        assert!(f.check("GET", "/networks").is_ok());
        // Network inspect
        assert!(f.check("HEAD", "/networks/my-net").is_ok());
        // Volume list
        assert!(f.check("GET", "/volumes").is_ok());
        // Volume inspect
        assert!(f.check("GET", "/volumes/my-vol").is_ok());
    }

    #[test]
    fn blocks_post_to_allowed_prefix() {
        let f = filter();
        // POST to a network endpoint should be blocked
        assert!(f.check("POST", "/networks/create").is_err());
    }

    #[test]
    fn blocks_unknown_endpoints() {
        let f = filter();
        assert!(f.check("GET", "/secrets").is_err());
        assert!(f.check("GET", "/swarm").is_err());
    }

    #[test]
    fn container_runtime_profile_allows_launcher_workflow() {
        let f = SecurityFilter::for_profile(&SecurityProfile::ContainerRuntime);
        assert!(f.check("POST", "/containers/create").is_ok());
        assert!(f.check("POST", "/containers/abc/start").is_ok());
        assert!(f.check("POST", "/images/create").is_ok());
        assert!(f.check("POST", "/networks/net/connect").is_ok());
        assert!(f.check("POST", "/containers/abc/exec").is_ok());
        assert!(f.check("POST", "/exec/exec-id/start").is_ok());
        assert!(f.check("POST", "/build").is_ok());
        assert!(f.check("POST", "/images/load").is_ok());
        assert!(f.check("POST", "/containers/abc/wait").is_ok());
        assert!(f.check("DELETE", "/containers/abc").is_ok());
    }

    #[test]
    fn container_runtime_profile_requires_safe_create_metadata() {
        let f = SecurityFilter::for_profile(&SecurityProfile::ContainerRuntime);
        let body = br#"{"Image":"worker:latest","Cmd":["dagster","api"],"Labels":{"dagster/run_id":"run-1","dagster/job_name":"job"}}"#;
        assert!(f.check_request("POST", "/containers/create", body).is_ok());
        assert!(
            f.check_request("POST", "/containers/create", br#"{"Image":"worker"}"#)
                .is_err()
        );
        let privileged = br#"{"Image":"worker","Cmd":[],"Labels":{"dagster/run_id":"r","dagster/job_name":"j"},"Privileged":true}"#;
        assert!(
            f.check_request("POST", "/containers/create", privileged)
                .is_err()
        );
        let mounted = br#"{"Image":"worker","Cmd":[],"Mounts":[{"Type":"bind","Source":"/opt/knime","Target":"/opt/knime"}]}"#;
        assert!(
            f.check_request("POST", "/containers/create", mounted)
                .is_ok()
        );
    }

    #[test]
    fn from_toml_merges_allow_rules_with_defaults() {
        let toml = r#"
[allow]
endpoints = ["/_ping"]
methods = ["GET"]

[deny]
endpoints = []
methods = []
"#;
        let cfg: AllowlistConfig = toml::from_str(toml).unwrap();
        let f = SecurityFilter::from_config(cfg, &SecurityProfile::Default);

        // The configured endpoint is added while the profile defaults remain.
        assert!(f.check("GET", "/_ping").is_ok());
        assert!(f.check("GET", "/containers/json").is_ok());
        assert!(f.check("GET", "/info").is_ok());
    }

    #[test]
    fn pattern_exact_match() {
        assert!(matches_pattern("/containers/json", "/containers/json"));
        assert!(!matches_pattern("/containers/json", "/containers/other"));
    }

    #[test]
    fn pattern_prefix_match() {
        assert!(matches_pattern("/exec/", "/exec/abc123/start"));
        assert!(matches_pattern("/exec/", "/exec/anything"));
        assert!(!matches_pattern("/exec/", "/containers/exec"));
    }

    #[test]
    fn pattern_wildcard_segment() {
        assert!(matches_pattern(
            "/containers/*/json",
            "/containers/abc123/json"
        ));
        assert!(matches_pattern(
            "/containers/*/json",
            "/containers/def456/json"
        ));
        // Wildcard matches ONE segment, not multiple
        assert!(!matches_pattern(
            "/containers/*/json",
            "/containers/a/b/json"
        ));
    }

    #[test]
    fn pattern_wildcard_fails_on_wrong_suffix() {
        assert!(!matches_pattern(
            "/containers/*/json",
            "/containers/abc123/exec"
        ));
        assert!(!matches_pattern(
            "/containers/*/json",
            "/containers/abc123/logs"
        ));
    }

    #[test]
    fn accepts_versioned_docker_api_paths() {
        let f = SecurityFilter::for_profile(&SecurityProfile::ContainerRuntime);
        assert!(
            f.check_request(
                "POST",
                "/v1.55/containers/create",
                br#"{"Image":"worker","Cmd":[]}"#
            )
            .is_ok()
        );
        assert!(f.check_request("GET", "/v1.55/version", b"").is_ok());
    }

    #[test]
    fn include_adds_and_exclude_removes_from_profile() {
        let cfg: AllowlistConfig = toml::from_str(
            r#"
[include]
endpoints = ["/images/*/json"]
methods = ["GET"]

[exclude]
endpoints = ["/containers/*/logs"]
"#,
        )
        .unwrap();
        let f = SecurityFilter::from_config(cfg, &SecurityProfile::Default);
        assert!(f.check("GET", "/images/abc/json").is_ok());
        assert!(f.check("GET", "/containers/abc/logs").is_err());
    }

    #[test]
    fn read_only_profile_blocks_mutating_methods() {
        let f = SecurityFilter::for_profile(&SecurityProfile::ReadOnly);
        assert!(f.check("GET", "/info").is_ok());
        assert!(f.check("POST", "/containers/json").is_err());
    }
}
