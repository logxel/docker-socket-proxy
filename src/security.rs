//! Policy decision point for the Docker API proxy.
//!
//! Implements a **default-deny** policy. This module is pure: it performs no
//! I/O and reads no environment. Loading policy from disk or environment is the
//! job of [`crate::policy`].
//!
//! # Contract
//! - **Post-condition**: `check` returns `Ok(())` if the request is allowed, or
//!   `Err(ProxyError::Forbidden)` naming the rule that rejected it.
//! - **Invariant**: Every method and path is evaluated; nothing escapes
//!   inspection.

use std::collections::HashSet;

use crate::config::SecurityProfile;
use crate::error::ProxyError;

type SecurityResult = Result<(), ProxyError>;

/// A set of methods and endpoint patterns evaluated as one rule.
///
/// An empty side is a wildcard, so `methods = ["DELETE"]` with no endpoints
/// matches every `DELETE`. A rule with both sides empty is inert rather than
/// universal — otherwise an unconfigured exclusion would reject everything.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    methods: HashSet<String>,
    endpoints: Vec<String>,
}

impl RuleSet {
    fn new(methods: &[&str], endpoints: &[&str]) -> Self {
        let mut set = Self::default();
        set.add(methods, endpoints);
        set
    }

    fn is_inert(&self) -> bool {
        self.methods.is_empty() && self.endpoints.is_empty()
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        if self.is_inert() {
            return false;
        }
        (self.methods.is_empty() || self.methods.contains(method))
            && (self.endpoints.is_empty()
                || self.endpoints.iter().any(|p| matches_pattern(p, path)))
    }

    fn add(&mut self, methods: &[&str], endpoints: &[&str]) {
        self.extend(
            Some(methods.iter().map(|m| (*m).to_owned()).collect()),
            Some(endpoints.iter().map(|e| (*e).to_owned()).collect()),
        );
    }

    /// Merge additional methods and endpoints, ignoring duplicates.
    pub fn extend(&mut self, methods: Option<Vec<String>>, endpoints: Option<Vec<String>>) {
        self.methods.extend(methods.into_iter().flatten());
        for endpoint in endpoints.into_iter().flatten() {
            if !self.endpoints.contains(&endpoint) {
                self.endpoints.push(endpoint);
            }
        }
    }
}

/// Independent rules, matching when any one of them matches.
///
/// Each source contributes its own [`RuleSet`] instead of merging into a shared
/// one, so "no POST anywhere" and "nothing under `/secrets`" stay separate
/// conditions rather than collapsing into "no POST under `/secrets`".
#[derive(Debug, Clone, Default)]
pub struct RuleList(Vec<RuleSet>);

impl RuleList {
    fn matches(&self, method: &str, path: &str) -> bool {
        self.0.iter().any(|rule| rule.matches(method, path))
    }

    fn push_rule(&mut self, rule: RuleSet) {
        if !rule.is_inert() {
            self.0.push(rule);
        }
    }

    /// Add a rule evaluated independently of those already present.
    pub fn push(&mut self, methods: Option<Vec<String>>, endpoints: Option<Vec<String>>) {
        let mut rule = RuleSet::default();
        rule.extend(methods, endpoints);
        self.push_rule(rule);
    }
}

const READ_METHODS: &[&str] = &["GET", "HEAD"];
const WRITE_METHODS: &[&str] = &["POST", "PUT", "DELETE"];

const READABLE_ENDPOINTS: &[&str] = &[
    "/containers/json",
    "/containers/*/json",
    "/containers/*/logs",
    "/images/json",
    "/images/*/json",
    "/info",
    "/version",
    "/networks",
    "/networks/",
    "/volumes",
    "/volumes/",
    "/_ping",
];

const MUTATING_ENDPOINTS: &[&str] = &[
    "/containers/create",
    "/containers/*/exec",
    "/containers/*/start",
    "/containers/*/stop",
    "/containers/*/restart",
    "/containers/*/kill",
    "/containers/*/pause",
    "/containers/*/unpause",
    "/containers/*/rename",
    "/containers/*/update",
    "/containers/*/delete",
    "/containers/*/resize",
    "/containers/*/attach",
    "/containers/*/wait",
    "/exec/",
    "/build",
    "/commit",
];

const RUNTIME_ENDPOINTS: &[&str] = &[
    "/containers/create",
    "/containers/*/start",
    "/containers/*/exec",
    "/containers/*/wait",
    "/containers/*/archive",
    "/containers/*",
    "/images/create",
    "/images/load",
    "/build",
    "/networks/*/connect",
    "/exec/*/start",
    // The exit status and terminal size of an exec the caller already created;
    // `docker exec` fails without them.
    "/exec/*/json",
    "/exec/*/resize",
];

/// Endpoint filter enforcing allow, deny, and exclude rules.
///
/// Combining algorithm is `deny-overrides`, evaluated in order:
/// 1. **Exclusions** — block.
/// 2. **Denials** — block.
/// 3. **Allowances** — allow.
/// 4. **Default deny**.
///
/// Patterns support a `*` wildcard matching exactly one path segment
/// (`/containers/*/json` matches `/containers/abc/json`), or a trailing `/`
/// for prefix matching.
#[derive(Debug, Clone)]
pub struct SecurityFilter {
    allow: RuleSet,
    deny: RuleList,
    exclude: RuleList,
    profile: SecurityProfile,
}

impl SecurityFilter {
    /// Create a filter with built-in defaults: read-only endpoints on GET/HEAD.
    pub fn new() -> Self {
        Self::for_profile(&SecurityProfile::Default)
    }

    /// Create a filter granting nothing, for a policy defined entirely by its
    /// caller rather than layered over a profile.
    pub fn deny_all() -> Self {
        Self {
            allow: RuleSet::default(),
            deny: RuleList::default(),
            exclude: RuleList::default(),
            profile: SecurityProfile::Default,
        }
    }

    /// Create a filter for a built-in security profile.
    pub fn for_profile(profile: &SecurityProfile) -> Self {
        let mut allow = RuleSet::new(READ_METHODS, READABLE_ENDPOINTS);
        let mut deny = RuleList::default();

        match profile {
            SecurityProfile::Default => {
                deny.push_rule(RuleSet::new(WRITE_METHODS, MUTATING_ENDPOINTS));
            }
            // Every write is refused, on any endpoint, so a later allow rule
            // cannot reopen one under a profile whose name promises otherwise.
            SecurityProfile::ReadOnly => {
                deny.push_rule(RuleSet::new(&["POST", "PUT", "DELETE", "PATCH"], &[]));
            }
            SecurityProfile::ContainerRuntime => {
                allow.add(WRITE_METHODS, RUNTIME_ENDPOINTS);

                let mut writes = RuleSet::new(WRITE_METHODS, MUTATING_ENDPOINTS);
                // Denials override allowances, so the endpoints this profile
                // grants have to leave the write denial entirely.
                writes.endpoints.retain(|endpoint| {
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
                deny.push_rule(writes);
            }
        }

        Self {
            allow,
            deny,
            exclude: RuleList::default(),
            profile: profile.clone(),
        }
    }

    /// Mutable access to the allow rules, for the policy loader.
    pub fn allow_mut(&mut self) -> &mut RuleSet {
        &mut self.allow
    }

    /// Mutable access to the deny rules, for the policy loader.
    pub fn deny_mut(&mut self) -> &mut RuleList {
        &mut self.deny
    }

    /// Mutable access to the exclude rules, for the policy loader.
    pub fn exclude_mut(&mut self) -> &mut RuleList {
        &mut self.exclude
    }

    /// The profile this filter was built from, for audit events.
    pub fn profile(&self) -> &SecurityProfile {
        &self.profile
    }

    /// Check a method and an already-normalized path against the policy.
    pub fn check(&self, method: &str, path: &str) -> SecurityResult {
        if self.exclude.matches(method, path) {
            return Err(ProxyError::Forbidden(format!(
                "excluded by policy: {method} {path}"
            )));
        }
        if self.deny.matches(method, path) {
            return Err(ProxyError::Forbidden(format!(
                "blocked endpoint: {method} {path}"
            )));
        }
        if self.allow.matches(method, path) {
            return Ok(());
        }
        Err(ProxyError::Forbidden(format!(
            "not allowed: {method} {path}"
        )))
    }

    /// Decide from the request head, reporting what the body still owes.
    ///
    /// Splitting the decision lets requests whose body carries no policy weight
    /// stream through instead of being held in memory.
    pub fn check_head(&self, method: &str, path: &str) -> Result<BodyRule, ProxyError> {
        let path = normalize_path(path)?;
        self.check(method, &path)?;

        if matches!(self.profile, SecurityProfile::ContainerRuntime)
            && method == "POST"
            && path == "/containers/create"
        {
            return Ok(BodyRule::ContainerCreate);
        }
        Ok(BodyRule::None)
    }

    /// Apply the rule [`Self::check_head`] reported.
    pub fn check_body(rule: BodyRule, body: &[u8]) -> SecurityResult {
        match rule {
            BodyRule::None => Ok(()),
            BodyRule::ContainerCreate => check_create_body(body),
        }
    }

    /// Normalize the path, check it, then validate profile-specific body rules.
    pub fn check_request(&self, method: &str, path: &str, body: &[u8]) -> SecurityResult {
        Self::check_body(self.check_head(method, path)?, body)
    }
}

/// What a request body owes the decision beyond its head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyRule {
    /// The head decided it; the body may stream through uninspected.
    None,
    /// Container-create constraints apply.
    ContainerCreate,
}

impl Default for SecurityFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Path normalization ─────────────────────────────────────────

/// Reduce a request path to the form policy patterns are written against.
///
/// Applies RFC 3986 §6 normalization — percent-decoding, dot-segment removal,
/// and empty-segment collapsing — before stripping the Docker API version
/// prefix. Without this, `/v1.4/containers/../secrets` or `/containers/%2e%2e`
/// would be matched literally and could evade a rule.
fn normalize_path(path: &str) -> Result<String, ProxyError> {
    let decoded = percent_decode(path)?;
    Ok(strip_api_version(&remove_dot_segments(&decoded)).to_owned())
}

/// Percent-decode, rejecting encoded path separators.
///
/// RFC 3986 §2.2 makes `%2F` distinct from `/`, so decoding one would invent a
/// segment boundary that the origin server does not see. Since either
/// interpretation could disagree with the daemon's, the request is refused.
fn percent_decode(path: &str) -> Result<String, ProxyError> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }

        let digits = bytes
            .get(i + 1..i + 3)
            .and_then(|d| std::str::from_utf8(d).ok())
            .ok_or_else(|| ProxyError::Forbidden("truncated percent-encoding in path".into()))?;
        let byte = u8::from_str_radix(digits, 16)
            .map_err(|_| ProxyError::Forbidden("invalid percent-encoding in path".into()))?;

        if byte == b'/' || byte == b'\\' {
            return Err(ProxyError::Forbidden(
                "encoded path separator in path".into(),
            ));
        }

        out.push(byte);
        i += 3;
    }

    String::from_utf8(out).map_err(|_| ProxyError::Forbidden("path is not valid UTF-8".into()))
}

/// Resolve `.` and `..` segments and collapse empty ones (RFC 3986 §5.2.4).
fn remove_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }

    if segments.is_empty() {
        return "/".to_owned();
    }

    let mut out = String::with_capacity(path.len());
    for segment in segments {
        out.push('/');
        out.push_str(segment);
    }
    out
}

/// Strip a Docker API version prefix (`/v1.55/version` → `/version`) so policy
/// patterns need not enumerate versions.
fn strip_api_version(path: &str) -> &str {
    let Some(rest) = path.strip_prefix("/v") else {
        return path;
    };
    let version = rest.split('/').next().unwrap_or_default();
    let is_version = !version.is_empty()
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));

    if is_version {
        &path[1 + 1 + version.len()..]
    } else {
        path
    }
}

// ── Body inspection ────────────────────────────────────────────

/// Reject container-create bodies that would escape the container boundary.
///
/// Mounts are deliberately permitted: orchestrators require them, and this
/// profile is documented as trusted-caller-only.
fn check_create_body(body: &[u8]) -> SecurityResult {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| ProxyError::Forbidden("container create body must be valid JSON".into()))?;
    let object = value
        .as_object()
        .ok_or_else(|| ProxyError::Forbidden("container create body must be an object".into()))?;

    let image = object.get("Image").and_then(serde_json::Value::as_str);
    if image.is_none() || image == Some("") || object.get("Cmd").is_none() {
        return Err(ProxyError::Forbidden(
            "container create requires Image and Cmd".into(),
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
                "container create field is not permitted: {key}"
            )));
        }
    }

    if let Some(labels) = object.get("Labels").and_then(serde_json::Value::as_object) {
        // Only enforced once a caller identifies itself as Dagster, so other
        // orchestrators are not required to carry its labels.
        let is_dagster = labels.keys().any(|key| key.starts_with("dagster/"));
        for label in ["dagster/run_id", "dagster/job_name"] {
            if is_dagster && labels.get(label).is_none() {
                return Err(ProxyError::Forbidden(format!(
                    "container create requires label: {label}"
                )));
            }
        }
    }

    Ok(())
}

// ── Pattern matching ───────────────────────────────────────────

/// Match a path against a pattern, in one of three modes:
///
/// - exact — `/containers/json`
/// - prefix, when the pattern ends in `/` — `/exec/` matches `/exec/abc/start`
/// - wildcard, where `*` matches exactly one segment — `/containers/*/json`
fn matches_pattern(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }

    if pattern.ends_with('/') {
        return path.starts_with(pattern);
    }

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
        assert!(f.check("GET", "/networks").is_ok());
        assert!(f.check("HEAD", "/networks/my-net").is_ok());
        assert!(f.check("GET", "/volumes").is_ok());
        assert!(f.check("GET", "/volumes/my-vol").is_ok());
    }

    #[test]
    fn blocks_post_to_allowed_prefix() {
        let f = filter();
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
    fn container_runtime_profile_completes_an_exec() {
        let f = SecurityFilter::for_profile(&SecurityProfile::ContainerRuntime);
        assert!(f.check("GET", "/exec/exec-id/json").is_ok(), "exit status");
        assert!(f.check("POST", "/exec/exec-id/resize").is_ok());
        assert!(
            f.check("POST", "/containers/abc/attach").is_err(),
            "attach stays denied; exec is the supported path"
        );
    }

    #[test]
    fn default_profile_refuses_the_exec_lifecycle() {
        let f = SecurityFilter::new();
        for (method, path) in [
            ("POST", "/containers/abc/exec"),
            ("POST", "/exec/exec-id/start"),
            ("GET", "/exec/exec-id/json"),
            ("POST", "/exec/exec-id/resize"),
        ] {
            assert!(f.check(method, path).is_err(), "{method} {path}");
        }
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
    fn read_only_profile_blocks_mutating_methods() {
        let f = SecurityFilter::for_profile(&SecurityProfile::ReadOnly);
        assert!(f.check("GET", "/info").is_ok());
        assert!(f.check("POST", "/containers/json").is_err());
    }

    #[test]
    fn rule_with_only_methods_matches_every_path() {
        let mut f = filter();
        f.exclude_mut()
            .push(Some(vec!["GET".into()]), Some(Vec::new()));
        assert!(f.check("GET", "/info").is_err());
        assert!(f.check("HEAD", "/info").is_ok());
    }

    #[test]
    fn rule_with_only_endpoints_matches_every_method() {
        let mut f = filter();
        f.exclude_mut()
            .push(Some(Vec::new()), Some(vec!["/info".into()]));
        assert!(f.check("GET", "/info").is_err());
        assert!(f.check("GET", "/version").is_ok());
    }

    #[test]
    fn separate_rules_do_not_intersect_each_other() {
        let mut f = filter();
        f.exclude_mut()
            .push(Some(vec!["GET".into()]), Some(Vec::new()));
        f.exclude_mut()
            .push(Some(Vec::new()), Some(vec!["/version".into()]));

        assert!(f.check("GET", "/info").is_err(), "method-only rule");
        assert!(f.check("HEAD", "/version").is_err(), "endpoint-only rule");
        assert!(f.check("HEAD", "/_ping").is_ok(), "neither rule");
    }

    #[test]
    fn empty_rule_is_inert() {
        let f = filter();
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
    fn leaves_non_version_prefixes_alone() {
        assert_eq!(strip_api_version("/volumes/my-vol"), "/volumes/my-vol");
        assert_eq!(strip_api_version("/v1.55/version"), "/version");
        assert_eq!(strip_api_version("/volumes"), "/volumes");
        assert_eq!(strip_api_version("/v/version"), "/v/version");
    }

    #[test]
    fn resolves_dot_segments_before_matching() {
        let f = filter();
        assert_eq!(normalize_path("/containers/../info").unwrap(), "/info");
        assert_eq!(normalize_path("//info").unwrap(), "/info");
        assert_eq!(normalize_path("/./info").unwrap(), "/info");
        assert!(f.check_request("GET", "/containers/../info", b"").is_ok());
    }

    #[test]
    fn dot_segments_cannot_escape_into_a_denied_endpoint() {
        let f = SecurityFilter::for_profile(&SecurityProfile::ContainerRuntime);
        // Would reach /containers/create, which requires body inspection.
        assert!(
            f.check_request("POST", "/containers/abc/../create", b"{}")
                .is_err()
        );
    }

    #[test]
    fn decodes_percent_encoded_paths() {
        assert_eq!(normalize_path("/%69nfo").unwrap(), "/info");
        assert_eq!(normalize_path("/containers/%2e%2e/info").unwrap(), "/info");
    }

    #[test]
    fn rejects_encoded_path_separators() {
        assert!(normalize_path("/containers%2f..%2finfo").is_err());
        assert!(normalize_path("/containers%5cinfo").is_err());
    }

    #[test]
    fn rejects_malformed_percent_encoding() {
        assert!(normalize_path("/info%").is_err());
        assert!(normalize_path("/info%zz").is_err());
    }

    #[test]
    fn normalizes_root() {
        assert_eq!(normalize_path("/").unwrap(), "/");
        assert_eq!(normalize_path("/..").unwrap(), "/");
    }
}
