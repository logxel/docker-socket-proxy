//! Policy administration point: builds a [`SecurityFilter`] from a profile, an
//! optional TOML or YAML file, and the environment.
//!
//! All policy I/O lives here so that [`crate::security`] stays pure and can be
//! tested without a filesystem or environment.
//!
//! # Contract
//! - **Pre-condition**: A configured allowlist path must exist and parse.
//! - **Post-condition**: The returned filter carries the profile defaults with
//!   file and environment rules merged over them.

use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;

use serde::Deserialize;

use crate::config::SecurityProfile;
use crate::error::ProxyError;
use crate::security::SecurityFilter;

/// A policy document, in either TOML or YAML.
///
/// `allow`/`deny` are aliases kept for compatibility with the terminology other
/// Docker socket proxies use; `include`/`exclude` are the explicit names.
#[derive(Debug, Default, Deserialize)]
pub struct PolicyDocument {
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

/// Builds a filter from a profile plus external policy sources.
pub struct PolicyLoader<'a> {
    file: Option<&'a Path>,
    profile: &'a SecurityProfile,
}

impl<'a> PolicyLoader<'a> {
    pub fn new(file: Option<&'a Path>, profile: &'a SecurityProfile) -> Self {
        Self { file, profile }
    }

    /// Read the configured sources and produce a filter.
    ///
    /// A configured file that cannot be read or parsed is fatal. Falling back to
    /// defaults would silently apply a policy the operator did not write.
    pub fn load(&self) -> Result<SecurityFilter, ProxyError> {
        let document = match self.file {
            None => PolicyDocument::default(),
            Some(path) => {
                let contents = std::fs::read_to_string(path).map_err(|e| {
                    ProxyError::Config(format!("cannot read allowlist {}: {e}", path.display()))
                })?;
                parse_document(path, &contents)?
            }
        };

        let env: HashMap<String, String> = std::env::vars().collect();
        let mut filter = match compatibility_filter(&env, self.profile)? {
            Some(filter) => filter,
            None => SecurityFilter::for_profile(self.profile),
        };
        apply_document(&mut filter, document);
        apply_environment(&mut filter, &env);
        Ok(filter)
    }
}

// ── Compatibility with section-variable socket proxies ─────────

/// Docker API sections, keyed by the variable other socket proxies grant them
/// with. Order is immaterial; each is an independent grant.
const COMPAT_SECTIONS: &[(&str, &str)] = &[
    ("AUTH", "/auth"),
    ("BUILD", "/build"),
    ("COMMIT", "/commit"),
    ("CONFIGS", "/configs"),
    ("CONTAINERS", "/containers"),
    ("DISTRIBUTION", "/distribution"),
    ("EVENTS", "/events"),
    ("EXEC", "/exec"),
    ("GRPC", "/grpc"),
    ("IMAGES", "/images"),
    ("INFO", "/info"),
    ("NETWORKS", "/networks"),
    ("NODES", "/nodes"),
    ("PING", "/_ping"),
    ("PLUGINS", "/plugins"),
    ("SECRETS", "/secrets"),
    ("SERVICES", "/services"),
    ("SESSION", "/session"),
    ("SWARM", "/swarm"),
    ("SYSTEM", "/system"),
    ("TASKS", "/tasks"),
    ("VERSION", "/version"),
    ("VOLUMES", "/volumes"),
];

/// Container operations granted individually, without opening `/containers`.
const COMPAT_OPERATIONS: &[(&str, &[&str])] = &[
    (
        "ALLOW_RESTARTS",
        &[
            "/containers/*/stop",
            "/containers/*/restart",
            "/containers/*/kill",
        ],
    ),
    ("ALLOW_START", &["/containers/*/start"]),
    ("ALLOW_STOP", &["/containers/*/stop"]),
    ("ALLOW_PAUSE", &["/containers/*/pause"]),
    ("ALLOW_UNPAUSE", &["/containers/*/unpause"]),
];

/// Sections granted unless the operator turns them off, as in the original.
const COMPAT_DEFAULT_ON: &[&str] = &["EVENTS", "PING", "VERSION"];

/// Build a filter from the section variables Tecnativa's socket proxy uses, or
/// `None` if the operator set none of them.
///
/// These variables describe a whole policy rather than a modifier, so they
/// replace the profile defaults instead of layering over them — otherwise
/// `CONTAINERS=1` would also grant everything the profile happened to allow.
/// A profile selected alongside them is therefore a contradiction, and refused.
///
/// `POST=0` restricts the grants to `GET` and `HEAD`; `POST=1` opens them to
/// every method, since the original's gate is the only thing standing between
/// a granted section and the daemon.
fn compatibility_filter(
    env: &HashMap<String, String>,
    profile: &SecurityProfile,
) -> Result<Option<SecurityFilter>, ProxyError> {
    let names: Vec<&str> = COMPAT_SECTIONS
        .iter()
        .map(|(name, _)| *name)
        .chain(COMPAT_OPERATIONS.iter().map(|(name, _)| *name))
        .chain(std::iter::once("POST"))
        .filter(|name| env.contains_key(*name))
        .collect();

    if names.is_empty() {
        return Ok(None);
    }
    if !matches!(profile, SecurityProfile::Default) {
        return Err(ProxyError::Config(format!(
            "compatibility variables ({}) define a complete policy and cannot be \
             combined with the {profile:?} profile: pick one",
            names.join(", ")
        )));
    }

    let granted = |name: &str| match env.get(name) {
        Some(value) => is_enabled(value),
        None => COMPAT_DEFAULT_ON.contains(&name),
    };

    let mut endpoints = Vec::new();
    for (name, section) in COMPAT_SECTIONS {
        if granted(name) {
            // Both forms, because our patterns take a trailing `/` to mean
            // prefix while a bare path is exact.
            endpoints.push((*section).to_owned());
            endpoints.push(format!("{section}/"));
        }
    }
    for (name, paths) in COMPAT_OPERATIONS {
        if granted(name) {
            endpoints.extend(paths.iter().map(|path| (*path).to_owned()));
        }
    }

    // An empty method list is a wildcard, which is what lifting the gate means.
    let methods = if granted("POST") {
        Vec::new()
    } else {
        vec!["GET".to_owned(), "HEAD".to_owned()]
    };

    let mut filter = SecurityFilter::deny_all();
    filter.allow_mut().extend(Some(methods), Some(endpoints));
    Ok(Some(filter))
}

/// Read a variable the way the shell-style proxies do: only an affirmative
/// spelling enables, so a typo fails closed.
fn is_enabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Parse a policy document, choosing the format from the file extension.
///
/// The extension is the operator's declaration of intent. An unrecognised one is
/// refused rather than guessed at, so a mistyped name cannot quietly parse as
/// the wrong format and yield a policy nobody wrote.
fn parse_document(path: &Path, contents: &str) -> Result<PolicyDocument, ProxyError> {
    let invalid =
        |e: &dyn Display| ProxyError::Config(format!("invalid allowlist {}: {e}", path.display()));

    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        #[cfg(feature = "yaml")]
        Some("yaml" | "yml") => serde_saphyr::from_str(contents).map_err(|e| invalid(&e)),
        #[cfg(not(feature = "yaml"))]
        Some("yaml" | "yml") => Err(ProxyError::Config(format!(
            "cannot read {}: this build has no YAML support (built without the \
             \"yaml\" feature); convert the file to TOML or use a default build",
            path.display()
        ))),
        Some("toml") | None => toml::from_str(contents).map_err(|e| invalid(&e)),
        Some(other) => Err(ProxyError::Config(format!(
            "unsupported allowlist format {other:?} for {}: expected toml, yaml, or yml",
            path.display()
        ))),
    }
}

fn apply_document(filter: &mut SecurityFilter, document: PolicyDocument) {
    for set in [document.allow, document.include].into_iter().flatten() {
        filter.allow_mut().extend(set.methods, set.endpoints);
    }
    if let Some(set) = document.deny {
        filter.deny_mut().push(set.methods, set.endpoints);
    }
    if let Some(set) = document.exclude {
        filter.exclude_mut().push(set.methods, set.endpoints);
    }
}

fn apply_environment(filter: &mut SecurityFilter, env: &HashMap<String, String>) {
    let list = |name: &str| env.get(name).map(|raw| split_list(raw));

    for prefix in ["ALLOW", "INCLUDE"] {
        filter.allow_mut().extend(
            list(&format!("DOCKER_PROXY_{prefix}_METHODS")),
            list(&format!("DOCKER_PROXY_{prefix}_ENDPOINTS")),
        );
    }
    filter.deny_mut().push(
        list("DOCKER_PROXY_DENY_METHODS"),
        list("DOCKER_PROXY_DENY_ENDPOINTS"),
    );
    filter.exclude_mut().push(
        list("DOCKER_PROXY_EXCLUDE_METHODS"),
        list("DOCKER_PROXY_EXCLUDE_ENDPOINTS"),
    );
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn from_toml(toml: &str, profile: &SecurityProfile) -> SecurityFilter {
        let mut filter = SecurityFilter::for_profile(profile);
        apply_document(&mut filter, toml::from_str(toml).unwrap());
        filter
    }

    #[test]
    fn merges_allow_rules_with_profile_defaults() {
        let filter = from_toml(
            r#"
[allow]
endpoints = ["/_ping"]
methods = ["GET"]

[deny]
endpoints = []
methods = []
"#,
            &SecurityProfile::Default,
        );

        assert!(filter.check("GET", "/_ping").is_ok());
        assert!(filter.check("GET", "/containers/json").is_ok());
        assert!(filter.check("GET", "/info").is_ok());
    }

    #[test]
    fn include_adds_and_exclude_removes() {
        let filter = from_toml(
            r#"
[include]
endpoints = ["/images/*/json"]
methods = ["GET"]

[exclude]
endpoints = ["/containers/*/logs"]
"#,
            &SecurityProfile::Default,
        );

        assert!(filter.check("GET", "/images/abc/json").is_ok());
        assert!(filter.check("GET", "/containers/abc/logs").is_err());
    }

    #[test]
    fn environment_lists_merge_with_profile() {
        let mut filter = SecurityFilter::for_profile(&SecurityProfile::Default);
        let env = HashMap::from([
            (
                "DOCKER_PROXY_ALLOW_ENDPOINTS".to_owned(),
                "/images/search".to_owned(),
            ),
            ("DOCKER_PROXY_ALLOW_METHODS".to_owned(), "POST".to_owned()),
            (
                "DOCKER_PROXY_EXCLUDE_ENDPOINTS".to_owned(),
                "/info".to_owned(),
            ),
        ]);

        apply_environment(&mut filter, &env);

        assert!(filter.check("POST", "/images/search").is_ok());
        assert!(filter.check("GET", "/info").is_err());
        assert!(filter.check("GET", "/version").is_ok());
    }

    #[test]
    fn missing_allowlist_file_is_fatal() {
        let profile = SecurityProfile::Default;
        let path = Path::new("/nonexistent/allowlist.toml");
        assert!(PolicyLoader::new(Some(path), &profile).load().is_err());
    }

    #[cfg(not(feature = "yaml"))]
    #[test]
    fn without_the_feature_yaml_is_refused_by_name() {
        let error = parse_document(Path::new("p.yaml"), "include:\n").unwrap_err();
        assert!(error.to_string().contains("no YAML support"), "{error}");
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn parses_the_same_policy_from_toml_and_yaml() {
        let toml_doc = parse_document(
            Path::new("p.toml"),
            r#"
[include]
endpoints = ["/images/*/json"]
methods = ["GET"]
"#,
        )
        .unwrap();
        let yaml_doc = parse_document(
            Path::new("p.yaml"),
            r#"
include:
  endpoints:
    - "/images/*/json"
  methods:
    - GET
"#,
        )
        .unwrap();

        for document in [toml_doc, yaml_doc] {
            let mut filter = SecurityFilter::for_profile(&SecurityProfile::Default);
            apply_document(&mut filter, document);
            assert!(filter.check("GET", "/images/abc/json").is_ok());
        }
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn accepts_the_yml_spelling() {
        assert!(
            parse_document(Path::new("p.yml"), "exclude:\n  endpoints:\n    - /info\n").is_ok()
        );
    }

    #[test]
    fn refuses_an_unrecognised_extension_rather_than_guessing() {
        let error = parse_document(Path::new("policy.json"), "{}").unwrap_err();
        assert!(
            error.to_string().contains("unsupported allowlist format"),
            "got: {error}"
        );
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn malformed_yaml_is_an_error_not_an_empty_policy() {
        assert!(parse_document(Path::new("p.yaml"), "include: [unclosed").is_err());
    }

    fn compat(vars: &[(&str, &str)]) -> SecurityFilter {
        let env = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        compatibility_filter(&env, &SecurityProfile::Default)
            .unwrap()
            .expect("variables were set")
    }

    #[test]
    fn compatibility_variables_grant_only_their_own_sections() {
        let filter = compat(&[("CONTAINERS", "1")]);
        assert!(filter.check("GET", "/containers/json").is_ok());
        assert!(filter.check("GET", "/containers/abc/logs").is_ok());
        assert!(
            filter.check("GET", "/info").is_err(),
            "the default profile's endpoints must not leak in"
        );
    }

    #[test]
    fn post_gates_writes_but_not_head() {
        let closed = compat(&[("CONTAINERS", "1")]);
        assert!(closed.check("POST", "/containers/create").is_err());
        assert!(closed.check("DELETE", "/containers/abc").is_err());
        assert!(
            closed.check("HEAD", "/containers/json").is_ok(),
            "the original's gate reads HEAD as a GET"
        );

        let open = compat(&[("CONTAINERS", "1"), ("POST", "1")]);
        assert!(open.check("POST", "/containers/create").is_ok());
        assert!(open.check("DELETE", "/containers/abc").is_ok());
    }

    #[test]
    fn events_ping_and_version_are_granted_unless_turned_off() {
        let filter = compat(&[("CONTAINERS", "1")]);
        for path in ["/events", "/_ping", "/version"] {
            assert!(filter.check("GET", path).is_ok(), "{path}");
        }
        assert!(
            compat(&[("PING", "0")]).check("GET", "/_ping").is_err(),
            "an explicit 0 still turns one off"
        );
    }

    #[test]
    fn zero_grants_nothing_and_typos_fail_closed() {
        for value in ["0", "false", "", "enabled", "sure"] {
            let filter = compat(&[("SECRETS", value), ("PING", "1")]);
            assert!(filter.check("GET", "/secrets").is_err(), "SECRETS={value}");
            assert!(filter.check("GET", "/_ping").is_ok());
        }
    }

    #[test]
    fn individual_operations_grant_without_opening_containers() {
        let filter = compat(&[("ALLOW_START", "1"), ("POST", "1")]);
        assert!(filter.check("POST", "/containers/abc/start").is_ok());
        assert!(filter.check("POST", "/containers/abc/stop").is_err());
        assert!(filter.check("GET", "/containers/json").is_err());
    }

    #[test]
    fn compatibility_variables_conflict_with_an_explicit_profile() {
        let env = HashMap::from([("CONTAINERS".to_owned(), "1".to_owned())]);
        let error = compatibility_filter(&env, &SecurityProfile::ReadOnly).unwrap_err();
        assert!(error.to_string().contains("cannot be combined"), "{error}");
    }

    #[test]
    fn absent_compatibility_variables_leave_the_profile_alone() {
        let env = HashMap::from([("PATH".to_owned(), "/usr/bin".to_owned())]);
        assert!(
            compatibility_filter(&env, &SecurityProfile::ContainerRuntime)
                .unwrap()
                .is_none()
        );
    }

    /// The `KEY=value` pairs from an example env file, comments skipped.
    fn env_file(name: &str) -> HashMap<String, String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(name);
        let contents = std::fs::read_to_string(&path).expect("example env file");

        contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
            .collect()
    }

    #[test]
    fn env_example_produces_the_policy_it_describes() {
        let env = env_file("env-modifiers.env");
        assert_eq!(
            env.get("DOCKER_PROXY_PROFILE").map(String::as_str),
            Some("read-only")
        );

        let mut filter = SecurityFilter::for_profile(&SecurityProfile::ReadOnly);
        apply_environment(&mut filter, &env);

        assert!(filter.check("GET", "/images/abc/json").is_ok());
        assert!(filter.check("GET", "/images/abc/history").is_ok());
        assert!(filter.check("GET", "/version").is_ok());

        assert!(filter.check("GET", "/containers/abc/logs").is_err());
        assert!(filter.check("GET", "/containers/abc/top").is_err());
        assert!(
            filter.check("POST", "/containers/create").is_err(),
            "read-only refuses writes whatever else is set"
        );
    }

    #[test]
    fn splits_and_trims_environment_lists() {
        assert_eq!(split_list(" /a , /b ,, "), vec!["/a", "/b"]);
        assert!(split_list("").is_empty());
    }
}
