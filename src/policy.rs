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

        let mut filter = SecurityFilter::for_profile(self.profile);
        apply_document(&mut filter, document);
        apply_environment(&mut filter, &std::env::vars().collect());
        Ok(filter)
    }
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
        Some("yaml" | "yml") => serde_saphyr::from_str(contents).map_err(|e| invalid(&e)),
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
        filter.deny_mut().extend(set.methods, set.endpoints);
    }
    if let Some(set) = document.exclude {
        filter.exclude_mut().extend(set.methods, set.endpoints);
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
    filter.deny_mut().extend(
        list("DOCKER_PROXY_DENY_METHODS"),
        list("DOCKER_PROXY_DENY_ENDPOINTS"),
    );
    filter.exclude_mut().extend(
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

    #[test]
    fn malformed_yaml_is_an_error_not_an_empty_policy() {
        assert!(parse_document(Path::new("p.yaml"), "include: [unclosed").is_err());
    }

    #[test]
    fn splits_and_trims_environment_lists() {
        assert_eq!(split_list(" /a , /b ,, "), vec!["/a", "/b"]);
        assert!(split_list("").is_empty());
    }
}
