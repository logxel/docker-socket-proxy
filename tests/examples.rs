//! Every file in `examples/` is loaded and its documented behaviour asserted,
//! so a shipped example cannot drift out of step with the parser or the policy
//! engine without a test failing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use docker_socket_proxy::config::SecurityProfile;
use docker_socket_proxy::policy::PolicyLoader;
use docker_socket_proxy::security::SecurityFilter;

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn load(name: &str, profile: SecurityProfile) -> SecurityFilter {
    PolicyLoader::new(Some(&examples_dir().join(name)), &profile)
        .load()
        .unwrap_or_else(|error| panic!("examples/{name}: {error}"))
}

/// Allowlist files only, and YAML only where the feature is built in, so a
/// minimal build skips a format it deliberately excludes.
fn parseable(path: &Path) -> bool {
    let extension = path.extension().and_then(|e| e.to_str());
    matches!(extension, Some("toml"))
        || (matches!(extension, Some("yaml" | "yml")) && cfg!(feature = "yaml"))
}

#[test]
fn every_example_parses() {
    let mut count = 0;
    for entry in std::fs::read_dir(examples_dir()).expect("examples directory") {
        let path = entry.unwrap().path();
        if !path.is_file() || !parseable(&path) {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        load(&name, SecurityProfile::Default);
        count += 1;
    }
    assert!(count >= 2, "expected the shipped examples, found {count}");
}

#[test]
fn container_runtime_example_permits_the_launcher_workflow() {
    let filter = load("container-runtime.toml", SecurityProfile::ContainerRuntime);
    assert!(filter.check("POST", "/containers/create").is_ok());
    assert!(filter.check("POST", "/containers/abc/start").is_ok());
    assert!(filter.check("GET", "/containers/abc/logs").is_ok());
}

#[cfg(feature = "yaml")]
#[test]
fn section_example_grants_reads_without_opening_writes() {
    let filter = load("sections-read-only.yaml", SecurityProfile::None);

    for path in ["/containers/json", "/images/json", "/networks", "/volumes"] {
        assert!(filter.check("GET", path).is_ok(), "{path}");
    }
    assert!(filter.check("POST", "/containers/create").is_err());
    assert!(filter.check("GET", "/secrets").is_err());
    assert!(
        filter.check("GET", "/info").is_err(),
        "no profile grants arrive under `none`"
    );
    assert!(
        filter.check("GET", "/containers/abc/top").is_err(),
        "the exclusion outranks the prefix grant"
    );
}

/// The claim this example makes is equivalence, so it is checked against the
/// section variables it replaces rather than against a list written by hand.
#[test]
fn tecnativa_equivalent_example_matches_the_variables_it_replaces() {
    let file = load("tecnativa-equivalent.toml", SecurityProfile::None);

    for (method, path) in [
        ("GET", "/containers/json"),
        ("POST", "/containers/create"),
        ("DELETE", "/containers/abc"),
        ("GET", "/images/json"),
        ("POST", "/images/create"),
        ("GET", "/_ping"),
        ("GET", "/version"),
        ("GET", "/events"),
    ] {
        assert!(file.check(method, path).is_ok(), "{method} {path}");
    }

    for (method, path) in [
        ("GET", "/secrets"),
        ("GET", "/info"),
        ("GET", "/volumes"),
        ("POST", "/build"),
        ("GET", "/swarm"),
    ] {
        assert!(file.check(method, path).is_err(), "{method} {path}");
    }
}

#[test]
fn create_inspection_example_rejects_the_bodies_it_documents() {
    let filter = load("create-inspection.toml", SecurityProfile::ContainerRuntime);
    let create = |body: &str| filter.check_request("POST", "/containers/create", body.as_bytes());

    assert!(create(r#"{"Image":"worker:1","Cmd":["run"]}"#).is_ok());

    for body in [
        r#"{"Image":"x","Cmd":[],"Privileged":true}"#,
        r#"{"Image":"x","Cmd":[],"CapAdd":["SYS_ADMIN"]}"#,
        r#"{"Image":"x","Cmd":[],"PidMode":"host"}"#,
        r#"{"Image":"x"}"#,
    ] {
        assert!(create(body).is_err(), "{body}");
    }

    for path in ["/build", "/commit", "/containers/abc/archive"] {
        assert!(filter.check("POST", path).is_err(), "{path}");
    }
}
