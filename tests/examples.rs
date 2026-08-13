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

#[test]
fn every_example_parses() {
    let mut count = 0;
    for entry in std::fs::read_dir(examples_dir()).expect("examples directory") {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        load(&name, SecurityProfile::Default);
        count += 1;
    }
    assert!(count >= 3, "expected the shipped examples, found {count}");
}

#[test]
fn container_runtime_example_permits_the_launcher_workflow() {
    let filter = load("container-runtime.toml", SecurityProfile::ContainerRuntime);
    assert!(filter.check("POST", "/containers/create").is_ok());
    assert!(filter.check("POST", "/containers/abc/start").is_ok());
    assert!(filter.check("GET", "/containers/abc/logs").is_ok());
}

#[test]
fn section_example_grants_reads_without_opening_writes() {
    let filter = load("sections-read-only.yaml", SecurityProfile::Default);

    for path in ["/containers/json", "/images/json", "/networks", "/volumes"] {
        assert!(filter.check("GET", path).is_ok(), "{path}");
    }
    assert!(filter.check("POST", "/containers/create").is_err());
    assert!(filter.check("GET", "/secrets").is_err());
    assert!(
        filter.check("GET", "/containers/abc/top").is_err(),
        "the exclusion outranks the prefix grant"
    );
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
