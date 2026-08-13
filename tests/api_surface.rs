//! Checks every shipped endpoint pattern against the real Docker Engine API.
//!
//! A pattern matching no actual endpoint is dead policy: it reads as though it
//! grants or blocks something, and does neither. Typos in a deny list are the
//! dangerous direction, since nothing at runtime reveals them.
//!
//! `tests/fixtures/docker-api-paths.txt` is the path list from
//! `moby/moby:api/swagger.yaml`. To refresh it for a newer API version:
//!
//! ```sh
//! curl -sL https://raw.githubusercontent.com/moby/moby/master/api/swagger.yaml \
//!   | grep -oP '^  \K/\S*(?=:$)' | sort -u
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use docker_socket_proxy::config::SecurityProfile;
use docker_socket_proxy::security::SecurityFilter;

/// Docker's own paths, with `{id}` placeholders reduced to the `*` wildcard our
/// patterns are written with.
fn docker_paths() -> Vec<String> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/docker-api-paths.txt");
    let contents = std::fs::read_to_string(&fixture).expect("api path fixture");

    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.split('/')
                .map(|segment| {
                    if segment.starts_with('{') {
                        "*"
                    } else {
                        segment
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect()
}

/// Whether a policy pattern could ever match a real endpoint, with `*` on
/// either side treated as any single segment.
fn covers_something(pattern: &str, paths: &[String]) -> bool {
    paths.iter().any(|path| {
        if pattern.ends_with('/') {
            return path.starts_with(pattern) || format!("{path}/") == pattern;
        }
        let pattern_segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
        let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        pattern_segments.len() == path_segments.len()
            && pattern_segments
                .iter()
                .zip(&path_segments)
                .all(|(a, b)| *a == "*" || b == a)
    })
}

#[test]
fn every_shipped_pattern_matches_a_real_endpoint() {
    let paths = docker_paths();
    assert!(paths.len() > 50, "fixture looks truncated: {}", paths.len());

    let mut dead = Vec::new();
    for profile in [
        SecurityProfile::Default,
        SecurityProfile::ReadOnly,
        SecurityProfile::ContainerRuntime,
        SecurityProfile::None,
    ] {
        let filter = SecurityFilter::for_profile(&profile);
        for pattern in filter.endpoint_patterns() {
            if !covers_something(pattern, &paths) {
                dead.push(format!("{profile:?}: {pattern}"));
            }
        }
    }

    assert!(
        dead.is_empty(),
        "patterns matching no Docker endpoint: {dead:#?}"
    );
}

#[test]
fn the_matcher_itself_distinguishes_real_from_invented() {
    let paths = docker_paths();
    assert!(covers_something("/containers/*/json", &paths));
    assert!(covers_something("/containers/", &paths));
    assert!(covers_something("/_ping", &paths));
    assert!(!covers_something("/containers/*/delete", &paths));
    assert!(!covers_something("/containers/*/teleport", &paths));
}
