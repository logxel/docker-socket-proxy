//! Checks every shipped endpoint pattern against the real Docker Engine API.
//!
//! A pattern matching no actual endpoint is dead policy: it reads as though it
//! grants or blocks something, and does neither. Typos in a deny list are the
//! dangerous direction, since nothing at runtime reveals them.
//!
//! Operator-supplied rules are checked by the same matcher at load time, but
//! only warned about. The patterns we ship have no such excuse.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use docker_socket_proxy::config::SecurityProfile;
use docker_socket_proxy::docker_api;
use docker_socket_proxy::security::SecurityFilter;

#[test]
fn every_shipped_pattern_matches_a_real_endpoint() {
    assert!(
        docker_api::PATHS.len() > 50,
        "path list looks truncated: {}",
        docker_api::PATHS.len()
    );

    let mut dead = Vec::new();
    for profile in [
        SecurityProfile::Default,
        SecurityProfile::ReadOnly,
        SecurityProfile::ContainerRuntime,
        SecurityProfile::None,
    ] {
        let filter = SecurityFilter::for_profile(&profile);
        for pattern in filter.endpoint_patterns() {
            if !docker_api::matches_known_path(pattern) {
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
fn the_matcher_distinguishes_real_endpoints_from_invented_ones() {
    assert!(docker_api::matches_known_path("/containers/*/json"));
    assert!(docker_api::matches_known_path("/containers/abc/json"));
    assert!(docker_api::matches_known_path("/containers/"));
    assert!(docker_api::matches_known_path("/_ping"));
    assert!(!docker_api::matches_known_path("/containers/*/delete"));
    assert!(!docker_api::matches_known_path("/containres/json"));
    assert!(!docker_api::matches_known_path("/containers/*/teleport"));
}

#[test]
fn methods_are_recognised_case_sensitively() {
    assert!(docker_api::is_known_method("GET"));
    assert!(docker_api::is_known_method("DELETE"));
    assert!(
        !docker_api::is_known_method("get"),
        "a lowercase spelling would match no request, so it is not known"
    );
    assert!(!docker_api::is_known_method("GTE"));
}
