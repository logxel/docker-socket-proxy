//! The Docker Engine API surface, for validating policy against reality.
//!
//! A rule that matches no real endpoint is invisible at runtime: it reads as
//! policy and does nothing. In an `exclude` rule that means a resource the
//! operator believes is blocked stays reachable.
//!
//! The list is a snapshot, so an unknown path is reported rather than refused —
//! a newer daemon may serve endpoints this build has never heard of.
//!
//! Regenerate for a newer API version with the following, rewriting `{param}`
//! to `*` and keeping the routes marked below as undocumented — the
//! specification does not list every path the daemon answers.
//!
//! ```sh
//! curl -sL https://raw.githubusercontent.com/moby/moby/master/api/swagger.yaml \
//!   | grep -oP '^  \K/\S*(?=:$)' | sort -u
//! ```

/// The API version [`PATHS`] was taken from.
pub const VERSION: &str = "1.55";

/// Every path the Docker Engine API serves, with `{id}` placeholders written
/// as the `*` wildcard that policy patterns use.
pub const PATHS: &[&str] = &[
    "/_ping",
    "/auth",
    "/build",
    "/build/prune",
    "/commit",
    "/configs",
    "/configs/*",
    "/configs/*/update",
    "/configs/create",
    "/containers/*",
    "/containers/*/archive",
    "/containers/*/attach",
    "/containers/*/attach/ws",
    "/containers/*/changes",
    "/containers/*/exec",
    "/containers/*/export",
    "/containers/*/json",
    "/containers/*/kill",
    "/containers/*/logs",
    "/containers/*/pause",
    "/containers/*/rename",
    "/containers/*/resize",
    "/containers/*/restart",
    "/containers/*/start",
    "/containers/*/stats",
    "/containers/*/stop",
    "/containers/*/top",
    "/containers/*/unpause",
    "/containers/*/update",
    "/containers/*/wait",
    "/containers/create",
    "/containers/json",
    "/containers/prune",
    "/distribution/*/json",
    "/events",
    "/exec/*/json",
    "/exec/*/resize",
    "/exec/*/start",
    "/images/*",
    "/images/*/attestations",
    "/images/*/get",
    "/images/*/history",
    "/images/*/json",
    "/images/*/push",
    "/images/*/tag",
    "/images/create",
    "/images/get",
    "/images/json",
    "/images/load",
    "/images/prune",
    "/images/search",
    "/info",
    "/networks",
    "/networks/*",
    "/networks/*/connect",
    "/networks/*/disconnect",
    "/networks/create",
    "/networks/prune",
    "/nodes",
    "/nodes/*",
    "/nodes/*/update",
    "/plugins",
    "/plugins/*",
    "/plugins/*/disable",
    "/plugins/*/enable",
    "/plugins/*/json",
    "/plugins/*/push",
    "/plugins/*/set",
    "/plugins/*/upgrade",
    "/plugins/create",
    "/plugins/privileges",
    "/plugins/pull",
    "/secrets",
    "/secrets/*",
    "/secrets/*/update",
    "/secrets/create",
    "/services",
    "/services/*",
    "/services/*/logs",
    "/services/*/update",
    "/services/create",
    "/session",
    "/swarm",
    "/swarm/init",
    "/swarm/join",
    "/swarm/leave",
    "/swarm/unlock",
    "/swarm/unlockkey",
    "/swarm/update",
    "/system/df",
    "/tasks",
    "/tasks/*",
    "/tasks/*/logs",
    "/version",
    "/volumes",
    "/volumes/*",
    "/volumes/create",
    "/volumes/prune",
    // Served by the daemon for BuildKit sessions but absent from
    // swagger.yaml, so regeneration drops it unless it is re-added.
    "/grpc",
];

/// Methods the Docker Engine API responds to.
pub const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "DELETE"];

/// Whether a policy pattern could ever match a real endpoint.
///
/// Wildcards on either side match any single segment, since [`PATHS`] carries
/// `*` where Docker's specification names a parameter and a policy may name a
/// concrete value there instead.
pub fn matches_known_path(pattern: &str) -> bool {
    PATHS.iter().any(|path| {
        if pattern.ends_with('/') {
            return path.starts_with(pattern) || format!("{path}/") == pattern;
        }
        let pattern_segments = pattern.split('/').filter(|s| !s.is_empty());
        let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        pattern_segments.clone().count() == path_segments.len()
            && pattern_segments
                .zip(&path_segments)
                .all(|(a, b)| a == "*" || b == &a || *b == "*")
    })
}

/// Whether a method is one the Docker Engine API uses.
///
/// Case-sensitive, because HTTP methods are (RFC 9110 §9.1) and a lowercase
/// spelling in a policy would match no request.
pub fn is_known_method(method: &str) -> bool {
    METHODS.contains(&method)
}
