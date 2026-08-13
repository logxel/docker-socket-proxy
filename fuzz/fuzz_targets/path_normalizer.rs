//! Fuzzes the request-path decision surface: percent-decoding, dot-segment
//! removal, API-version stripping, and pattern matching. This is the primary
//! bypass surface -- a path that normalizes differently from how the matcher
//! sees it could slip past a deny rule, so the whole normalized pipeline is
//! driven here rather than just `check`.

// The libFuzzer runtime provides `main`; this binary has no entry point of its
// own, only the exported `LLVMFuzzerTestOneInput` shim.
#![no_main]

use docker_socket_proxy::security::{BodyRule, SecurityFilter};
use libfuzzer_sys::fuzz_target;

/// Split `data` at the first NUL byte. A raw fuzz input has no inherent
/// structure; NUL is a delimiter no UTF-8 path can contain, so it never costs
/// coverage the way a printable byte would.
fn split_once(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match data.iter().position(|&b| b == 0) {
        Some(i) => (data[..i].to_vec(), data[i + 1..].to_vec()),
        None => (data.to_vec(), Vec::new()),
    }
}

fuzz_target!(|data: &[u8]| {
    let (head, pattern) = split_once(data);
    let (method, path) = split_once(&head);

    // Invalid UTF-8 is lossy-mapped rather than made fatal: the normalizer and
    // matcher must tolerate arbitrary byte strings without panicking.
    let method = String::from_utf8_lossy(&method);
    let path = String::from_utf8_lossy(&path);
    let pattern = String::from_utf8_lossy(&pattern);

    let mut filter = SecurityFilter::deny_all();

    // Inject input-derived rules through every public mutator so the decision
    // combines allow/deny/exclude surface rather than a fixed profile.
    let methods = Some(vec![method.to_string()]);
    let endpoints = Some(vec![pattern.to_string()]);
    filter
        .allow_mut()
        .push(methods.clone(), endpoints.clone());
    filter.deny_mut().push(methods.clone(), endpoints.clone());
    filter
        .exclude_mut()
        .push(methods.clone(), endpoints.clone());

    // The raw decision surface (no normalization).
    let _ = filter.check(&method, &path);

    // Body inspection is keyed on whether the effective policy permits
    // `POST /containers/create`, so `check_head` may also yield
    // `BodyRule::ContainerCreate` when the injected allow rule opens it. Both
    // outcomes must route through `check_request` without panicking.
    match filter.check_head(&method, &path) {
        Ok(BodyRule::None) => {
            assert!(
                filter.check_request(&method, &path, b"{}").is_ok(),
                "check_request must agree with check_head when no body rule applies"
            );
        }
        _ => {
            let _ = filter.check_request(&method, &path, b"{}");
        }
    }

    // Exercise the same rules against the pattern and the normalized path to
    // cover exact/prefix/wildcard matching under arbitrary inputs.
    let _ = filter.check(&method, &pattern);
    let _ = filter.check_request(&method, &pattern, b"{}");
});
