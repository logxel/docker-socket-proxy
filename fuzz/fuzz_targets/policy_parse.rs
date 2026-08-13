//! Fuzzes TOML policy parsing and its application through the public mutators.
//! Parse errors are expected fuzz input and are ignored; the surface under test
//! is the merge of a parsed document into a filter and the decisions it yields.

// The libFuzzer runtime provides `main`; this binary has no entry point of its
// own, only the exported `LLVMFuzzerTestOneInput` shim.
#![no_main]

use docker_socket_proxy::policy::PolicyDocument;
use docker_socket_proxy::security::SecurityFilter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TOML is text, so invalid UTF-8 or malformed documents are ordinary fuzz
    // input -- a parse failure, not a crash. The `let-else` early-returns on it.
    let Some(document) = std::str::from_utf8(data)
        .ok()
        .and_then(|text| toml::from_str::<PolicyDocument>(text).ok())
    else {
        return;
    };

    let mut filter = SecurityFilter::deny_all();

    // Mirror PolicyLoader::apply_document, but through the public surface only.
    if let Some(set) = document.allow {
        filter.allow_mut().push(set.methods, set.endpoints);
    }
    if let Some(set) = document.include {
        filter.allow_mut().push(set.methods, set.endpoints);
    }
    if let Some(set) = document.deny {
        filter.deny_mut().push(set.methods, set.endpoints);
    }
    if let Some(set) = document.exclude {
        filter.exclude_mut().push(set.methods, set.endpoints);
    }

    // Representative decisions over the merged rules, including a normalized
    // version-prefixed path so the pipeline, not just the matcher, runs.
    let _ = filter.check("GET", "/info");
    let _ = filter.check("POST", "/containers/create");
    let _ = filter.check_request("GET", "/v1.55/version", b"");
});
