#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../../hell-builtins/build.rs"]
#[allow(dead_code)]
mod production_catalog;

fuzz_target!(|data: &[u8]| {
    if let Ok(document) = std::str::from_utf8(data) {
        let _ = production_catalog::fuzz_validate_catalog("claim", document);
    }
});
