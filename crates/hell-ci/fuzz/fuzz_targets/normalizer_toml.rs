#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(document) = std::str::from_utf8(data) {
        let _ = hell_builtins::fuzz_validate_catalog("normalizer", document);
    }
});
