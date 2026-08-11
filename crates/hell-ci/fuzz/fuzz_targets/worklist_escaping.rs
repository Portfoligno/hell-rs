#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/worklist_encoding.rs"]
mod worklist_encoding;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        let _ = worklist_encoding::html_escape(value);
        let _ = worklist_encoding::csv_field(value);
        let _ = worklist_encoding::json_field(value);
    }
});
