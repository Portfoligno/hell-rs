#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hell_ci::fuzz_admit_provenance_record(data);
});
