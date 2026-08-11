#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hell_testkit::verify_observation_bundle_manifest_bytes(data);
});
