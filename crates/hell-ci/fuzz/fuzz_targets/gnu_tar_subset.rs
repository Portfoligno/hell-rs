#![no_main]

use hell_ci::fuzz::{Target, exercise};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = exercise(Target::GnuTarSubset, data);
});
