#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| skein_pim_dav::fuzzing::multistatus(data));
