#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_storage::fuzzing;

fuzz_target!(|data: &[u8]| {
    fuzzing::head(data);
    fuzzing::verify(data);
});
