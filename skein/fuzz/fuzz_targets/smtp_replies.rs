#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_send_smtp::fuzzing;

fuzz_target!(|data: &[u8]| {
    fuzzing::replies(data);
});
