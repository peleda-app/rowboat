#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_pim_jmap::fuzzing;

fuzz_target!(|data: &[u8]| {
    fuzzing::session(data);
    fuzzing::response(data);
    fuzzing::event(data);
    fuzzing::cursor(data);
});
