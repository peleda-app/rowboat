#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_mail_jmap::fuzzing;

fuzz_target!(|data: &[u8]| {
    fuzzing::session(data);
    fuzzing::response(data);
    fuzzing::cursor(data);
});
