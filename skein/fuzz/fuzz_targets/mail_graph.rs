#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_mail_graph::fuzzing;

fuzz_target!(|data: &[u8]| {
    fuzzing::page_of(data);
    fuzzing::date(data);
    fuzzing::cursor(data);
});
