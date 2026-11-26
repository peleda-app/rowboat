#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_mail_imap::fuzzing;

fuzz_target!(|data: &[u8]| {
    fuzzing::probe(data);
});
