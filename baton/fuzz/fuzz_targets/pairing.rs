#![no_main]

use baton_identity::{Pake, PakeRole};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let pake = Pake::start_seeded(PakeRole::Responder, b"pw", b"ch", b"sid", b"", &[7; 64]);
    if let Ok(session) = pake.finish(data, data) {
        let _ = session.check_confirmation(data);
    }
});
