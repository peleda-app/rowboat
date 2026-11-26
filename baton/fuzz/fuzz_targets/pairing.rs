#![no_main]

use baton_identity::{Invite, JoinRequest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Invite::from_bytes(data);
    let _ = JoinRequest::from_bytes(data);
});
