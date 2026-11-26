#![no_main]

use baton_seal::{Context, Key, open};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = Key::from_bytes([7u8; 32]);
    let ctx = Context::new("fuzz", b"object");
    assert!(open(&key, ctx, data).is_err(), "random bytes never open");
});
