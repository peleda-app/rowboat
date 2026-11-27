#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    baton_fetch::fuzz_decoders(data);
});
