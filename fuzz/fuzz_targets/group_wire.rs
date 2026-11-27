#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rowboat_group::pairing::fuzz_decoders(data);
    rowboat_group::sync::fuzz_decoders(data);
    rowboat_group::notice::fuzz_decoders(data);
});
