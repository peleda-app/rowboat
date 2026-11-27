#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rowboat_sync::heads::fuzz_decoder(data);
    rowboat_sync::commands::fuzz_decoders(data);
    rowboat_sync::fuzz_attestation(data);
    rowboat_sync::fuzz_grant(data);
    rowboat_sync::fuzz_locator(data);
    rowboat_sync::handover::fuzz_offer(data);
});
