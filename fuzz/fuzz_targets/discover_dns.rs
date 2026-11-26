#![no_main]

use libfuzzer_sys::fuzz_target;
use rowboat_discover::MAX_SRV_RECORDS;
use rowboat_discover_net::dns::parse_answer;

fuzz_target!(|data: &[u8]| {
    let id = data
        .get(..2)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    if let Ok(records) = parse_answer(data, id, "_imaps._tcp.example.com") {
        assert!(records.len() <= MAX_SRV_RECORDS);
    }
});
