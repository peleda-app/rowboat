#![no_main]

use libfuzzer_sys::fuzz_target;
use rowboat::tenant::{MAX_RECORD, decode_binding, decode_record};

fuzz_target!(|data: &[u8]| {
    if let Some(b) = decode_binding(data) {
        assert!(data.len() <= MAX_RECORD);
        assert!(b.genesis_bytes().is_some());
        let again = serde_json::to_vec(&b).unwrap();
        assert_eq!(decode_binding(&again), Some(b));
    }
    if let Some(r) = decode_record(data) {
        assert!(data.len() <= MAX_RECORD);
        let again = serde_json::to_vec(&r).unwrap();
        assert_eq!(decode_record(&again), Some(r));
    }
});
