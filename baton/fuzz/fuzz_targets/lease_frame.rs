#![no_main]

use baton_lease_server::wire::{
    MAX_REPLY, MAX_REQUEST, decode_reply, decode_request, encode_reply, encode_request, frame_len,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = decode_request(data) {
        assert!(data.len() <= MAX_REQUEST);
        assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
    }
    if let Ok(r) = decode_reply(data, MAX_REPLY) {
        assert_eq!(decode_reply(&encode_reply(&r), MAX_REPLY).unwrap(), r);
    }
    if let Some(prefix) = data.get(..4) {
        let prefix: [u8; 4] = prefix.try_into().unwrap();
        if let Ok(n) = frame_len(prefix, MAX_REQUEST) {
            assert!((1..=MAX_REQUEST).contains(&n));
        }
    }
});
