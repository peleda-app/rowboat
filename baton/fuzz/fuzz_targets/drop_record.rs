#![no_main]

use baton_drop::record::{
    decode_box, decode_message, encode_box, encode_message, split_message_key,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(info) = decode_box(data) {
        assert_eq!(decode_box(&encode_box(&info)).unwrap(), info);
    }
    if let Ok((at, bytes)) = decode_message(data) {
        assert_eq!(encode_message(at, bytes), data);
    }
    if let Ok((id, n)) = split_message_key(data) {
        assert_eq!(baton_drop::record::message_key(&id, n), data);
    }
});
