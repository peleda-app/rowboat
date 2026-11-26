#![no_main]

use libfuzzer_sys::fuzz_target;
use rowboat_api::Cursor;
use rowboat_api::cursor::{decode, encode};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for candidate in [text.to_string(), format!("c1.{text}")] {
        if let Ok(cursor) = Cursor::new(candidate)
            && let Ok(position) = decode(&cursor)
        {
            assert!(!position.id.is_empty() && position.id.len() <= 128);
            assert_eq!(decode(&encode(&position)).unwrap(), position);
        }
    }
});
