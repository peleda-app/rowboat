#![no_main]

use libfuzzer_sys::fuzz_target;
use rowboat_api::{decode_request, encode_request};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = decode_request(data) {
        assert!(request.check().is_ok());
        let again =
            decode_request(&encode_request(&request)).expect("a decoded request re-encodes");
        assert_eq!(again, request);
        assert!(request.class().as_str().starts_with("mail-"));
    }
});
