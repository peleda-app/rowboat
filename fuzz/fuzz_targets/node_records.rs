#![no_main]

use libfuzzer_sys::fuzz_target;
use rowboat_node::records::{
    decode_account_meta, decode_draft_record, decode_node_record, encode_account_meta,
    encode_draft_record, encode_node_record,
};

fuzz_target!(|data: &[u8]| {
    rowboat_node::fuzz_leaving(data);
    if let Ok(r) = decode_node_record(data) {
        assert_eq!(decode_node_record(&encode_node_record(&r)).unwrap(), r);
    }
    if let Ok(r) = decode_draft_record(data) {
        assert!(r.draft.id.is_some());
        assert_eq!(decode_draft_record(&encode_draft_record(&r)).unwrap(), r);
    }
    if let Ok(r) = decode_account_meta(data) {
        assert_eq!(decode_account_meta(&encode_account_meta(&r)).unwrap(), r);
    }
});
