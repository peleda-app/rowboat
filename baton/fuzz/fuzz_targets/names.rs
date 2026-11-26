#![no_main]

use baton_core::NodeId;
use baton_state::RecordName;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(n) = RecordName::new(s) {
            assert!(
                n.as_str()
                    .split('/')
                    .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
            );
        }
        if let Ok(id) = NodeId::new(s) {
            assert!(!id.as_str().contains(['/', '.', '\\']));
        }
        let _ = serde_json::from_slice::<NodeId>(data);
    }
});
