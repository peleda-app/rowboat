#![no_main]

use baton_lease::record::LeaseRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = LeaseRecord::decode(data) {
        let again = LeaseRecord::decode(&r.encode()).expect("a decoded record re-encodes validly");
        assert_eq!(again, r);
        if r.holder.is_some() {
            assert!(r.fence > 0);
        }
    }
});
