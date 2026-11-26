#![no_main]

use baton_identity::Roster;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = Roster::from_bytes(data) {
        r.verify()
            .expect("from_bytes only returns verified rosters");
        assert!(!r.members().is_empty());
        assert!(r.members().iter().all(|m| !r.revoked().contains(m)));
        assert!(r.is_member(r.signer()));
    }
});
