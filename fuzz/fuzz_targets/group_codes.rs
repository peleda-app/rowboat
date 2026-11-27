#![no_main]

use libfuzzer_sys::fuzz_target;
use rowboat_group::invite::{Invite, PairAddress, ShortCode};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(i) = Invite::from_qr(text) {
        assert_eq!(Invite::from_qr(&i.to_qr()).unwrap(), i);
    }
    if let Ok(c) = ShortCode::parse(text) {
        assert_eq!(ShortCode::parse(&c.display()).unwrap(), c);
    }
    if let Ok(a) = PairAddress::parse(text) {
        assert_eq!(PairAddress::parse(&a.to_text()).unwrap(), a);
    }
});
