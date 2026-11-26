#![no_main]

use baton_keys::{KEM_SECRET_LEN, KemPublic, KemSecret, SealedBox, open_box, seal_box};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(public) = KemPublic::from_bytes(data) {
        assert_eq!(public.as_bytes(), data);
    }
    let secret = KemSecret::from_bytes(&[9u8; KEM_SECRET_LEN]).expect("any 32 bytes are a seed");
    let split = data.first().map_or(0, |&n| n as usize).min(data.len());
    let (enc, ct) = data.split_at(split);
    let forged = SealedBox {
        enc: enc.to_vec(),
        ct: ct.to_vec(),
    };
    assert!(
        open_box(&secret, b"fuzz", &forged).is_err(),
        "forged boxes never open"
    );
    if ct.len() <= 64 {
        let sealed = seal_box(&secret.public(), b"fuzz", ct).expect("seal");
        assert_eq!(&open_box(&secret, b"fuzz", &sealed).expect("open")[..], ct);
        assert!(open_box(&secret, b"other", &sealed).is_err());
    }
});
