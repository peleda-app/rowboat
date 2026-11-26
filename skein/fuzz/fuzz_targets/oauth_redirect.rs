#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_oauth::read_redirect;

fuzz_target!(|data: &[u8]| {
    let pasted = String::from_utf8_lossy(data);
    if let Ok(redirect) = read_redirect(&pasted) {
        assert!(!redirect.code.is_empty() && !redirect.state.is_empty());
        assert_eq!(redirect.code.trim(), redirect.code);
        assert_eq!(redirect.state.trim(), redirect.state);
    }
});
