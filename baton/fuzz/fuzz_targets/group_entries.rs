#![no_main]

use baton_group::{Entry, GroupLog};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut entries = Vec::new();
    for chunk in data.split(|b| *b == 0xA5).take(16) {
        if let Ok(e) = Entry::decode(chunk) {
            assert_eq!(Entry::decode(&e.encode()).as_ref(), Ok(&e));
            entries.push(e);
        }
    }
    if let Ok(log) = GroupLog::verify(entries) {
        assert_eq!(log.entries().len() as u64, log.head_seq() + 1);
    }
});
