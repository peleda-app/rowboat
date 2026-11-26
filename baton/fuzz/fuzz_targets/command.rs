#![no_main]

use baton_command::{Command, CommandResult};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = Command::decode(data) {
        assert_eq!(Command::decode(&c.encode()).as_ref(), Ok(&c));
    }
    if let Ok(r) = CommandResult::decode(data) {
        assert_eq!(CommandResult::decode(&r.encode()).as_ref(), Ok(&r));
    }
});
