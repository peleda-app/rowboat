#![no_main]

use libfuzzer_sys::fuzz_target;
use rowboat_discover::{Candidate, Domain, MAX_CANDIDATES};

fuzz_target!(|data: &[u8]| {
    let domain = Domain::new("example.com").expect("domain");
    let found = rowboat_discover_autoconfig::parse(data, &domain);
    assert!(found.len() <= MAX_CANDIDATES);
    assert!(found.iter().all(Candidate::is_valid));
    assert_eq!(rowboat_discover_autoconfig::parse(data, &domain), found);
});
