#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| skein_pim_graph::fuzzing::page_of(data));
