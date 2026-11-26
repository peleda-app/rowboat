#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use skein_core::{Command, Event};
use skein_storage::fuzzing;

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(data: &[u8]) {
    if let Ok(value) = serde_json::from_slice::<T>(data) {
        let written = serde_json::to_vec(&value).expect("a value serializes");
        let back: T = serde_json::from_slice(&written).expect("a written value reads");
        assert_eq!(back, value);
    }
}

fuzz_target!(|data: &[u8]| {
    round_trip::<Event>(data);
    round_trip::<Command>(data);
    fuzzing::snapshot(data);
    fuzzing::segment(data);
});
