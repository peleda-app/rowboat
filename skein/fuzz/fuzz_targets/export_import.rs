#![no_main]

use std::io::Write;
use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use skein_core::TenantId;
use skein_storage::Objects;
use skein_storage_memory::MemoryObjects;

#[allow(dead_code)]
#[path = "../../apps/skein/src/transfer.rs"]
mod transfer;

fn run(file: &[u8]) {
    let mut tmp = tempfile::NamedTempFile::new().expect("a temporary file");
    tmp.write_all(file).expect("the file is written");
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    let target: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let tenant = TenantId::new("t1").expect("a valid tenant");
    let _ = rt.block_on(transfer::import(target, &tenant, tmp.path()));
}

fuzz_target!(|data: &[u8]| {
    match data.split_first() {
        Some((0, rest)) => run(rest),
        _ => run(&zstd::bulk::compress(data, 1).expect("zstd compresses in memory")),
    }
});
