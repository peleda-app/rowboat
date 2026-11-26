#![no_main]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use baton_core::Timestamp;
use baton_drop::admission::AdmissionConfig;
use baton_drop::wire::{self, Body, Reply, WireAdmission};
use baton_drop::{DropConfig, DropService, MemoryDropStore};
use baton_mailbox::{BoxId, BoxKey, BoxPolicy};
use libfuzzer_sys::fuzz_target;

const REALM: &str = "drop.example.com";
const NOW: Timestamp = Timestamp(1_800_000_000_000);

struct World {
    rt: tokio::runtime::Runtime,
    svc: DropService,
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let mut config = DropConfig::new(REALM, AdmissionConfig::open());
        config.max_wait = Duration::ZERO;
        let svc =
            DropService::new(Arc::new(MemoryDropStore::new()), config, Arc::new(|| NOW)).unwrap();
        let reader = BoxKey::derive(&[1; 32], &BoxId([2; 32]), baton_mailbox::BoxRole::Reader);
        let writer = BoxKey::derive(&[1; 32], &BoxId([2; 32]), baton_mailbox::BoxRole::Writer);
        let create = wire::seal(
            REALM,
            &reader,
            &BoxId::of_reader(&reader.public()),
            &Body::Create {
                policy: BoxPolicy {
                    max_bytes: 1 << 20,
                    max_messages: 1000,
                    ttl_ms: 24 * 3600 * 1000,
                    ..BoxPolicy::new(reader.public(), vec![writer.public()])
                },
                admission: WireAdmission::None,
            },
            NOW,
            [0; 16],
        );
        rt.block_on(svc.execute(&create)).unwrap();
        World { rt, svc }
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(o) = wire::open(data, REALM, NOW, 300_000, 1 << 20) {
        assert_eq!(o.body.op(), o.head.op);
        assert!(NOW.0.abs_diff(o.head.at.0) <= 300_000);
    }
    if let Ok(Ok(Reply::Messages(m))) = wire::decode_reply(data, 1 << 20) {
        let again = wire::encode_reply(&Ok(Reply::Messages(m.clone())));
        assert_eq!(
            wire::decode_reply(&again, 1 << 20),
            Ok(Ok(Reply::Messages(m)))
        );
    }
    let _ = wire::decode_info(data);
    if let (Some(wait), Ok(o)) = (
        wire::wait_ms(data),
        wire::open(data, REALM, NOW, 300_000, 1 << 20),
    ) {
        assert!(matches!(o.body, Body::Take { wait_ms, .. } if wait_ms == wait));
    }
    let w = world();
    let reply = w.rt.block_on(w.svc.handle(data));
    assert!(wire::decode_reply(&reply, w.svc.max_reply()).is_ok());
});
