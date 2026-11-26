#![no_main]

use std::sync::{Arc, OnceLock};

use baton_core::{GroupId, Timestamp};
use baton_group::{Entry, Founding, GroupLog};
use baton_group_server::GroupLogs;
use baton_group_server::wire::{
    MAX_REPLY, MAX_REQUEST, Request, decode_reply, decode_request, encode_reply, encode_request,
    frame_len,
};
use baton_identity::Identity;
use baton_keys::{KemSecret, RecoveryRoot};
use baton_lease::NodeClass;
use baton_state_memory::MemoryState;
use libfuzzer_sys::fuzz_target;

const NOW: Timestamp = Timestamp(1_800_000_000_000);

struct World {
    rt: tokio::runtime::Runtime,
    logs: Arc<GroupLogs>,
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let owner = Identity::from_secret_bytes(&[1; 32]);
        let node = Identity::from_secret_bytes(&[2; 32]);
        let log = GroupLog::genesis(
            GroupId::new("g").unwrap(),
            Founding {
                owner: &owner,
                owner_recovery: RecoveryRoot::generate().public(),
                group_recovery: RecoveryRoot::generate().public(),
                node: &node,
                node_kem: KemSecret::generate().public(),
                class: NodeClass::Desktop,
                expires: NOW.plus_ms(1_000_000),
            },
            NOW,
        )
        .unwrap();
        let logs = Arc::new(GroupLogs::new(
            [(GroupId::new("g").unwrap(), log.genesis_hash())],
            Arc::new(MemoryState::new()),
            1000,
        ));
        rt.block_on(async {
            logs.load().await.unwrap();
            logs.push(log.entries()[0].clone(), NOW, 0).await.unwrap();
        });
        World { rt, logs }
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = decode_request(data) {
        assert!(data.len() <= MAX_REQUEST);
        assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
        if let Request::Push { entry } = r
            && let Ok(e) = Entry::decode(&entry)
        {
            let w = world();
            let before = w.logs.head(e.group());
            let _ = w.rt.block_on(w.logs.push(e, NOW, 0));
            if let Some(b) = before {
                assert!(w.logs.head(&GroupId::new("g").unwrap()).unwrap().seq >= b.seq);
            }
        }
    }
    if let Ok(r) = decode_reply(data, MAX_REPLY) {
        assert_eq!(decode_reply(&encode_reply(&r), MAX_REPLY).unwrap(), r);
    }
    if let Some(prefix) = data.get(..4) {
        let prefix: [u8; 4] = prefix.try_into().unwrap();
        if let Ok(n) = frame_len(prefix, MAX_REQUEST) {
            assert!((1..=MAX_REQUEST).contains(&n));
        }
    }
});
