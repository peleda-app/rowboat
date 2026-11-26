#![no_main]

use std::sync::Arc;

use baton_core::GroupId;
use baton_state::{RecordName, StateStore};
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use skein_core::TenantId;
use skein_storage::{ControlState, ControlStore, Expect, ObjectControl, STATE_AREA, fuzzing};
use skein_storage_memory::MemoryObjects;

fuzz_target!(|data: &[u8]| {
    fuzzing::state_record(data);
    let split = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    let Ok(text) = std::str::from_utf8(&data[..split]) else {
        return;
    };
    let path = format!("{STATE_AREA}/{text}");
    let decoded = fuzzing::state_name(&path);
    if let Some(name) = &decoded {
        assert_eq!(fuzzing::state_path(name), path);
    }
    let stored = Bytes::copy_from_slice(data.get(split + 1..).unwrap_or_default());
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let control: Arc<dyn ControlStore> =
            Arc::new(ObjectControl::new(Arc::new(MemoryObjects::new())));
        let tenant = TenantId::new("t").expect("valid");
        let group = GroupId::new("t").expect("valid");
        let state = ControlState::new(control.clone());
        if control
            .put(&tenant, &path, stored.clone(), Expect::Any)
            .await
            .is_err()
        {
            return;
        }
        if let Some(name) = &decoded
            && let Ok(Some((value, _))) = state.get(&group, name).await
        {
            assert_eq!(&value[..], &stored[fuzzing::STATE_HEADER_LEN..]);
        }
        for prefix in ["a", "lease", "nodes"] {
            let prefix = RecordName::new(prefix).expect("valid");
            for listed in state.list(&group, &prefix, None, 10).await.expect("list") {
                assert!(listed.is_under(&prefix));
                assert_eq!(Some(&listed), decoded.as_ref());
            }
        }
    });
});
