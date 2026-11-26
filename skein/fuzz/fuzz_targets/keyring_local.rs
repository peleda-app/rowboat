#![no_main]

use std::sync::Arc;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use skein_core::{AccountId, TenantId};
use skein_keyring::{KeyScope, Keyring, KeyringError, open_account};
use skein_keyring_local::LocalKeyring;
use skein_storage::{ControlStore, Expect, ObjectControl};
use skein_storage_memory::MemoryObjects;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let split = rest.iter().position(|b| *b == 0xff).unwrap_or(rest.len());
    let record = Bytes::copy_from_slice(&rest[..split]);
    let sealed = rest.get(split + 1..).unwrap_or_default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let control: Arc<dyn ControlStore> =
            Arc::new(ObjectControl::new(Arc::new(MemoryObjects::new())));
        let ring = LocalKeyring::from_master([7; 32], control.clone());
        let tenant = TenantId::new("t").expect("valid");
        let account = AccountId::new("a").expect("valid");
        let path = match selector % 3 {
            0 => Some("keys/data"),
            1 => Some("keys/accounts/a"),
            _ => None,
        };
        if let Some(path) = path {
            control
                .put(&tenant, path, record, Expect::Any)
                .await
                .expect("memory put");
        }
        for scope in [
            KeyScope::tenant_of(&tenant),
            KeyScope::account_of(&tenant, &account),
        ] {
            let opened = ring.open(&scope, "c", sealed).await;
            assert!(
                matches!(opened, Err(KeyringError::Invalid | KeyringError::Destroyed)),
                "forged bytes never open"
            );
            if let Ok(again) = ring.seal(&scope, "c", sealed).await {
                assert_eq!(
                    ring.open(&scope, "c", &again).await.expect("round trip"),
                    sealed
                );
            }
        }
        let fallback = open_account(&ring, &tenant, &account, "c", sealed).await;
        assert!(fallback.is_err());
    });
});
