//! Shared helpers for the integration and live suites.

use std::sync::Arc;

use baton_lease::{Leases, Liveness};
use baton_lease_cas::{CasLeases, CasLiveness, Clock};
use baton_signal_local::LocalSignal;
use baton_state_memory::MemoryState;
use skein_engine::{Engine, OneGroupLiveness, node_profile};
use skein_storage::{ControlState, Objects, Storage};
use skein_storage_s3::{S3Config, S3Objects};

/// An engine for `node` that holds every lease itself: Baton's compare-and-swap leases over
/// in-memory state, as the binary's `single` mode.
pub fn single_engine(storage: Storage, node: &str) -> Engine {
    let state = Arc::new(MemoryState::new());
    let liveness = Arc::new(CasLiveness::new(state.clone(), 20_000));
    Engine::new(
        storage,
        Arc::new(CasLeases::new(state, liveness)),
        Arc::new(LocalSignal::new()),
        node_profile(skein_core::NodeId::new(node).unwrap(), 1, true),
    )
}

/// An engine for `node` coordinating through leases and heartbeats in `storage`'s control store,
/// as the binary's `storage` mode, with its own liveness (returned) judged on `clock` when given.
pub fn storage_engine(
    storage: Storage,
    node: &str,
    ttl_ms: u64,
    clock: Option<Clock>,
) -> (Engine, Arc<dyn Liveness>) {
    let state = Arc::new(ControlState::new(storage.control.clone()));
    let liveness: Arc<dyn Liveness> = Arc::new(OneGroupLiveness::nodes(Arc::new(
        CasLiveness::new(state.clone(), ttl_ms),
    )));
    let leases = CasLeases::new(state, liveness.clone());
    let leases: Arc<dyn Leases> = Arc::new(match clock {
        Some(c) => leases.with_clock(c),
        None => leases,
    });
    let engine = Engine::new(
        storage,
        leases,
        Arc::new(LocalSignal::new()),
        node_profile(skein_core::NodeId::new(node).unwrap(), 1, true),
    );
    (engine, liveness)
}

/// Whether the integration stack is up (`SKEIN_IT=1`, set by `mise run it`).
pub fn enabled() -> bool {
    std::env::var("SKEIN_IT").as_deref() == Ok("1")
}

/// A required environment variable.
pub fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

/// An object store on the integration S3 server under a fresh prefix, so runs never see each other.
pub fn s3() -> Arc<dyn Objects> {
    let config = S3Config {
        endpoint: Some(env("SKEIN_IT_S3_ENDPOINT")),
        bucket: env("SKEIN_IT_S3_BUCKET"),
        region: "us-east-1".into(),
        prefix: Some(format!(
            "it-{}",
            ulid::Ulid::generate().to_string().to_lowercase()
        )),
        access_key_id: env("SKEIN_IT_S3_ACCESS_KEY"),
        secret_access_key: env("SKEIN_IT_S3_SECRET_KEY"),
        allow_http: true,
    };
    Arc::new(S3Objects::new(&config).expect("S3 config"))
}

use bytes::Bytes;
use skein_core::{
    AccountId, BlobHash, Command, CommandBody, CommandId, EventBody, Flags, ItemRef, Seq, TenantId,
    Timestamp,
};
use skein_engine::AccountConfig;
use skein_mail::MailProvider;
use skein_storage_memory::MemoryObjects;

/// The id of the mailbox with `role`; panics when the account has none.
pub async fn mailbox_with_role(
    provider: &dyn MailProvider,
    role: skein_core::MailboxRole,
) -> String {
    let mut session = provider.connect().await.expect("connect");
    let id = session
        .mailboxes()
        .await
        .expect("mailboxes")
        .into_iter()
        .find(|m| m.role == Some(role))
        .unwrap_or_else(|| panic!("no mailbox with role {role:?}"))
        .id;
    session.logout().await.expect("logout");
    id
}

/// A full round trip through the engine against a real server: append a uniquely tagged message
/// through a command, see it journaled, flag it, delete it, and see both journaled. Leaves the
/// mailbox as it found it. Prints counts only.
pub async fn mail_round_trip(provider: &dyn MailProvider, mailbox: &str) {
    let tenant = TenantId::new("live").unwrap();
    let account = AccountId::new("acc").unwrap();
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let engine = single_engine(storage.clone(), "it");
    let mut config = AccountConfig::new(tenant.clone(), account.clone());
    config.include = Some(vec![mailbox.to_owned()]);

    let first = engine
        .sync_account(&config, provider)
        .await
        .expect("first sync");
    eprintln!("first sync: {} events", first.events);

    let tag = ulid::Ulid::generate().to_string().to_lowercase();
    let message = format!(
        "From: Skein Test <skein-test@example.com>\r\nTo: skein-test@example.com\r\nSubject: skein live {tag}\r\nMessage-ID: <{tag}@example.com>\r\nDate: Thu, 20 Nov 2025 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis message was written by the Skein test suite and will be deleted.\r\n"
    );
    let blob = storage
        .blobs
        .put(&tenant, Bytes::from(message.clone()))
        .await
        .unwrap();
    let submit = |body| {
        let storage = storage.clone();
        let tenant = tenant.clone();
        let account = account.clone();
        async move {
            let command = Command {
                id: CommandId::generate(),
                account,
                created_at: Timestamp::now(),
                trace: None,
                body,
            };
            storage.commands.submit(&tenant, &command).await.unwrap();
            command.id
        }
    };
    let id = submit(CommandBody::Append {
        mailbox: mailbox.to_owned(),
        blob,
        flags: Flags::default(),
        received_at: None,
    })
    .await;
    let r = engine
        .run_commands(&config, provider)
        .await
        .expect("append runs");
    assert_eq!(r.applied, 1, "append applied");
    let _ = id;

    let after_append = storage.log.head(&tenant, &account).await.unwrap();
    engine
        .sync_account(&config, provider)
        .await
        .expect("sync after append");
    let item = find_added(&storage, &tenant, &account, after_append, &tag).await;

    submit(CommandBody::SetFlags {
        mailbox: mailbox.to_owned(),
        items: vec![item.clone()],
        add: Flags::new(["\\Flagged"]),
        remove: Flags::default(),
    })
    .await;
    assert_eq!(
        engine
            .run_commands(&config, provider)
            .await
            .unwrap()
            .applied,
        1
    );
    let before = storage.log.head(&tenant, &account).await.unwrap();
    engine.sync_account(&config, provider).await.unwrap();
    let events = storage
        .log
        .read(&tenant, &account, before.next(), 10_000)
        .await
        .unwrap();
    assert!(
        events.iter().any(|e| matches!(&e.body, EventBody::FlagsChanged { item: i, flags, .. } if i.id == item.id && flags.contains("\\Flagged"))),
        "the flag change is journaled"
    );

    submit(CommandBody::Delete {
        mailbox: mailbox.to_owned(),
        items: vec![item.clone()],
        to_trash: false,
    })
    .await;
    assert_eq!(
        engine
            .run_commands(&config, provider)
            .await
            .unwrap()
            .applied,
        1
    );
    let before = storage.log.head(&tenant, &account).await.unwrap();
    engine.sync_account(&config, provider).await.unwrap();
    let events = storage
        .log
        .read(&tenant, &account, before.next(), 10_000)
        .await
        .unwrap();
    assert!(
        events.iter().any(
            |e| matches!(&e.body, EventBody::MessageRemoved { item: i, .. } if i.id == item.id)
        ),
        "the removal is journaled"
    );
    eprintln!(
        "round trip done; journal head {}",
        storage.log.head(&tenant, &account).await.unwrap().0
    );
}

async fn find_added(
    storage: &Storage,
    tenant: &TenantId,
    account: &AccountId,
    after: Seq,
    tag: &str,
) -> ItemRef {
    let events = storage
        .log
        .read(tenant, account, after.next(), 10_000)
        .await
        .unwrap();
    for e in events {
        if let EventBody::MessageAdded { item, blob, .. } = e.body {
            let bytes = storage.blobs.get(tenant, &blob).await.unwrap().unwrap();
            let needle = format!("<{tag}@example.com>");
            if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                assert_eq!(BlobHash::of(&bytes), blob);
                return item;
            }
        }
    }
    panic!("the appended message was not journaled");
}
