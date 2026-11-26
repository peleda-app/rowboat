use std::sync::Arc;

use serde_json::{Value, json};
use skein_core::{
    AccountId, Event, EventBody, FencingToken, SCHEMA_VERSION, Seq, TenantId, Timestamp,
};
use skein_keyring::{KeyScope, Keyring};
use skein_keyring_local::LocalKeyring;
use skein_oauth::testing::FakeTokenEndpoint;
use skein_oauth::{Access, Client, Grant, MailAccess, Provider, TokenManager};
use skein_storage::{Objects, Storage};
use skein_storage_memory::MemoryObjects;

use super::*;
use crate::{AccountRecord, Accounts, OAuthClients, TenantRegistry};

struct Node {
    storage: Storage,
    keyring: Arc<dyn Keyring>,
    accounts: Accounts,
    tokens: TokenManager,
    tenants: TenantRegistry,
}

fn node() -> Node {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let storage = Storage::over(objects.clone());
    let keyring: Arc<dyn Keyring> =
        Arc::new(LocalKeyring::from_master([4; 32], storage.control.clone()));
    Node {
        accounts: Accounts::new(storage.control.clone(), keyring.clone()),
        tokens: TokenManager::new(
            Arc::new(FakeTokenEndpoint::default()),
            storage.control.clone(),
            keyring.clone(),
        ),
        tenants: TenantRegistry::new(objects),
        storage,
        keyring,
    }
}

fn t(id: &str) -> TenantId {
    TenantId::new(id).unwrap()
}

fn a() -> AccountId {
    AccountId::new("box").unwrap()
}

fn record(value: Value) -> AccountRecord {
    let mut v = json!({"account": "box"});
    v.as_object_mut()
        .unwrap()
        .extend(value.as_object().unwrap().clone());
    serde_json::from_value(v).unwrap()
}

fn code(r: Result<(), AdminError>) -> &'static str {
    match r {
        Err(AdminError::Invalid { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn records_keep_their_settings_small_and_shaped() {
    let clients = OAuthClients::new();
    let ok = record(
        json!({"provider": "imap", "settings": {"host": "imap.example.com"}, "auth": {"type": "password"}}),
    );
    check_record(&ok, &clients).unwrap();
    let not_object = record(
        json!({"provider": "imap", "settings": "imap.example.com", "auth": {"type": "password"}}),
    );
    assert_eq!(
        code(check_record(&not_object, &clients)),
        "invalid_settings"
    );
    let big = record(
        json!({"provider": "imap", "settings": {"pad": "x".repeat(MAX_SETTINGS)}, "auth": {"type": "password"}}),
    );
    assert_eq!(code(check_record(&big, &clients)), "invalid_settings");
    let send = record(
        json!({"provider": "imap", "settings": {"host": "imap.example.com"}, "auth": {"type": "password"},
        "send": {"kind": "smtp", "settings": "smtp.example.com"}}),
    );
    assert_eq!(code(check_record(&send, &clients)), "invalid_settings");
    let send = record(
        json!({"provider": "imap", "settings": {"host": "imap.example.com"}, "auth": {"type": "password"},
        "send": {"kind": "smtp", "settings": {"host": "smtp.example.com", "security": "starttls"}}}),
    );
    check_record(&send, &clients).unwrap();
    let oauth = record(
        json!({"provider": "gmail", "settings": {}, "auth": {"type": "o_auth", "client": "google"}}),
    );
    assert_eq!(code(check_record(&oauth, &clients)), "unknown_client");
    let mut known = OAuthClients::new();
    known.insert(
        "google",
        Client::new(
            Provider::Google,
            "id",
            None,
            "https://app.example.com/cb",
            &Access {
                mail: MailAccess::Api,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    check_record(&oauth, &known).unwrap();
}

#[test]
fn ses_settings_are_checked() {
    let clients = OAuthClients::new();
    let with_send = |send: Value| {
        record(json!({
            "provider": "imap",
            "settings": {"host": "imap.example.com", "username": "ada@example.com"},
            "auth": {"type": "password"},
            "send": send,
        }))
    };
    for bad in [
        json!({"kind": "ses", "settings": {}}),
        json!({"kind": "ses", "settings": null}),
        json!({"kind": "ses", "settings": {"region": "EU-WEST-1"}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1.evil.example"}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1", "endpoint": "http://ses.example.com"}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1", "endpoint": "https://ses.example.com/v2"}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1", "endpoint": "https://user@ses.example.com"}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1", "endpoint": 5}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1", "message_id_domain": ""}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1", "message_id_domain": "ses..example.net"}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1", "message_id_domain": "-ses.example.net"}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1", "message_id_domain": "ses.example.net>\r\nBcc: x"}}),
        json!({"kind": "ses", "settings": {"region": "eu-west-1", "message_id_domain": 5}}),
    ] {
        assert_eq!(
            code(check_record(&with_send(bad.clone()), &clients)),
            "invalid_settings",
            "{bad}"
        );
    }
    let good = json!({"kind": "ses", "settings": {"region": "eu-west-1", "configuration_set": "transactional", "endpoint": "http://127.0.0.1:4566", "message_id_domain": "ses.example.net"}});
    check_record(&with_send(good), &clients).unwrap();
}

#[test]
fn secrets_are_checked_without_repeating_them() {
    let secret = "ses-secret/EXAMPLE+key";
    for (id, s, token) in [
        ("", secret, None),
        ("AKID EXAMPLE", secret, None),
        ("AKIDEXAMPLE", "", None),
        ("AKIDEXAMPLE", secret, Some("a b")),
    ] {
        let r = check_send_key(id, s, token);
        assert!(!format!("{r:?}").contains(secret));
        assert_eq!(code(r), "invalid_key");
    }
    check_send_key("AKIDEXAMPLE", secret, Some("session-token-EXAMPLE")).unwrap();
    assert_eq!(code(check_password("")), "invalid_password");
    assert_eq!(
        code(check_password(&"x".repeat(MAX_PASSWORD + 1))),
        "invalid_password"
    );
    check_password("hunter2-hunter2").unwrap();
    assert_eq!(code(check_token("a\nb")), "invalid_token");
    assert_eq!(
        code(check_token(&"x".repeat(MAX_TOKEN + 1))),
        "invalid_token"
    );
    check_token("ya29.EXAMPLE").unwrap();
}

#[tokio::test]
async fn a_send_key_is_sealed_and_goes_with_its_account() {
    let n = node();
    let tenant = t("acme");
    register_tenant(&n.tenants, &*n.keyring, &tenant)
        .await
        .unwrap();
    let r = record(
        json!({"provider": "imap", "settings": {"host": "imap.example.com"}, "auth": {"type": "password"},
        "send": {"kind": "ses", "settings": {"region": "eu-west-1"}}}),
    );
    n.accounts.put(&tenant, &r).await.unwrap();
    let secret = "ses-secret/EXAMPLE+key";
    let token = "session-token-EXAMPLE";
    n.accounts
        .set_send_key(&tenant, &a(), "AKIDEXAMPLE", secret, Some(token))
        .await
        .unwrap();
    let stored = n
        .storage
        .control
        .get(&tenant, "credentials/box/send-key")
        .await
        .unwrap()
        .unwrap()
        .0;
    let text = String::from_utf8_lossy(&stored);
    assert!(!text.contains(secret) && !text.contains(token));
    let listed = serde_json::to_string(&n.accounts.list(&tenant).await.unwrap()).unwrap();
    assert!(!listed.contains(secret) && !listed.contains("AKIDEXAMPLE"));

    n.tokens
        .store(&tenant, &a(), &Grant::external("ya29.EXAMPLE", None, None))
        .await
        .unwrap();
    assert!(
        n.storage
            .control
            .get(&tenant, "credentials/box/oauth")
            .await
            .unwrap()
            .is_some()
    );
    delete_account(&n.accounts, &n.tokens, &tenant, &a())
        .await
        .unwrap();
    assert!(
        n.storage
            .control
            .get(&tenant, "credentials/box/send-key")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        n.storage
            .control
            .get(&tenant, "credentials/box/oauth")
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        delete_account(&n.accounts, &n.tokens, &tenant, &a()).await,
        Err(AdminError::NotFound)
    ));
}

#[tokio::test]
async fn purging_shreds_the_key_and_the_id_cannot_come_back() {
    let n = node();
    let acme = t("acme");
    let globex = t("globex");
    register_tenant(&n.tenants, &*n.keyring, &acme)
        .await
        .unwrap();
    register_tenant(&n.tenants, &*n.keyring, &acme)
        .await
        .expect("registering again changes nothing");
    register_tenant(&n.tenants, &*n.keyring, &globex)
        .await
        .unwrap();
    let r = record(
        json!({"provider": "imap", "settings": {"host": "imap.example.com"}, "auth": {"type": "password"}}),
    );
    n.accounts.put(&acme, &r).await.unwrap();
    n.accounts
        .set_password(&acme, &a(), "hunter2-hunter2")
        .await
        .unwrap();
    let sealed = n
        .storage
        .control
        .get(&acme, "credentials/box/password")
        .await
        .unwrap()
        .unwrap()
        .0;
    let scope = KeyScope::account_of(&acme, &a());
    assert!(
        n.keyring
            .open(&scope, "credentials/box/password", &sealed)
            .await
            .is_ok()
    );
    n.storage
        .log
        .append(
            &acme,
            &a(),
            FencingToken(1),
            vec![Event {
                v: SCHEMA_VERSION,
                seq: Seq(0),
                at: Timestamp(1),
                account: a(),
                key: "k".into(),
                origin: None,
                trace: None,
                body: EventBody::FirstSyncCompleted,
            }],
        )
        .await
        .unwrap();

    let purged = purge_tenant(
        &n.storage,
        &n.accounts,
        &n.tokens,
        &n.tenants,
        &*n.keyring,
        &acme,
    )
    .await
    .unwrap();
    assert_eq!(purged.accounts, 1);
    assert!(purged.objects > 0);
    assert_eq!(n.storage.log.head(&acme, &a()).await.unwrap(), Seq(0));
    assert!(
        n.keyring
            .open(&scope, "credentials/box/password", &sealed)
            .await
            .is_err()
    );
    assert!(n.accounts.list(&acme).await.unwrap().is_empty());
    assert_eq!(n.tenants.list().await.unwrap(), vec![globex.clone()]);
    assert!(matches!(
        unregister_tenant(&n.tenants, &acme).await,
        Err(AdminError::NotFound)
    ));
    assert!(matches!(
        register_tenant(&n.tenants, &*n.keyring, &acme).await,
        Err(AdminError::Purged)
    ));
    unregister_tenant(&n.tenants, &globex).await.unwrap();
    assert!(n.tenants.list().await.unwrap().is_empty());
}

#[test]
fn the_node_liveness_group_is_never_a_tenant() {
    assert!(TenantId::new("_nodes").is_err());
    assert!(TenantId::new("_other").is_err());
}
