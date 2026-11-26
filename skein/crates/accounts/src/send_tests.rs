use std::sync::{Arc, Mutex};

use skein_core::{AccountId, Credentials, TenantId};
use skein_engine::SenderDirectory;
use skein_keyring::Keyring;
use skein_keyring_local::LocalKeyring;
use skein_oauth::TokenManager;
use skein_oauth::testing::FakeTokenEndpoint;
use skein_send::testing::FakeSender;
use skein_send::{SendError, Sender};
use skein_storage::Storage;
use skein_storage_memory::MemoryObjects;

use crate::*;

#[derive(Default)]
struct Built(Mutex<Vec<(SenderKind, serde_json::Value, Credentials)>>);

impl SenderFactory for Built {
    fn build(
        &self,
        _record: &AccountRecord,
        kind: SenderKind,
        settings: &serde_json::Value,
        credentials: Credentials,
    ) -> Result<Arc<dyn Sender>, SendError> {
        self.0
            .lock()
            .unwrap()
            .push((kind, settings.clone(), credentials));
        Ok(Arc::new(FakeSender::new()))
    }
}

fn record(provider: ProviderKind, send: Option<SendSettings>) -> AccountRecord {
    AccountRecord {
        account: AccountId::new("a").unwrap(),
        provider,
        settings: serde_json::json!({"host": "imap.example.com", "username": "ada@example.com"}),
        auth: Auth::Password,
        include: None,
        exclude: vec![],
        paused: false,
        send,
        pim: None,
    }
}

fn smtp(settings: serde_json::Value) -> Option<SendSettings> {
    Some(SendSettings {
        kind: SenderKind::Smtp,
        settings,
    })
}

#[test]
fn picks_the_sender_from_send_settings_or_the_provider() {
    assert!(record(ProviderKind::Imap, None).sender().is_none());
    let (kind, settings) = record(ProviderKind::Gmail, None).sender().unwrap();
    assert_eq!(kind, SenderKind::Gmail);
    assert_eq!(settings["host"], "imap.example.com");
    let (kind, settings) = record(
        ProviderKind::Imap,
        smtp(serde_json::json!({"host": "smtp.example.com", "security": "starttls"})),
    )
    .sender()
    .unwrap();
    assert_eq!(kind, SenderKind::Smtp);
    assert_eq!(settings["host"], "smtp.example.com");
    assert_eq!(settings["username"], "ada@example.com");
    let (_, settings) = record(
        ProviderKind::Imap,
        smtp(serde_json::json!({"host": "relay.example.com", "username": null})),
    )
    .sender()
    .unwrap();
    assert!(settings["username"].is_null(), "an explicit null stays");
}

#[test]
fn version_1_records_upgrade_without_send_settings() {
    let old = br#"{"v":1,"data":{"account":"a","provider":"imap","settings":{"host":"imap.example.com"},"auth":{"type":"password"}}}"#;
    let r: AccountRecord = skein_storage::decode_record(old).unwrap();
    assert_eq!(r.send, None);
    let with = record(
        ProviderKind::Imap,
        smtp(serde_json::json!({"host": "smtp.example.com"})),
    );
    let bytes = skein_storage::encode_record(&with).unwrap();
    assert_eq!(
        skein_storage::decode_record::<AccountRecord>(&bytes).unwrap(),
        with
    );
}

#[tokio::test]
async fn senders_resolve_credentials_when_asked() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let keyring: Arc<dyn Keyring> =
        Arc::new(LocalKeyring::from_master([9; 32], storage.control.clone()));
    let accounts = Accounts::new(storage.control.clone(), keyring.clone());
    let tokens = Arc::new(TokenManager::new(
        Arc::new(FakeTokenEndpoint::default()),
        storage.control.clone(),
        keyring,
    ));
    let built = Arc::new(Built::default());
    let senders = Senders::new(accounts.clone(), tokens, OAuthClients::new(), built.clone());
    let t = TenantId::new("t").unwrap();
    let a = AccountId::new("a").unwrap();

    assert!(
        senders.sender(&t, &a).await.unwrap().is_none(),
        "no account"
    );
    accounts
        .put(&t, &record(ProviderKind::Imap, None))
        .await
        .unwrap();
    assert!(
        senders.sender(&t, &a).await.unwrap().is_none(),
        "IMAP without SMTP"
    );

    accounts
        .put(
            &t,
            &record(
                ProviderKind::Imap,
                smtp(serde_json::json!({"host": "smtp.example.com"})),
            ),
        )
        .await
        .unwrap();
    assert!(matches!(
        senders.sender(&t, &a).await,
        Err(SendError::Auth(_))
    ));
    assert!(built.0.lock().unwrap().is_empty());
    accounts.set_password(&t, &a, "hunter2").await.unwrap();
    assert!(senders.sender(&t, &a).await.unwrap().is_some());
    let seen = built.0.lock().unwrap();
    assert_eq!(seen[0].0, SenderKind::Smtp);
    assert_eq!(
        seen[0].2,
        Credentials::Password {
            secret: "hunter2".into()
        }
    );
    let _ = (
        storage.control.clone() as Arc<dyn ControlStore>,
        Expect::Any,
    );
}

#[tokio::test]
async fn ses_senders_sign_with_the_sealed_send_key() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let keyring: Arc<dyn Keyring> =
        Arc::new(LocalKeyring::from_master([9; 32], storage.control.clone()));
    let accounts = Accounts::new(storage.control.clone(), keyring.clone());
    let tokens = Arc::new(TokenManager::new(
        Arc::new(FakeTokenEndpoint::default()),
        storage.control.clone(),
        keyring,
    ));
    let built = Arc::new(Built::default());
    let senders = Senders::new(accounts.clone(), tokens, OAuthClients::new(), built.clone());
    let t = TenantId::new("t").unwrap();
    let a = AccountId::new("a").unwrap();
    let ses = Some(SendSettings {
        kind: SenderKind::Ses,
        settings: serde_json::json!({"region": "eu-west-1"}),
    });
    accounts
        .put(&t, &record(ProviderKind::Imap, ses))
        .await
        .unwrap();
    accounts.set_password(&t, &a, "hunter2").await.unwrap();
    assert!(
        matches!(senders.sender(&t, &a).await, Err(SendError::Auth(_))),
        "the account password is not a send key"
    );

    accounts
        .set_send_key(&t, &a, "AKIDEXAMPLE", "ses-secret", Some("session"))
        .await
        .unwrap();
    let stored = storage
        .control
        .get(&t, "credentials/a/send-key")
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(!String::from_utf8_lossy(&stored).contains("ses-secret"));
    assert!(senders.sender(&t, &a).await.unwrap().is_some());
    {
        let seen = built.0.lock().unwrap();
        assert_eq!(seen[0].0, SenderKind::Ses);
        assert_eq!(seen[0].1["region"], "eu-west-1");
        assert_eq!(
            seen[0].2,
            Credentials::AccessKey {
                id: "AKIDEXAMPLE".into(),
                secret: "ses-secret".into(),
                session_token: Some("session".into()),
            }
        );
    }
    accounts.delete(&t, &a).await.unwrap();
    assert!(
        storage
            .control
            .get(&t, "credentials/a/send-key")
            .await
            .unwrap()
            .is_none()
    );
}
