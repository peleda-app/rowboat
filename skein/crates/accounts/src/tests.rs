use std::sync::{Arc, Mutex};

use baton_lease_cas::{CasLeases, CasLiveness};
use baton_signal_local::LocalSignal;
use baton_state_memory::MemoryState;
use skein_core::{AccountId, Credentials, NodeId, TenantId, Timestamp};
use skein_engine::{AccountDirectory, Engine, node_profile};
use skein_keyring::Keyring;
use skein_keyring_local::LocalKeyring;
use skein_mail::testing::FakeMail;
use skein_mail::{MailError, MailProvider};
use skein_oauth::testing::FakeTokenEndpoint;
use skein_oauth::{Access, Client, Grant, MailAccess, Provider, TokenManager};
use skein_storage::{ControlStore, Storage};
use skein_storage_memory::MemoryObjects;

use crate::*;

#[derive(Default)]
struct Factory {
    seen: Mutex<Vec<Credentials>>,
    tenants: Mutex<Vec<String>>,
    fake: FakeMail,
}

impl ProviderFactory for Factory {
    fn build(
        &self,
        _record: &AccountRecord,
        credentials: Credentials,
    ) -> Result<Arc<dyn MailProvider>, MailError> {
        self.seen.lock().unwrap().push(credentials);
        Ok(Arc::new(self.fake.clone()))
    }

    fn build_in(
        &self,
        tenant: &TenantId,
        record: &AccountRecord,
        credentials: Credentials,
    ) -> Result<Arc<dyn MailProvider>, MailError> {
        self.tenants
            .lock()
            .unwrap()
            .push(format!("{tenant}/{}", record.account));
        self.build(record, credentials)
    }
}

struct Setup {
    registry: TenantRegistry,
    storage: Storage,
    accounts: Accounts,
    tokens: Arc<TokenManager>,
    endpoint: Arc<FakeTokenEndpoint>,
    factory: Arc<Factory>,
    directory: Directory,
}

fn client() -> Client {
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
    .unwrap()
}

fn setup() -> Setup {
    let objects: Arc<dyn skein_storage::Objects> = Arc::new(MemoryObjects::new());
    let storage = Storage::over(objects.clone());
    let registry = TenantRegistry::new(objects);
    let keyring: Arc<dyn Keyring> =
        Arc::new(LocalKeyring::from_master([9; 32], storage.control.clone()));
    let accounts = Accounts::new(storage.control.clone(), keyring.clone());
    let endpoint = Arc::new(FakeTokenEndpoint::default());
    let tokens = Arc::new(TokenManager::new(
        endpoint.clone(),
        storage.control.clone(),
        keyring,
    ));
    let factory = Arc::new(Factory {
        fake: FakeMail::new(),
        ..Default::default()
    });
    let mut clients = OAuthClients::new();
    clients.insert("google", client());
    let directory = Directory::new(
        registry.clone(),
        accounts.clone(),
        tokens.clone(),
        clients,
        factory.clone(),
    );
    Setup {
        registry,
        storage,
        accounts,
        tokens,
        endpoint,
        factory,
        directory,
    }
}

fn record(name: &str, auth: Auth) -> AccountRecord {
    AccountRecord {
        account: AccountId::new(name).unwrap(),
        provider: ProviderKind::Imap,
        settings: serde_json::json!({"host": "imap.example.com", "username": "ada@example.com"}),
        auth,
        include: None,
        exclude: vec!["Junk".into()],
        paused: false,
        send: None,
        pim: None,
    }
}

#[tokio::test]
async fn records_hold_no_secrets_and_passwords_are_sealed() {
    let s = setup();
    let t = TenantId::new("t1").unwrap();
    let r = record("a", Auth::Password);
    s.accounts.put(&t, &r).await.unwrap();
    s.accounts
        .set_password(&t, &r.account, "hunter2-secret")
        .await
        .unwrap();
    assert_eq!(s.accounts.get(&t, &r.account).await.unwrap().unwrap(), r);
    for path in ["accounts/a", "credentials/a/password"] {
        let (bytes, _) = s.storage.control.get(&t, path).await.unwrap().unwrap();
        assert!(
            !bytes.windows(7).any(|w| w == b"hunter2"),
            "{path} holds the password"
        );
    }
    s.accounts.delete(&t, &r.account).await.unwrap();
    assert!(s.accounts.get(&t, &r.account).await.unwrap().is_none());
    assert!(
        s.storage
            .control
            .get(&t, "credentials/a/password")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_directory_resolves_credentials_only_when_connecting() {
    let s = setup();
    let t1 = TenantId::new("t1").unwrap();
    let t2 = TenantId::new("t2").unwrap();
    s.registry.add(&t1).await.unwrap();
    s.registry.add(&t2).await.unwrap();
    s.registry.add(&t2).await.unwrap();
    s.registry
        .add(&TenantId::new("unused").unwrap())
        .await
        .unwrap();
    s.registry
        .remove(&TenantId::new("unused").unwrap())
        .await
        .unwrap();
    assert_eq!(
        s.registry.list().await.unwrap(),
        vec![t1.clone(), t2.clone()]
    );
    s.accounts
        .put(&t1, &record("pw", Auth::Password))
        .await
        .unwrap();
    s.accounts
        .set_password(&t1, &AccountId::new("pw").unwrap(), "app-password")
        .await
        .unwrap();
    s.accounts
        .put(
            &t2,
            &record(
                "oa",
                Auth::OAuth {
                    client: "google".into(),
                },
            ),
        )
        .await
        .unwrap();
    let mut paused = record("off", Auth::Password);
    paused.paused = true;
    s.accounts.put(&t2, &paused).await.unwrap();
    s.tokens
        .store(
            &t2,
            &AccountId::new("oa").unwrap(),
            &Grant::external(
                "expired",
                Some(Timestamp::now().plus_ms(-1)),
                Some("refresh".into()),
            ),
        )
        .await
        .unwrap();

    let entries = s.directory.accounts().await.unwrap();
    let names: Vec<_> = entries
        .iter()
        .map(|e| e.config.account.as_str().to_owned())
        .collect();
    assert_eq!(names, ["pw", "oa"], "paused accounts are left out");
    assert_eq!(entries[0].config.exclude, vec!["Junk".to_owned()]);
    assert!(
        s.endpoint.requests().is_empty(),
        "listing never refreshes tokens"
    );
    assert!(s.factory.seen.lock().unwrap().is_empty());

    s.endpoint.tokens("fresh-access", None, 3600);
    let state = Arc::new(MemoryState::new());
    let liveness = Arc::new(CasLiveness::new(state.clone(), 5_000));
    let engine = Engine::new(
        s.storage.clone(),
        Arc::new(CasLeases::new(state, liveness)),
        Arc::new(LocalSignal::new()),
        node_profile(NodeId::new("n").unwrap(), 1, true),
    );
    for e in &entries {
        engine.sync_account(&e.config, &*e.provider).await.unwrap();
    }
    assert_eq!(
        *s.factory.tenants.lock().unwrap(),
        [format!("{t1}/pw"), format!("{t2}/oa")],
        "the directory builds through build_in with the tenant"
    );
    let seen = s.factory.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            Credentials::Password {
                secret: "app-password".into()
            },
            Credentials::AccessToken {
                token: "fresh-access".into()
            },
        ]
    );
    assert_eq!(s.endpoint.requests().len(), 1);
}

#[tokio::test]
async fn revoked_grants_and_missing_secrets_are_auth_errors() {
    let s = setup();
    let t = TenantId::new("t1").unwrap();
    s.registry.add(&t).await.unwrap();
    s.accounts
        .put(&t, &record("nopw", Auth::Password))
        .await
        .unwrap();
    s.accounts
        .put(
            &t,
            &record(
                "revoked",
                Auth::OAuth {
                    client: "google".into(),
                },
            ),
        )
        .await
        .unwrap();
    s.accounts
        .put(
            &t,
            &record(
                "noclient",
                Auth::OAuth {
                    client: "missing".into(),
                },
            ),
        )
        .await
        .unwrap();
    s.tokens
        .store(
            &t,
            &AccountId::new("revoked").unwrap(),
            &Grant::external("x", Some(Timestamp::now().plus_ms(-1)), Some("r".into())),
        )
        .await
        .unwrap();
    s.endpoint.error("invalid_grant");
    let entries = s.directory.accounts().await.unwrap();
    let by = |n: &str| {
        entries
            .iter()
            .find(|e| e.config.account.as_str() == n)
            .unwrap()
    };
    assert!(matches!(
        by("nopw").provider.connect().await,
        Err(MailError::Auth)
    ));
    assert!(matches!(
        by("revoked").provider.connect().await,
        Err(MailError::Auth)
    ));
    assert!(matches!(
        by("noclient").provider.connect().await,
        Err(MailError::Config(_))
    ));
}

#[test]
fn records_carry_a_schema_version() {
    let bytes = skein_storage::encode_record(&record("a", Auth::Password)).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["v"], 3);
    let _: Arc<dyn ControlStore>;
}

#[tokio::test]
async fn calendars_and_contacts_can_use_a_password_of_their_own() {
    let s = setup();
    let t = TenantId::new("t1").unwrap();
    let mut r = record("both", Auth::Password);
    r.pim = Some(PimSettings {
        kind: PimKind::Dav,
        settings: serde_json::json!({"calendars": "https://dav.example.com/"}),
        auth: Some(PimAuth::Password),
    });
    s.accounts.put(&t, &r).await.unwrap();
    s.accounts
        .set_password(&t, &r.account, "mail-secret")
        .await
        .unwrap();
    s.accounts
        .set_pim_password(&t, &r.account, "dav-secret")
        .await
        .unwrap();
    let (bytes, _) = s
        .storage
        .control
        .get(&t, "credentials/both/pim-password")
        .await
        .unwrap()
        .unwrap();
    assert!(!bytes.windows(10).any(|w| w == b"dav-secret"), "sealed");
    assert_eq!(
        s.accounts
            .pim_password(&t, &r.account)
            .await
            .unwrap()
            .as_deref(),
        Some("dav-secret")
    );
    s.accounts.delete(&t, &r.account).await.unwrap();
    assert!(
        s.storage
            .control
            .get(&t, "credentials/both/pim-password")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn secrets_sealed_under_the_tenant_are_resealed_under_the_account() {
    let objects: Arc<dyn skein_storage::Objects> = Arc::new(MemoryObjects::new());
    let storage = Storage::over(objects);
    let keyring: Arc<dyn Keyring> = Arc::new(
        LocalKeyring::from_master([9; 32], storage.control.clone())
            .with_cache_ttl(std::time::Duration::ZERO),
    );
    let accounts = Accounts::new(storage.control.clone(), keyring.clone());
    let t = TenantId::new("t1").unwrap();
    let (a, b) = (AccountId::new("a").unwrap(), AccountId::new("b").unwrap());
    let control = &storage.control;

    let legacy = keyring
        .seal(&KeyScope::tenant_of(&t), "credentials/a/password", b"old")
        .await
        .unwrap();
    control
        .put(
            &t,
            "credentials/a/password",
            Bytes::from(legacy.clone()),
            Expect::Absent,
        )
        .await
        .unwrap();
    assert_eq!(
        accounts.password(&t, &a).await.unwrap().as_deref(),
        Some("old")
    );
    let (now, _) = control
        .get(&t, "credentials/a/password")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(now.as_ref(), legacy.as_slice());
    assert_eq!(
        keyring
            .open(
                &KeyScope::account_of(&t, &a),
                "credentials/a/password",
                &now
            )
            .await
            .unwrap(),
        b"old"
    );
    assert!(
        keyring
            .open(&KeyScope::tenant_of(&t), "credentials/a/password", &now)
            .await
            .is_err()
    );
    assert_eq!(
        accounts.password(&t, &a).await.unwrap().as_deref(),
        Some("old")
    );

    accounts.set_password(&t, &b, "bee").await.unwrap();
    let legacy_b = keyring
        .seal(&KeyScope::tenant_of(&t), "credentials/b/password", b"bee")
        .await
        .unwrap();
    let webhook = keyring
        .seal(&KeyScope::tenant_of(&t), "webhooks/w1", b"hook")
        .await
        .unwrap();
    let (sealed_b, _) = control
        .get(&t, "credentials/b/password")
        .await
        .unwrap()
        .unwrap();
    for planted in [sealed_b.to_vec(), legacy_b, webhook] {
        control
            .put(
                &t,
                "credentials/a/password",
                Bytes::from(planted),
                Expect::Any,
            )
            .await
            .unwrap();
        assert!(
            matches!(
                accounts.password(&t, &a).await,
                Err(AccountError::Keyring(skein_keyring::KeyringError::Invalid))
            ),
            "another account's or another context's secret is refused"
        );
    }

    accounts.set_password(&t, &a, "new").await.unwrap();
    keyring
        .destroy(&KeyScope::account_of(&t, &a))
        .await
        .unwrap();
    assert!(matches!(
        accounts.password(&t, &a).await,
        Err(AccountError::Keyring(
            skein_keyring::KeyringError::Destroyed
        ))
    ));
    assert_eq!(
        accounts.password(&t, &b).await.unwrap().as_deref(),
        Some("bee")
    );
}
