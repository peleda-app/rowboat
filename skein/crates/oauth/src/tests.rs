use std::sync::Arc;
use std::time::Duration;

use baton_signal::Signal;
use baton_signal_local::LocalSignal;
use skein_core::{AccountId, TenantId, Timestamp};
use skein_keyring::Keyring;
use skein_keyring_local::LocalKeyring;
use skein_storage::{ControlStore, ObjectControl};
use skein_storage_memory::MemoryObjects;

use crate::testing::FakeTokenEndpoint;
use crate::*;

fn google() -> Client {
    Client::new(
        Provider::Google,
        "client-id",
        Some("client-secret".into()),
        "https://app.example.com/oauth/callback",
        &Access {
            mail: MailAccess::Api,
            mail_write: true,
            ..Default::default()
        },
    )
    .unwrap()
}

fn microsoft() -> Client {
    Client::new(
        Provider::Microsoft,
        "ms-client",
        None,
        "https://app.example.com/oauth/callback",
        &Access {
            mail: MailAccess::Api,
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn pkce_matches_the_rfc_7636_example() {
    assert_eq!(
        challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn authorize_url_carries_pkce_state_and_offline_access() {
    let auth = google().authorize(Some("ada@example.com")).unwrap();
    let url = url::Url::parse(&auth.url).unwrap();
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["state"], auth.state);
    assert_eq!(q["code_challenge"], challenge(&auth.verifier));
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["access_type"], "offline");
    assert_eq!(q["login_hint"], "ada@example.com");
    assert!(
        !auth.url.contains(&auth.verifier),
        "the verifier never leaves"
    );
    assert_ne!(
        auth.state,
        google().authorize(None).unwrap().state,
        "states are random"
    );
    assert!(!format!("{auth:?}").contains(&auth.state));
}

#[test]
fn microsoft_tenants_are_checked() {
    let c = microsoft()
        .with_microsoft_tenant("contoso.onmicrosoft.com")
        .unwrap();
    assert!(c.token_url.contains("/contoso.onmicrosoft.com/"));
    assert!(microsoft().with_microsoft_tenant("evil/../x").is_err());
    assert!(microsoft().with_microsoft_tenant("").is_err());
}

#[tokio::test]
async fn completing_checks_the_state_before_exchanging() {
    let endpoint = FakeTokenEndpoint::default();
    let client = google();
    let auth = client.authorize(None).unwrap();
    let foreign = Redirect {
        code: "code".into(),
        state: "someone-else".into(),
    };
    assert!(matches!(
        client.complete(&endpoint, &auth, &foreign).await,
        Err(OAuthError::Redirect(_))
    ));
    assert!(
        endpoint.requests().is_empty(),
        "nothing is sent for a foreign answer"
    );

    endpoint.tokens("access-1", Some("refresh-1"), 3599);
    let ours = Redirect {
        code: "code-1".into(),
        state: auth.state.clone(),
    };
    let tokens = client.complete(&endpoint, &auth, &ours).await.unwrap();
    assert_eq!(tokens.access_token, "access-1");
    assert_eq!(endpoint.last("code_verifier").unwrap(), auth.verifier);
    assert_eq!(endpoint.last("grant_type").unwrap(), "authorization_code");
    assert!(!format!("{tokens:?}").contains("access-1"));
}

#[tokio::test]
async fn refresh_errors_map_to_what_helps() {
    let endpoint = FakeTokenEndpoint::default();
    let client = microsoft();
    endpoint.error("invalid_grant");
    assert!(matches!(
        client.refresh(&endpoint, "r").await,
        Err(OAuthError::Revoked(_))
    ));
    assert_eq!(
        endpoint.last("scope").unwrap(),
        client.scope,
        "Microsoft refreshes with the scope"
    );
    endpoint.error("temporarily_unavailable");
    let e = client.refresh(&endpoint, "r").await.unwrap_err();
    assert!(e.is_transient());
    endpoint.error("invalid_client");
    assert!(matches!(
        client.refresh(&endpoint, "r").await,
        Err(OAuthError::Rejected(_))
    ));
    endpoint.answer(500, serde_json::json!({}));
    assert!(matches!(
        client.refresh(&endpoint, "r").await,
        Err(OAuthError::Protocol(_))
    ));
}

struct Fixture {
    endpoint: Arc<FakeTokenEndpoint>,
    control: Arc<dyn ControlStore>,
    eph: Arc<dyn Signal>,
    manager: Arc<TokenManager>,
    tenant: TenantId,
    account: AccountId,
}

fn fixture() -> Fixture {
    let objects = Arc::new(MemoryObjects::new());
    let control: Arc<dyn ControlStore> = Arc::new(ObjectControl::new(objects));
    let keyring: Arc<dyn Keyring> = Arc::new(LocalKeyring::from_master([3; 32], control.clone()));
    let endpoint = Arc::new(FakeTokenEndpoint::default());
    let eph: Arc<dyn Signal> = Arc::new(LocalSignal::new());
    let manager = Arc::new(
        TokenManager::new(endpoint.clone(), control.clone(), keyring).with_signal(eph.clone()),
    );
    Fixture {
        endpoint,
        control,
        eph,
        manager,
        tenant: TenantId::new("t").unwrap(),
        account: AccountId::new("acc").unwrap(),
    }
}

#[tokio::test]
async fn refreshes_expired_tokens_once_and_keeps_rotated_refresh_tokens() {
    let f = fixture();
    let expired = Grant {
        refresh_token: Some("refresh-1".into()),
        access_token: Some("old".into()),
        expires_at: Some(Timestamp::now().plus_ms(-1)),
        scope: None,
    };
    f.manager
        .store(&f.tenant, &f.account, &expired)
        .await
        .unwrap();
    f.endpoint.tokens("access-2", Some("refresh-2"), 3600);

    let client = microsoft();
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let (m, t, a, c) = (
            f.manager.clone(),
            f.tenant.clone(),
            f.account.clone(),
            client.clone(),
        );
        tasks.push(tokio::spawn(
            async move { m.access_token(&t, &a, &c).await },
        ));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap(), "access-2");
    }
    assert_eq!(
        f.endpoint.requests().len(),
        1,
        "concurrent callers refresh once"
    );
    assert_eq!(f.endpoint.last("refresh_token").unwrap(), "refresh-1");

    let (bytes, _) = f
        .control
        .get(&f.tenant, "credentials/acc/oauth")
        .await
        .unwrap()
        .unwrap();
    for secret in ["refresh-2", "access-2"] {
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "grants are stored sealed"
        );
    }
    let cached = f
        .eph
        .get(&skein_core::coordination::group(&f.tenant), "oauth/acc")
        .await
        .unwrap()
        .unwrap();
    assert!(
        !cached.windows(8).any(|w| w == b"access-2"),
        "the cache is sealed too"
    );

    let other = TokenManager::new(
        f.endpoint.clone(),
        f.control.clone(),
        Arc::new(LocalKeyring::from_master([3; 32], f.control.clone())),
    );
    assert_eq!(
        other
            .access_token(&f.tenant, &f.account, &client)
            .await
            .unwrap(),
        "access-2",
        "another node uses the stored token instead of refreshing"
    );
    assert_eq!(f.endpoint.requests().len(), 1);

    let soon = Grant {
        expires_at: Some(Timestamp::now().plus_ms(30_000)),
        ..Grant::external("about-to-expire", None, Some("refresh-2".into()))
    };
    other.store(&f.tenant, &f.account, &soon).await.unwrap();
    f.endpoint.tokens("access-3", None, 3600);
    assert_eq!(
        other
            .access_token(&f.tenant, &f.account, &client)
            .await
            .unwrap(),
        "access-3"
    );
    assert_eq!(f.endpoint.last("refresh_token").unwrap(), "refresh-2");
    f.endpoint.tokens("never-used", None, 3600);
    let again = TokenManager::new(
        f.endpoint.clone(),
        f.control.clone(),
        Arc::new(LocalKeyring::from_master([3; 32], f.control.clone())),
    );
    assert_eq!(
        again
            .access_token(&f.tenant, &f.account, &client)
            .await
            .unwrap(),
        "access-3",
        "a refresh without a new refresh token keeps the old one"
    );
}

#[tokio::test]
async fn revoked_and_missing_grants_are_reported() {
    let f = fixture();
    let client = google();
    assert!(matches!(
        f.manager.access_token(&f.tenant, &f.account, &client).await,
        Err(OAuthError::NoGrant)
    ));
    let handed_in = Grant::external("tok", Some(Timestamp::now().plus_ms(-5)), None);
    f.manager
        .store(&f.tenant, &f.account, &handed_in)
        .await
        .unwrap();
    assert!(matches!(
        f.manager.access_token(&f.tenant, &f.account, &client).await,
        Err(OAuthError::Revoked(_))
    ));
    let with_refresh = Grant::external("tok", Some(Timestamp::now().plus_ms(-5)), Some("r".into()));
    f.manager
        .store(&f.tenant, &f.account, &with_refresh)
        .await
        .unwrap();
    f.endpoint.error("invalid_grant");
    assert!(matches!(
        f.manager.access_token(&f.tenant, &f.account, &client).await,
        Err(OAuthError::Revoked(_))
    ));
    let forever = Grant::external("no-expiry", None, None);
    f.manager
        .store(&f.tenant, &f.account, &forever)
        .await
        .unwrap();
    assert_eq!(
        f.manager
            .access_token(&f.tenant, &f.account, &client)
            .await
            .unwrap(),
        "no-expiry"
    );
    f.manager.forget(&f.tenant, &f.account).await.unwrap();
    assert!(matches!(
        f.manager.access_token(&f.tenant, &f.account, &client).await,
        Err(OAuthError::NoGrant)
    ));
    let _ = Duration::ZERO;
}

#[test]
fn grants_never_show_tokens() {
    let g = Grant::external("secret-access", None, Some("secret-refresh".into()));
    let text = format!("{g:?}");
    assert!(!text.contains("secret"));
    let c = google();
    assert!(!format!("{c:?}").contains("client-secret"));
}

#[test]
fn reads_pasted_redirects() {
    let r = read_redirect("https://app.example.com/oauth/callback?code=abc&state=xyz").unwrap();
    assert_eq!((r.code.as_str(), r.state.as_str()), ("abc", "xyz"));
    assert!(matches!(
        read_redirect("https://app.example.com/cb?error=access_denied"),
        Err(OAuthError::Denied(_))
    ));
    assert!(read_redirect("https://app.example.com/cb?state=x").is_err());
    assert!(read_redirect("").is_err());
}

#[tokio::test]
async fn grants_sealed_under_the_tenant_are_resealed_under_the_account() {
    let f = fixture();
    let keyring = LocalKeyring::from_master([3; 32], f.control.clone());
    let grant = Grant::external(
        "legacy-access",
        Some(Timestamp::now().plus_ms(3_600_000)),
        Some("refresh".into()),
    );
    let legacy = keyring
        .seal(
            &skein_keyring::KeyScope::tenant_of(&f.tenant),
            "credentials/acc/oauth",
            &serde_json::to_vec(&grant).unwrap(),
        )
        .await
        .unwrap();
    f.control
        .put(
            &f.tenant,
            "credentials/acc/oauth",
            bytes::Bytes::from(legacy),
            skein_storage::Expect::Absent,
        )
        .await
        .unwrap();
    assert_eq!(
        f.manager
            .access_token(&f.tenant, &f.account, &microsoft())
            .await
            .unwrap(),
        "legacy-access"
    );
    let (now, _) = f
        .control
        .get(&f.tenant, "credentials/acc/oauth")
        .await
        .unwrap()
        .unwrap();
    let opened = keyring
        .open(
            &skein_keyring::KeyScope::account_of(&f.tenant, &f.account),
            "credentials/acc/oauth",
            &now,
        )
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<Grant>(&opened).unwrap(), grant);
    assert!(f.endpoint.requests().is_empty());

    let other = AccountId::new("other").unwrap();
    f.control
        .put(
            &f.tenant,
            "credentials/other/oauth",
            now,
            skein_storage::Expect::Absent,
        )
        .await
        .unwrap();
    assert!(
        f.manager
            .access_token(&f.tenant, &other, &microsoft())
            .await
            .is_err(),
        "another account's grant does not open"
    );
}
