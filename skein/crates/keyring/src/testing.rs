//! Conformance suite for [`Keyring`].

use std::sync::Arc;

use skein_core::{AccountId, TenantId};

use crate::{KeyScope, Keyring, KeyringError, Opened, open_account};

fn tenant(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

fn account(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

/// The [`Keyring`] contract. `other` must be a second keyring over the same key store (another
/// node), to check that concurrent first use agrees on one key. Both must see destruction made by
/// the other at once (a cache lifetime of zero).
pub async fn keyring(ring: Arc<dyn Keyring>, other: Arc<dyn Keyring>) {
    tenant_scope(&*ring, &*other).await;
    account_scopes(&*ring, &*other).await;
    account_destruction(&*ring, &*other).await;
    tenant_destruction(&*ring, &*other).await;
    legacy_fallback(&*ring).await;
}

async fn tenant_scope(ring: &dyn Keyring, other: &dyn Keyring) {
    let t1 = KeyScope::Tenant(tenant("conf-keyring-1"));
    let t2 = KeyScope::Tenant(tenant("conf-keyring-2"));

    let (a, b) = tokio::join!(
        ring.seal(&t1, "credentials/acc", b"hunter2"),
        other.seal(&t1, "credentials/acc", b"hunter2")
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a, b, "random nonces");
    assert_eq!(
        other.open(&t1, "credentials/acc", &a).await.unwrap(),
        b"hunter2"
    );
    assert_eq!(
        ring.open(&t1, "credentials/acc", &b).await.unwrap(),
        b"hunter2"
    );
    assert!(
        !a.windows(7).any(|w| w == b"hunter2"),
        "the plaintext does not show"
    );

    assert!(matches!(
        ring.open(&t1, "credentials/other", &a).await,
        Err(KeyringError::Invalid)
    ));
    assert!(matches!(
        ring.open(&t2, "credentials/acc", &a).await,
        Err(KeyringError::Invalid)
    ));
    tampering_is_detected(ring, &t1, "credentials/acc", &a).await;

    let kept = ring.seal(&t2, "c", b"x").await.unwrap();
    ring.destroy(&t1).await.unwrap();
    assert!(matches!(
        ring.open(&t1, "credentials/acc", &a).await,
        Err(KeyringError::Destroyed)
    ));
    assert!(matches!(
        other.open(&t1, "credentials/acc", &b).await,
        Err(KeyringError::Destroyed)
    ));
    assert!(matches!(
        ring.seal(&t1, "c", b"x").await,
        Err(KeyringError::Destroyed)
    ));
    assert_eq!(ring.open(&t2, "c", &kept).await.unwrap(), b"x");
}

async fn tampering_is_detected(ring: &dyn Keyring, scope: &KeyScope, context: &str, sealed: &[u8]) {
    for i in 0..sealed.len() {
        let mut bad = sealed.to_vec();
        bad[i] ^= 1;
        assert!(
            ring.open(scope, context, &bad).await.is_err(),
            "flipping byte {i} is detected"
        );
    }
    assert!(
        ring.open(scope, context, &sealed[..sealed.len() - 1])
            .await
            .is_err()
    );
    let mut longer = sealed.to_vec();
    longer.push(0);
    assert!(ring.open(scope, context, &longer).await.is_err());
    assert!(ring.open(scope, context, &[]).await.is_err());
}

async fn account_scopes(ring: &dyn Keyring, other: &dyn Keyring) {
    let t = tenant("conf-keyring-3");
    let t_other = tenant("conf-keyring-4");
    let a = KeyScope::account_of(&t, &account("alice"));
    let b = KeyScope::account_of(&t, &account("bob"));
    let tenant_scope = KeyScope::tenant_of(&t);
    let same_id_elsewhere = KeyScope::account_of(&t_other, &account("alice"));

    let (x, y) = tokio::join!(
        ring.seal(&a, "credentials/alice", b"s3cret"),
        other.seal(&a, "credentials/alice", b"s3cret")
    );
    let (x, y) = (x.unwrap(), y.unwrap());
    assert_ne!(x, y, "random nonces");
    assert_eq!(
        other.open(&a, "credentials/alice", &x).await.unwrap(),
        b"s3cret",
        "concurrent first use of an account agrees on one key"
    );
    assert_eq!(
        ring.open(&a, "credentials/alice", &y).await.unwrap(),
        b"s3cret"
    );
    assert!(!x.windows(6).any(|w| w == b"s3cret"));

    for scope in [&b, &tenant_scope, &same_id_elsewhere] {
        assert!(
            matches!(
                ring.open(scope, "credentials/alice", &x).await,
                Err(KeyringError::Invalid)
            ),
            "an account's bytes do not open under {scope:?}"
        );
    }
    assert!(matches!(
        ring.open(&a, "credentials/bob", &x).await,
        Err(KeyringError::Invalid)
    ));
    tampering_is_detected(ring, &a, "credentials/alice", &x).await;

    let by_tenant = ring
        .seal(&tenant_scope, "credentials/alice", b"t")
        .await
        .unwrap();
    for scope in [&a, &b] {
        assert!(
            matches!(
                ring.open(scope, "credentials/alice", &by_tenant).await,
                Err(KeyringError::Invalid)
            ),
            "tenant bytes do not open under {scope:?}"
        );
    }
    let by_bob = ring.seal(&b, "credentials/alice", b"b").await.unwrap();
    assert!(matches!(
        ring.open(&a, "credentials/alice", &by_bob).await,
        Err(KeyringError::Invalid)
    ));
}

async fn account_destruction(ring: &dyn Keyring, other: &dyn Keyring) {
    let t = tenant("conf-keyring-5");
    let gone = KeyScope::account_of(&t, &account("gone"));
    let kept = KeyScope::account_of(&t, &account("kept"));
    let tenant_scope = KeyScope::tenant_of(&t);

    let sealed = ring.seal(&gone, "c", b"x").await.unwrap();
    let sealed_kept = ring.seal(&kept, "c", b"y").await.unwrap();
    let sealed_tenant = ring.seal(&tenant_scope, "c", b"z").await.unwrap();
    other.destroy(&gone).await.unwrap();
    for r in [ring, other] {
        assert!(matches!(
            r.open(&gone, "c", &sealed).await,
            Err(KeyringError::Destroyed)
        ));
        assert!(matches!(
            r.seal(&gone, "c", b"x").await,
            Err(KeyringError::Destroyed)
        ));
        assert!(
            matches!(
                open_account(r, &t, &account("gone"), "c", &sealed).await,
                Err(KeyringError::Destroyed)
            ),
            "a destroyed account does not open through its tenant"
        );
    }
    assert_eq!(ring.open(&kept, "c", &sealed_kept).await.unwrap(), b"y");
    assert_eq!(
        ring.open(&tenant_scope, "c", &sealed_tenant).await.unwrap(),
        b"z"
    );
    ring.destroy(&gone).await.unwrap();
    assert!(matches!(
        ring.seal(&gone, "c", b"x").await,
        Err(KeyringError::Destroyed)
    ));

    let never_used = KeyScope::account_of(&t, &account("never-used"));
    ring.destroy(&never_used).await.unwrap();
    assert!(
        matches!(
            other.seal(&never_used, "c", b"x").await,
            Err(KeyringError::Destroyed)
        ),
        "an account destroyed before first use stays destroyed"
    );
}

async fn tenant_destruction(ring: &dyn Keyring, other: &dyn Keyring) {
    let t = tenant("conf-keyring-6");
    let spared = tenant("conf-keyring-7");
    let a = KeyScope::account_of(&t, &account("a"));
    let b = KeyScope::account_of(&t, &account("b"));
    let spared_a = KeyScope::account_of(&spared, &account("a"));

    let sealed_a = ring.seal(&a, "c", b"x").await.unwrap();
    let sealed_spared = ring.seal(&spared_a, "c", b"y").await.unwrap();
    ring.destroy(&KeyScope::tenant_of(&t)).await.unwrap();
    for r in [ring, other] {
        assert!(matches!(
            r.open(&a, "c", &sealed_a).await,
            Err(KeyringError::Destroyed)
        ));
        assert!(matches!(
            r.seal(&a, "c", b"x").await,
            Err(KeyringError::Destroyed)
        ));
        assert!(
            matches!(r.seal(&b, "c", b"x").await, Err(KeyringError::Destroyed)),
            "an account first used after its tenant was destroyed has no key"
        );
    }
    assert_eq!(
        other.open(&spared_a, "c", &sealed_spared).await.unwrap(),
        b"y"
    );
}

async fn legacy_fallback(ring: &dyn Keyring) {
    let t = tenant("conf-keyring-8");
    let alice = account("alice");
    let tenant_scope = KeyScope::tenant_of(&t);

    let legacy = ring
        .seal(&tenant_scope, "credentials/alice", b"old")
        .await
        .unwrap();
    assert_eq!(
        open_account(ring, &t, &alice, "credentials/alice", &legacy)
            .await
            .unwrap(),
        Opened::Legacy(b"old".to_vec())
    );
    let current = ring
        .seal(
            &KeyScope::account_of(&t, &alice),
            "credentials/alice",
            b"new",
        )
        .await
        .unwrap();
    assert_eq!(
        open_account(ring, &t, &alice, "credentials/alice", &current)
            .await
            .unwrap(),
        Opened::Account(b"new".to_vec())
    );
    assert!(
        matches!(
            open_account(ring, &t, &alice, "credentials/bob", &legacy).await,
            Err(KeyringError::Invalid)
        ),
        "the fallback keeps the context binding"
    );
    assert!(matches!(
        open_account(ring, &t, &account("bob"), "credentials/bob", &current).await,
        Err(KeyringError::Invalid)
    ));
    let elsewhere = tenant("conf-keyring-9");
    assert!(matches!(
        open_account(ring, &elsewhere, &alice, "credentials/alice", &legacy).await,
        Err(KeyringError::Invalid)
    ));
}
