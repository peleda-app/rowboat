//! The conformance suite every [`Keystore`] runs.
//!
//! ```ignore
//! #[tokio::test]
//! async fn conformance() {
//!     let backing = MyBacking::new();
//!     rowboat_keystore::testing::keystore(&|| Arc::new(MyKeystore::over(backing.clone()))).await;
//! }
//! ```

use std::sync::Arc;

use crate::{KeyClass, KeyName, Keystore, KeystoreError, MAX_SECRET, Secret};

fn name(text: &str) -> KeyName {
    KeyName::new(text).unwrap()
}

/// Runs the whole suite. `factory` gives a new instance over the same backing store on every
/// call, so persistence across instances can be checked. Uses names under `conformance.`.
pub async fn keystore(factory: &(dyn Fn() -> Arc<dyn Keystore> + Send + Sync)) {
    let store = factory();
    let a = name("conformance.a");
    let b = name("conformance.b");
    let _ = store.delete(&a).await;
    let _ = store.delete(&b).await;

    assert_eq!(store.get(&a).await.unwrap(), None, "missing item");
    assert!(!store.delete(&a).await.unwrap(), "deleting a missing item");

    store
        .put(&a, &Secret::from_text("first"), KeyClass::Background)
        .await
        .unwrap();
    store
        .put(&b, &Secret::new(vec![0, 255, 7]), KeyClass::Foreground)
        .await
        .unwrap();
    assert_eq!(
        store.get(&a).await.unwrap().unwrap().expose(),
        b"first",
        "round trip"
    );
    assert_eq!(store.get(&b).await.unwrap().unwrap().expose(), &[0, 255, 7]);

    store
        .put(&a, &Secret::from_text("second"), KeyClass::Background)
        .await
        .unwrap();
    assert_eq!(
        store.get(&a).await.unwrap().unwrap().expose(),
        b"second",
        "replace"
    );

    let again = factory();
    assert_eq!(
        again.get(&a).await.unwrap().unwrap().expose(),
        b"second",
        "persistence across instances"
    );

    let big = Secret::new(vec![42; MAX_SECRET]);
    store.put(&b, &big, KeyClass::Background).await.unwrap();
    assert_eq!(store.get(&b).await.unwrap().unwrap(), big, "largest secret");
    assert_eq!(
        store.get(&a).await.unwrap().unwrap().expose(),
        b"second",
        "no cross-talk"
    );

    assert!(store.delete(&a).await.unwrap(), "delete");
    assert_eq!(store.get(&a).await.unwrap(), None);
    assert_eq!(again.get(&a).await.unwrap(), None, "delete persists");
    assert!(store.delete(&b).await.unwrap());

    assert_eq!(
        KeyName::new("../escape").unwrap_err(),
        KeystoreError::InvalidName
    );
    for e in [
        KeystoreError::InvalidName,
        KeystoreError::Locked,
        KeystoreError::Denied,
        KeystoreError::Unsupported,
        KeystoreError::Backend,
    ] {
        assert!(!e.to_string().contains("conformance"));
    }
}

/// For stores that can inject a failing write: after `fail_next_put` is armed, a `put` fails
/// and the previous item stays readable unchanged.
pub async fn failed_put_keeps_the_old_item(store: Arc<dyn Keystore>, fail_next_put: &dyn Fn()) {
    let a = name("conformance.atomic");
    store
        .put(&a, &Secret::from_text("old"), KeyClass::Background)
        .await
        .unwrap();
    fail_next_put();
    assert!(
        store
            .put(&a, &Secret::from_text("new"), KeyClass::Background)
            .await
            .is_err()
    );
    assert_eq!(store.get(&a).await.unwrap().unwrap().expose(), b"old");
    store.delete(&a).await.unwrap();
}
