//! A [`Keystore`] in memory. Clones share their items, so a clone stands in for a second
//! instance over the same backing store. Faults can be injected for tests: a locked store, a
//! failing next write, a lost item.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rowboat_keystore::{KeyClass, KeyName, Keystore, KeystoreError, MAX_SECRET, Secret};

#[derive(Default)]
struct Inner {
    items: Mutex<BTreeMap<KeyName, (Secret, KeyClass)>>,
    locked: AtomicBool,
    fail_next_put: AtomicBool,
}

/// An in-memory keystore; clones share their items and faults.
#[derive(Clone, Default)]
pub struct MemoryKeystore {
    inner: Arc<Inner>,
}

impl MemoryKeystore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// While `locked`, reads of existing items fail with [`KeystoreError::Locked`].
    pub fn set_locked(&self, locked: bool) {
        self.inner.locked.store(locked, Ordering::SeqCst);
    }

    /// Makes the next `put` fail with [`KeystoreError::Backend`] and change nothing.
    pub fn fail_next_put(&self) {
        self.inner.fail_next_put.store(true, Ordering::SeqCst);
    }

    /// The class the item was stored with, for tests.
    pub fn class_of(&self, name: &KeyName) -> Option<KeyClass> {
        self.lock().get(name).map(|(_, c)| *c)
    }

    /// Replaces an item's bytes behind the node's back, for tests.
    pub fn tamper(&self, name: &KeyName, secret: Secret) {
        if let Some(item) = self.lock().get_mut(name) {
            item.0 = secret;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<KeyName, (Secret, KeyClass)>> {
        self.inner.items.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl Keystore for MemoryKeystore {
    async fn get(&self, name: &KeyName) -> Result<Option<Secret>, KeystoreError> {
        let items = self.lock();
        match items.get(name) {
            None => Ok(None),
            Some(_) if self.inner.locked.load(Ordering::SeqCst) => Err(KeystoreError::Locked),
            Some((secret, _)) => Ok(Some(secret.clone())),
        }
    }

    async fn put(
        &self,
        name: &KeyName,
        secret: &Secret,
        class: KeyClass,
    ) -> Result<(), KeystoreError> {
        if self.inner.fail_next_put.swap(false, Ordering::SeqCst) {
            return Err(KeystoreError::Backend);
        }
        if secret.len() > MAX_SECRET {
            return Err(KeystoreError::Unsupported);
        }
        self.lock().insert(name.clone(), (secret.clone(), class));
        Ok(())
    }

    async fn delete(&self, name: &KeyName) -> Result<bool, KeystoreError> {
        Ok(self.lock().remove(name).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn conformance() {
        let backing = MemoryKeystore::new();
        rowboat_keystore::testing::keystore(&|| Arc::new(backing.clone()) as Arc<dyn Keystore>)
            .await;
        let fault = backing.clone();
        rowboat_keystore::testing::failed_put_keeps_the_old_item(
            Arc::new(backing.clone()),
            &move || fault.fail_next_put(),
        )
        .await;
    }

    #[tokio::test]
    async fn a_locked_store_refuses_reads_of_existing_items_only() {
        let store = MemoryKeystore::new();
        let name = KeyName::new("rowboat.master").unwrap();
        store
            .put(&name, &Secret::from_text("k"), KeyClass::Background)
            .await
            .unwrap();
        store.set_locked(true);
        assert_eq!(store.get(&name).await, Err(KeystoreError::Locked));
        assert_eq!(store.get(&KeyName::new("other").unwrap()).await, Ok(None));
        assert_eq!(store.class_of(&name), Some(KeyClass::Background));
        let too_big = Secret::new(vec![0; MAX_SECRET + 1]);
        assert_eq!(
            store.put(&name, &too_big, KeyClass::Background).await,
            Err(KeystoreError::Unsupported)
        );
    }
}
