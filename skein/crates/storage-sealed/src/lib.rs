//! Skein's [`Objects`] contract over any other object store, with every value sealed.
//!
//! A sealed value is `version (1) || nonce (24) || XChaCha20-Poly1305 ciphertext and tag`, with
//! the format version, a fixed context and the full object key as associated data. A value moved
//! or copied to another key, cut, extended, bit-flipped or written under another key does not
//! open: reads fail with [`StorageError::Corrupt`] and never return bytes that were not sealed for
//! that key. Keys themselves stay readable (they hold tenant, account and mailbox ids and blob
//! hashes, never content). Versions, compare-and-swap, listing and deletion pass through to the
//! inner store unchanged.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use skein_storage::{Expect, ObjectKey, Objects, StorageError, Version};
use zeroize::Zeroizing;

/// The format version written as the first byte of every sealed value.
pub const FORMAT: u8 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CONTEXT: &[u8] = b"skein-storage-sealed v1";

/// Sealed values over an inner [`Objects`].
pub struct SealedObjects {
    inner: Arc<dyn Objects>,
    cipher: XChaCha20Poly1305,
}

impl SealedObjects {
    /// Seals every value written to `inner` with the 256-bit `key`. The caller keeps the key
    /// secret and passes the same key on every start; values sealed under another key never open.
    pub fn new(inner: Arc<dyn Objects>, key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            inner,
            cipher: XChaCha20Poly1305::new(&(*key).into()),
        }
    }

    fn aad(key: &ObjectKey) -> Vec<u8> {
        let mut aad = Vec::with_capacity(CONTEXT.len() + 2 + key.as_str().len());
        aad.extend_from_slice(CONTEXT);
        aad.push(0);
        aad.push(FORMAT);
        aad.extend_from_slice(key.as_str().as_bytes());
        aad
    }

    fn seal(&self, key: &ObjectKey, value: &[u8]) -> Result<Bytes, StorageError> {
        let nonce = XNonce::generate();
        let ct = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: value,
                    aad: &Self::aad(key),
                },
            )
            .map_err(|_| StorageError::Corrupt("sealing failed".into()))?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(FORMAT);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(Bytes::from(out))
    }

    fn open(&self, key: &ObjectKey, sealed: &[u8]) -> Result<Bytes, StorageError> {
        let refused = || StorageError::Corrupt(format!("sealed value at {key} does not open"));
        let Some((&version, rest)) = sealed.split_first() else {
            return Err(refused());
        };
        if version != FORMAT || rest.len() < NONCE_LEN + TAG_LEN {
            return Err(refused());
        }
        let (nonce, ct) = rest.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).map_err(|_| refused())?;
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ct,
                    aad: &Self::aad(key),
                },
            )
            .map(Bytes::from)
            .map_err(|_| refused())
    }
}

#[async_trait]
impl Objects for SealedObjects {
    async fn get(&self, key: &ObjectKey) -> Result<Option<(Bytes, Version)>, StorageError> {
        match self.inner.get(key).await? {
            None => Ok(None),
            Some((sealed, version)) => Ok(Some((self.open(key, &sealed)?, version))),
        }
    }

    async fn put(
        &self,
        key: &ObjectKey,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError> {
        let sealed = self.seal(key, &value)?;
        self.inner.put(key, sealed, expect).await
    }

    async fn delete(&self, key: &ObjectKey, expect: Expect) -> Result<(), StorageError> {
        self.inner.delete(key, expect).await
    }

    async fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError> {
        self.inner.list(prefix, start_after, limit).await
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use skein_storage_memory::MemoryObjects;

    use super::*;

    fn key(text: &str) -> ObjectKey {
        ObjectKey::parse(text).unwrap()
    }

    fn sealed(inner: Arc<dyn Objects>, byte: u8) -> SealedObjects {
        SealedObjects::new(inner, Zeroizing::new([byte; 32]))
    }

    #[tokio::test]
    async fn conformance() {
        let inner: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        skein_storage::testing::all_over_objects(Arc::new(sealed(inner, 9))).await;
    }

    #[tokio::test]
    async fn the_inner_store_holds_only_ciphertext() {
        let inner: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        let store = sealed(inner.clone(), 1);
        let k = key("tenants/acme/control/accounts/box");
        store
            .put(
                &k,
                Bytes::from_static(b"canary-password-0451"),
                Expect::Absent,
            )
            .await
            .unwrap();
        let (raw, _) = inner.get(&k).await.unwrap().unwrap();
        assert_eq!(raw[0], FORMAT);
        assert!(!raw.windows(6).any(|w| w == b"canary"));
        assert_eq!(
            store.get(&k).await.unwrap().unwrap().0,
            Bytes::from_static(b"canary-password-0451")
        );
    }

    #[tokio::test]
    async fn moved_truncated_flipped_and_foreign_values_do_not_open() {
        let inner: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        let store = sealed(inner.clone(), 1);
        let a = key("tenants/acme/blobs/aaaa");
        let b = key("tenants/acme/blobs/bbbb");
        store
            .put(&a, Bytes::from_static(b"secret value"), Expect::Any)
            .await
            .unwrap();
        let (raw, _) = inner.get(&a).await.unwrap().unwrap();

        inner.put(&b, raw.clone(), Expect::Any).await.unwrap();
        assert!(matches!(store.get(&b).await, Err(StorageError::Corrupt(_))));

        for cut in [0, 1, 24, raw.len() - 1] {
            inner.put(&a, raw.slice(..cut), Expect::Any).await.unwrap();
            assert!(
                matches!(store.get(&a).await, Err(StorageError::Corrupt(_))),
                "cut at {cut}"
            );
        }
        for i in 0..raw.len() {
            let mut flipped = raw.to_vec();
            flipped[i] ^= 0x40;
            inner
                .put(&a, Bytes::from(flipped), Expect::Any)
                .await
                .unwrap();
            assert!(store.get(&a).await.is_err(), "flip at {i}");
        }
        let mut longer = raw.to_vec();
        longer.push(0);
        inner
            .put(&a, Bytes::from(longer), Expect::Any)
            .await
            .unwrap();
        assert!(store.get(&a).await.is_err());

        inner.put(&a, raw.clone(), Expect::Any).await.unwrap();
        let other = sealed(inner.clone(), 2);
        assert!(matches!(other.get(&a).await, Err(StorageError::Corrupt(_))));
        assert!(store.get(&a).await.unwrap().is_some());

        let mut downgraded = raw.to_vec();
        downgraded[0] = 0;
        inner
            .put(&a, Bytes::from(downgraded), Expect::Any)
            .await
            .unwrap();
        assert!(store.get(&a).await.is_err());
    }

    #[tokio::test]
    async fn errors_name_the_key_but_never_the_value() {
        let inner: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        let store = sealed(inner.clone(), 1);
        let k = key("tenants/acme/control/x");
        inner
            .put(
                &k,
                Bytes::from_static(b"\x01plaintext-canary-plaintext-canary-xx"),
                Expect::Any,
            )
            .await
            .unwrap();
        let e = store.get(&k).await.unwrap_err().to_string();
        assert!(!e.contains("canary"), "{e}");
    }

    proptest! {
        #[test]
        fn any_value_round_trips_and_any_garbage_is_refused(
            value in proptest::collection::vec(any::<u8>(), 0..512),
            garbage in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let inner: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
                let store = sealed(inner.clone(), 3);
                let k = key("tenants/acme/blobs/c");
                store.put(&k, Bytes::from(value.clone()), Expect::Any).await.unwrap();
                prop_assert_eq!(store.get(&k).await.unwrap().unwrap().0.to_vec(), value);
                inner.put(&k, Bytes::from(garbage), Expect::Any).await.unwrap();
                prop_assert!(store.get(&k).await.is_err());
                Ok(())
            })?;
        }
    }
}
