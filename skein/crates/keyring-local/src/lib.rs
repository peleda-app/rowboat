//! A [`Keyring`] with a random data key per tenant, wrapped by a 256-bit master key from a local
//! file and stored as the control record `keys/data` of the tenant, and a random data key per
//! account, wrapped by a key derived from its tenant's key and stored as `keys/accounts/{account}`.
//!
//! Sealed bytes are `version || nonce (24) || XChaCha20-Poly1305 ciphertext and tag`: version 1
//! under a tenant key with `tenant \0 context` as associated data, version 2 under an account key
//! with `tenant \0 account \0 context`. Destroying a scope replaces its record with a tombstone, so
//! the key cannot come back; account keys are unreadable without their tenant's key, so destroying
//! a tenant destroys its accounts' keys, copies in backups included.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use chacha20poly1305::aead::{Aead, Generate, Key, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use skein_core::AccountId;
use skein_keyring::{KeyScope, Keyring, KeyringError};
use skein_storage::{ControlStore, Expect, StorageError};

const TENANT_VERSION: u8 = 1;
const ACCOUNT_VERSION: u8 = 2;
const NONCE_LEN: usize = 24;
const TENANT_RECORD: &str = "keys/data";
const ACCOUNT_WRAP_CONTEXT: &str = "skein keyring-local account key wrap v1";

fn account_record(account: &AccountId) -> String {
    format!("keys/accounts/{account}")
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum KeyRecord {
    Active { wrapped: String },
    Destroyed,
}

struct ScopeKey {
    data: XChaCha20Poly1305,
    wrap: XChaCha20Poly1305,
}

impl ScopeKey {
    fn new(raw: &[u8]) -> Result<Self, KeyringError> {
        let raw: [u8; 32] = raw.try_into().map_err(|_| KeyringError::Invalid)?;
        Ok(Self {
            data: XChaCha20Poly1305::new(&raw.into()),
            wrap: XChaCha20Poly1305::new(&blake3::derive_key(ACCOUNT_WRAP_CONTEXT, &raw).into()),
        })
    }
}

#[derive(Clone)]
enum Cached {
    Key(Arc<ScopeKey>),
    Destroyed,
}

/// Per-tenant keys wrapped by a local master key, and per-account keys wrapped under their
/// tenant's key.
pub struct LocalKeyring {
    master: XChaCha20Poly1305,
    control: Arc<dyn ControlStore>,
    cache: Mutex<HashMap<KeyScope, (Cached, Instant)>>,
    cache_ttl: Duration,
}

impl LocalKeyring {
    /// Reads the master key at `path`, creating a random one readable only by the owner when the
    /// file does not exist. Losing the file makes every sealed secret of every tenant unreadable.
    pub fn open_or_create(
        path: impl AsRef<Path>,
        control: Arc<dyn ControlStore>,
    ) -> Result<Self, KeyringError> {
        let path = path.as_ref();
        if !path.exists() {
            let key = Key::<XChaCha20Poly1305>::generate();
            write_private(path, key.as_slice()).map_err(KeyringError::backend)?;
        }
        let bytes = fs::read(path).map_err(KeyringError::backend)?;
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            KeyringError::backend(format!("{} is not a 32-byte key", path.display()))
        })?;
        Ok(Self::from_master(key, control))
    }

    /// A keyring with the given master key.
    pub fn from_master(master: [u8; 32], control: Arc<dyn ControlStore>) -> Self {
        Self {
            master: XChaCha20Poly1305::new(&master.into()),
            control,
            cache: Mutex::new(HashMap::new()),
            cache_ttl: Duration::from_secs(60),
        }
    }

    /// Keeps tenant and account keys in memory for `ttl` (one minute by default). A key destroyed
    /// on another node, directly or through its tenant, keeps working here for at most this long:
    /// an account key is never kept longer than the cached tenant key it was unwrapped with.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    fn aad(scope: &KeyScope, context: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64 + context.len());
        aad.extend_from_slice(scope.tenant().as_str().as_bytes());
        aad.push(0);
        if let Some(account) = scope.account() {
            aad.extend_from_slice(account.as_str().as_bytes());
            aad.push(0);
        }
        aad.extend_from_slice(context.as_bytes());
        aad
    }

    fn version(scope: &KeyScope) -> u8 {
        match scope {
            KeyScope::Tenant(_) => TENANT_VERSION,
            KeyScope::Account(..) => ACCOUNT_VERSION,
        }
    }

    fn wrap_aad(scope: &KeyScope) -> Vec<u8> {
        match scope {
            KeyScope::Tenant(_) => Self::aad(scope, "skein data key v1"),
            KeyScope::Account(..) => Self::aad(scope, "skein account key v1"),
        }
    }

    fn record(scope: &KeyScope) -> String {
        match scope {
            KeyScope::Tenant(_) => TENANT_RECORD.to_owned(),
            KeyScope::Account(_, a) => account_record(a),
        }
    }

    fn cached(&self, scope: &KeyScope) -> Option<(Cached, Instant)> {
        let cache = self.cache.lock().expect("lock");
        let (cached, at) = cache.get(scope)?;
        (at.elapsed() < self.cache_ttl).then(|| (cached.clone(), *at))
    }

    async fn key(&self, scope: &KeyScope) -> Result<Arc<ScopeKey>, KeyringError> {
        match self.entry(scope).await?.0 {
            Cached::Key(k) => Ok(k),
            Cached::Destroyed => Err(KeyringError::Destroyed),
        }
    }

    async fn entry(&self, scope: &KeyScope) -> Result<(Cached, Instant), KeyringError> {
        if let Some(hit) = self.cached(scope) {
            return Ok(hit);
        }
        let (loaded, at) = match scope {
            KeyScope::Tenant(_) => (
                self.load_or_create(scope, &self.master).await?,
                Instant::now(),
            ),
            KeyScope::Account(t, _) => {
                let (tenant, at) = Box::pin(self.entry(&KeyScope::tenant_of(t))).await?;
                let Cached::Key(tenant) = tenant else {
                    return Err(KeyringError::Destroyed);
                };
                (self.load_or_create(scope, &tenant.wrap).await?, at)
            }
        };
        self.cache
            .lock()
            .expect("lock")
            .insert(scope.clone(), (loaded.clone(), at));
        Ok((loaded, at))
    }

    async fn load_or_create(
        &self,
        scope: &KeyScope,
        wrapper: &XChaCha20Poly1305,
    ) -> Result<Cached, KeyringError> {
        let tenant = scope.tenant();
        let path = Self::record(scope);
        loop {
            if let Some((bytes, _)) = self.control.get(tenant, &path).await.map_err(backend)? {
                return Self::unwrap_record(scope, wrapper, &bytes);
            }
            let key = Key::<XChaCha20Poly1305>::generate();
            let nonce = XNonce::generate();
            let wrapped = wrapper
                .encrypt(
                    &nonce,
                    Payload {
                        msg: key.as_slice(),
                        aad: &Self::wrap_aad(scope),
                    },
                )
                .map_err(|_| KeyringError::Invalid)?;
            let mut blob = nonce.as_slice().to_vec();
            blob.extend_from_slice(&wrapped);
            let record = KeyRecord::Active {
                wrapped: STANDARD.encode(blob),
            };
            let bytes = Bytes::from(serde_json::to_vec(&record).expect("plain record"));
            match self.control.put(tenant, &path, bytes, Expect::Absent).await {
                Ok(_) => return Ok(Cached::Key(Arc::new(ScopeKey::new(key.as_slice())?))),
                Err(StorageError::Conflict) => continue,
                Err(e) => return Err(backend(e)),
            }
        }
    }

    fn unwrap_record(
        scope: &KeyScope,
        wrapper: &XChaCha20Poly1305,
        bytes: &[u8],
    ) -> Result<Cached, KeyringError> {
        let record: KeyRecord = serde_json::from_slice(bytes).map_err(|_| KeyringError::Invalid)?;
        match record {
            KeyRecord::Destroyed => Ok(Cached::Destroyed),
            KeyRecord::Active { wrapped } => {
                let blob = STANDARD
                    .decode(wrapped)
                    .map_err(|_| KeyringError::Invalid)?;
                if blob.len() < NONCE_LEN {
                    return Err(KeyringError::Invalid);
                }
                let (nonce, ct) = blob.split_at(NONCE_LEN);
                let nonce = XNonce::try_from(nonce).map_err(|_| KeyringError::Invalid)?;
                let key = wrapper
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: ct,
                            aad: &Self::wrap_aad(scope),
                        },
                    )
                    .map_err(|_| KeyringError::Invalid)?;
                Ok(Cached::Key(Arc::new(ScopeKey::new(&key)?)))
            }
        }
    }
}

fn backend(e: StorageError) -> KeyringError {
    KeyringError::backend(e)
}

#[async_trait]
impl Keyring for LocalKeyring {
    async fn seal(
        &self,
        scope: &KeyScope,
        context: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyringError> {
        let key = self.key(scope).await?;
        let nonce = XNonce::generate();
        let ct = key
            .data
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &Self::aad(scope, context),
                },
            )
            .map_err(|_| KeyringError::Invalid)?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(Self::version(scope));
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    async fn open(
        &self,
        scope: &KeyScope,
        context: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>, KeyringError> {
        let key = self.key(scope).await?;
        let Some((&version, rest)) = sealed.split_first() else {
            return Err(KeyringError::Invalid);
        };
        if version != Self::version(scope) || rest.len() < NONCE_LEN {
            return Err(KeyringError::Invalid);
        }
        let (nonce, ct) = rest.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).map_err(|_| KeyringError::Invalid)?;
        key.data
            .decrypt(
                &nonce,
                Payload {
                    msg: ct,
                    aad: &Self::aad(scope, context),
                },
            )
            .map_err(|_| KeyringError::Invalid)
    }

    async fn destroy(&self, scope: &KeyScope) -> Result<(), KeyringError> {
        let bytes = Bytes::from(serde_json::to_vec(&KeyRecord::Destroyed).expect("plain record"));
        self.control
            .put(scope.tenant(), &Self::record(scope), bytes, Expect::Any)
            .await
            .map_err(backend)?;
        let mut cache = self.cache.lock().expect("lock");
        if let KeyScope::Tenant(t) = scope {
            cache.retain(|s, _| s.tenant() != t);
        }
        cache.insert(scope.clone(), (Cached::Destroyed, Instant::now()));
        Ok(())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use skein_keyring::{Opened, open_account};
    use skein_storage::{ObjectControl, Objects};
    use skein_storage_memory::MemoryObjects;

    use skein_core::TenantId;

    use super::*;

    fn control() -> Arc<dyn ControlStore> {
        let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        Arc::new(ObjectControl::new(objects))
    }

    fn t(s: &str) -> TenantId {
        TenantId::new(s).unwrap()
    }

    fn a(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    #[tokio::test]
    async fn conformance() {
        let control = control();
        let master = [7u8; 32];
        let a = Arc::new(
            LocalKeyring::from_master(master, control.clone()).with_cache_ttl(Duration::ZERO),
        );
        let b = Arc::new(LocalKeyring::from_master(master, control).with_cache_ttl(Duration::ZERO));
        skein_keyring::testing::keyring(a, b).await;
    }

    #[tokio::test]
    async fn another_master_key_cannot_open() {
        let control = control();
        let scope = KeyScope::Tenant(t("t"));
        let x = LocalKeyring::from_master([1; 32], control.clone());
        let sealed = x.seal(&scope, "c", b"secret").await.unwrap();
        let account = KeyScope::account_of(&t("t"), &a("box"));
        let sealed_account = x.seal(&account, "c", b"secret").await.unwrap();
        let y = LocalKeyring::from_master([2; 32], control);
        assert!(matches!(
            y.open(&scope, "c", &sealed).await,
            Err(KeyringError::Invalid)
        ));
        assert!(matches!(
            y.open(&account, "c", &sealed_account).await,
            Err(KeyringError::Invalid)
        ));
    }

    #[tokio::test]
    async fn an_account_key_never_outlives_its_cached_tenant_key() {
        let control = control();
        let ttl = Duration::from_millis(400);
        let a_node = LocalKeyring::from_master([7; 32], control.clone()).with_cache_ttl(ttl);
        let b_node = LocalKeyring::from_master([7; 32], control).with_cache_ttl(ttl);
        let tenant = KeyScope::tenant_of(&t("t"));
        let account = KeyScope::account_of(&t("t"), &a("x"));
        a_node.seal(&account, "c", b"warm").await.unwrap();
        let started = Instant::now();
        b_node.seal(&tenant, "c", b"cached").await.unwrap();
        a_node.destroy(&tenant).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        b_node
            .seal(&account, "c", b"within the tenant's lifetime")
            .await
            .unwrap();
        tokio::time::sleep((started + ttl + Duration::from_millis(50)) - Instant::now()).await;
        assert!(matches!(
            b_node.seal(&account, "c", b"after").await,
            Err(KeyringError::Destroyed)
        ));
    }

    fn wrap(key: &XChaCha20Poly1305, nonce: [u8; 24], msg: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut out = nonce.to_vec();
        out.extend(
            key.encrypt(&XNonce::from(nonce), Payload { msg, aad })
                .unwrap(),
        );
        out
    }

    #[tokio::test]
    async fn data_sealed_before_account_scopes_still_opens() {
        let control = control();
        let master = XChaCha20Poly1305::new(&[7u8; 32].into());
        let data_key = [42u8; 32];
        let record = format!(
            r#"{{"state":"active","wrapped":"{}"}}"#,
            STANDARD.encode(wrap(
                &master,
                [1; 24],
                &data_key,
                b"acme\0skein data key v1"
            ))
        );
        control
            .put(&t("acme"), "keys/data", Bytes::from(record), Expect::Absent)
            .await
            .unwrap();
        let data = XChaCha20Poly1305::new(&data_key.into());
        let mut sealed = vec![1u8];
        sealed.extend(wrap(
            &data,
            [2; 24],
            b"hunter2",
            b"acme\0credentials/box/password",
        ));

        let ring = LocalKeyring::from_master([7; 32], control);
        assert_eq!(
            ring.open(
                &KeyScope::Tenant(t("acme")),
                "credentials/box/password",
                &sealed
            )
            .await
            .unwrap(),
            b"hunter2"
        );
        assert_eq!(
            open_account(
                &ring,
                &t("acme"),
                &a("box"),
                "credentials/box/password",
                &sealed
            )
            .await
            .unwrap(),
            Opened::Legacy(b"hunter2".to_vec())
        );
        let resealed = ring
            .seal(
                &KeyScope::account_of(&t("acme"), &a("box")),
                "credentials/box/password",
                b"hunter2",
            )
            .await
            .unwrap();
        assert_eq!(resealed[0], ACCOUNT_VERSION);
        assert!(matches!(
            ring.open(
                &KeyScope::Tenant(t("acme")),
                "credentials/box/password",
                &resealed
            )
            .await,
            Err(KeyringError::Invalid)
        ));
    }

    #[tokio::test]
    async fn account_keys_survive_a_restart() {
        let control = control();
        let scope = KeyScope::account_of(&t("t"), &a("box"));
        let sealed = LocalKeyring::from_master([3; 32], control.clone())
            .seal(&scope, "c", b"x")
            .await
            .unwrap();
        let again = LocalKeyring::from_master([3; 32], control.clone());
        assert_eq!(again.open(&scope, "c", &sealed).await.unwrap(), b"x");
        assert!(
            control
                .get(&t("t"), "keys/accounts/box")
                .await
                .unwrap()
                .is_some()
        );
    }

    async fn copy(control: &dyn ControlStore, from: (&str, &str), to: (&str, &str)) {
        let (bytes, _) = control.get(&t(from.0), from.1).await.unwrap().unwrap();
        control
            .put(&t(to.0), to.1, bytes, Expect::Any)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn swapped_key_records_are_refused() {
        let control = control();
        let ring =
            LocalKeyring::from_master([3; 32], control.clone()).with_cache_ttl(Duration::ZERO);
        for (tenant, account) in [("t", "a"), ("t", "b"), ("u", "a")] {
            ring.seal(&KeyScope::account_of(&t(tenant), &a(account)), "c", b"x")
                .await
                .unwrap();
        }
        copy(
            &*control,
            ("t", "keys/accounts/a"),
            ("t", "keys/accounts/b"),
        )
        .await;
        assert!(matches!(
            ring.seal(&KeyScope::account_of(&t("t"), &a("b")), "c", b"x")
                .await,
            Err(KeyringError::Invalid)
        ));
        copy(
            &*control,
            ("t", "keys/accounts/a"),
            ("u", "keys/accounts/a"),
        )
        .await;
        assert!(matches!(
            ring.seal(&KeyScope::account_of(&t("u"), &a("a")), "c", b"x")
                .await,
            Err(KeyringError::Invalid)
        ));
        copy(&*control, ("t", "keys/accounts/a"), ("t", "keys/data")).await;
        assert!(matches!(
            ring.seal(&KeyScope::Tenant(t("t")), "c", b"x").await,
            Err(KeyringError::Invalid)
        ));
        copy(&*control, ("u", "keys/data"), ("t", "keys/data")).await;
        assert!(
            matches!(
                ring.seal(&KeyScope::account_of(&t("t"), &a("a")), "c", b"x")
                    .await,
                Err(KeyringError::Invalid)
            ),
            "another tenant's key does not unwrap this tenant's account keys"
        );
    }

    #[tokio::test]
    async fn a_forged_account_record_is_refused() {
        let control = control();
        let ring = LocalKeyring::from_master([3; 32], control.clone());
        for forged in [
            &b"not json"[..],
            br#"{"state":"active","wrapped":"!!"}"#,
            br#"{"state":"active","wrapped":"AAAA"}"#,
            br#"{"state":"unknown"}"#,
        ] {
            control
                .put(
                    &t("t"),
                    "keys/accounts/f",
                    Bytes::copy_from_slice(forged),
                    Expect::Any,
                )
                .await
                .unwrap();
            assert!(matches!(
                ring.seal(&KeyScope::account_of(&t("t"), &a("f")), "c", b"x")
                    .await,
                Err(KeyringError::Invalid)
            ));
        }
    }

    #[tokio::test]
    async fn destroying_a_tenant_shreds_backed_up_account_records() {
        let control = control();
        let ring = LocalKeyring::from_master([3; 32], control.clone());
        let scope = KeyScope::account_of(&t("t"), &a("box"));
        let sealed = ring.seal(&scope, "c", b"x").await.unwrap();
        let (backup, _) = control
            .get(&t("t"), "keys/accounts/box")
            .await
            .unwrap()
            .unwrap();
        ring.destroy(&KeyScope::Tenant(t("t"))).await.unwrap();
        control
            .put(&t("t"), "keys/accounts/box", backup, Expect::Any)
            .await
            .unwrap();
        let fresh = LocalKeyring::from_master([3; 32], control);
        assert!(matches!(
            fresh.open(&scope, "c", &sealed).await,
            Err(KeyringError::Destroyed)
        ));
    }

    #[test]
    fn master_key_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        let control = control();
        LocalKeyring::open_or_create(&path, control.clone()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(fs::read(&path).unwrap().len(), 32);
        LocalKeyring::open_or_create(&path, control).unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_bytes_never_open(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let ring = LocalKeyring::from_master([5; 32], control());
                for scope in [
                    KeyScope::Tenant(t("t")),
                    KeyScope::account_of(&t("t"), &a("box")),
                ] {
                    assert!(matches!(
                        ring.open(&scope, "c", &bytes).await,
                        Err(KeyringError::Invalid)
                    ));
                }
            });
        }

        #[test]
        fn associated_data_is_unambiguous(
            account in "[a-z]{1,8}",
            context in "[a-z/\\x00]{0,16}",
        ) {
            let tenant_aad = LocalKeyring::aad(&KeyScope::Tenant(t("t")), &context);
            let account_aad =
                LocalKeyring::aad(&KeyScope::account_of(&t("t"), &a(&account)), &context);
            prop_assert_ne!(tenant_aad, account_aad.clone());
            let prefix = format!("t\0{account}\0");
            prop_assert!(account_aad.starts_with(prefix.as_bytes()));
        }
    }
}
