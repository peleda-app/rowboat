//! The device secret store the node keeps its identity and master key in.
//!
//! Deliberately small: names, two protection classes, get, put and delete. The app implements
//! it over its platform vault (Keychain, Secret Service, a passphrase file); tests use
//! `rowboat-keystore-memory`. Implementations run [`testing::keystore`].

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

#[cfg(feature = "testing")]
pub mod testing;

/// Most bytes in a [`Secret`] a keystore must accept.
pub const MAX_SECRET: usize = 16 * 1024;

/// The name of an item: 1 to 64 characters of `[a-z0-9.-]`, not starting with `.`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct KeyName(String);

impl KeyName {
    /// Checks and wraps `name`; [`KeystoreError::InvalidName`] when it breaks the rules.
    pub fn new(name: impl Into<String>) -> Result<Self, KeystoreError> {
        let name = name.into();
        let ok = !name.is_empty()
            && name.len() <= 64
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        if ok {
            Ok(Self(name))
        } else {
            Err(KeystoreError::InvalidName)
        }
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// When an item can be read. Never shared with app extensions, never synced or backed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyClass {
    /// Readable while the device is unlocked.
    Foreground,
    /// Readable from the first unlock after boot until shutdown, for background work.
    Background,
}

/// Secret bytes: zeroized on drop; `Debug` shows only the length; never `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Wraps `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A copy of `text`'s bytes.
    pub fn from_text(text: &str) -> Self {
        Self::new(text.as_bytes().to_vec())
    }

    /// The bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The bytes as text, when they are UTF-8.
    pub fn expose_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// The number of bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

/// Why a keystore call failed. Carries no secret, path, name or platform text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeystoreError {
    /// The name breaks [`KeyName`]'s rules.
    #[error("invalid key name")]
    InvalidName,
    /// The item exists but cannot be read now (device locked, keychain locked).
    #[error("the keystore is locked")]
    Locked,
    /// The platform refused access (the person declined, the app lacks an entitlement).
    #[error("access to the keystore was denied")]
    Denied,
    /// The class cannot be honoured, or the secret is larger than the store takes.
    #[error("not supported by this keystore")]
    Unsupported,
    /// The backend failed otherwise; the call may be retried.
    #[error("the keystore failed")]
    Backend,
}

/// The device secret store.
///
/// Guarantees every implementation keeps (checked by [`testing::keystore`]):
///
/// - `get` returns exactly the bytes of the last successful `put` under that name, `None` when
///   there is none, and never another item's bytes;
/// - `put` is atomic: after a failed `put` the previous item is still readable unchanged;
/// - `delete` returns whether an item was removed; deleting a missing item is `Ok(false)`;
/// - items persist across instances over the same backing store;
/// - secrets of up to [`MAX_SECRET`] bytes are accepted; larger ones may be `Unsupported`.
#[async_trait]
pub trait Keystore: Send + Sync {
    /// The item named `name`, `None` when it does not exist; [`KeystoreError::Locked`] when it
    /// exists but cannot be read now.
    async fn get(&self, name: &KeyName) -> Result<Option<Secret>, KeystoreError>;

    /// Creates or replaces the item named `name` with `secret`, readable as `class` allows.
    async fn put(
        &self,
        name: &KeyName,
        secret: &Secret,
        class: KeyClass,
    ) -> Result<(), KeystoreError>;

    /// Removes the item named `name`; `true` when one was removed.
    async fn delete(&self, name: &KeyName) -> Result<bool, KeystoreError>;
}

/// A shared keystore.
pub type SharedKeystore = Arc<dyn Keystore>;

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn names_follow_the_rules() {
        for good in ["rowboat.master", "rowboat.identity", "a", "a-b.c-9"] {
            assert!(KeyName::new(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            ".hidden",
            "Upper",
            "a/b",
            "a b",
            "ä",
            &"a".repeat(65),
            "a_b",
        ] {
            assert_eq!(KeyName::new(bad), Err(KeystoreError::InvalidName), "{bad}");
        }
    }

    #[test]
    fn secrets_never_show_their_bytes() {
        let s = Secret::from_text("canary-hunter2");
        assert_eq!(format!("{s:?}"), "Secret(14 bytes)");
        assert_eq!(s.expose_str(), Some("canary-hunter2"));
        assert_eq!(s.len(), 14);
        assert!(!Secret::new(vec![]).len().gt(&0));
    }

    proptest! {
        #[test]
        fn names_are_accepted_exactly_by_the_rule(s in "[a-z0-9._/ A-Z-]{0,70}") {
            let rule = !s.is_empty() && s.len() <= 64 && !s.starts_with('.')
                && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
            prop_assert_eq!(KeyName::new(s.clone()).is_ok(), rule);
        }
    }
}
