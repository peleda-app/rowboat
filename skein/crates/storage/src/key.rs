use std::fmt;

use skein_core::{AccountId, TenantId};

/// A key segment that is empty, too long, `.`/`..`, starts with `.` or holds characters outside
/// `[a-zA-Z0-9_.-]`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid storage key segment")]
pub struct InvalidKey;

/// A storage key: segments joined by `/`.
///
/// Every segment is checked when it is added, so a key can never climb out of its prefix on a
/// file system or address another tenant's objects: no empty segments, no `.` or `..`, no leading
/// dot, no separators inside a segment.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectKey(String);

const MAX_SEGMENT: usize = 128;

fn check(segment: &str) -> Result<(), InvalidKey> {
    let ok = !segment.is_empty()
        && segment.len() <= MAX_SEGMENT
        && !segment.starts_with('.')
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if ok { Ok(()) } else { Err(InvalidKey) }
}

impl ObjectKey {
    /// A key of one segment.
    pub fn root(segment: &str) -> Result<Self, InvalidKey> {
        check(segment)?;
        Ok(Self(segment.to_owned()))
    }

    /// `tenants/{tenant}`, the root of everything a tenant owns.
    pub fn tenant(tenant: &TenantId) -> Self {
        Self(format!("tenants/{tenant}"))
    }

    /// `tenants/{tenant}/{area}/{account}`.
    pub fn account(tenant: &TenantId, area: &str, account: &AccountId) -> Result<Self, InvalidKey> {
        Self::tenant(tenant).join(area)?.join(account.as_str())
    }

    /// This key with one more segment.
    pub fn join(&self, segment: &str) -> Result<Self, InvalidKey> {
        check(segment)?;
        Ok(Self(format!("{}/{segment}", self.0)))
    }

    /// This key with more segments given as `a/b/c`, each checked.
    pub fn join_path(&self, path: &str) -> Result<Self, InvalidKey> {
        let mut key = self.clone();
        for segment in path.split('/') {
            key = key.join(segment)?;
        }
        Ok(key)
    }

    /// Parses a full key, checking every segment.
    pub fn parse(text: &str) -> Result<Self, InvalidKey> {
        let mut parts = text.split('/');
        let mut key = Self::root(parts.next().ok_or(InvalidKey)?)?;
        for part in parts {
            key = key.join(part)?;
        }
        Ok(key)
    }

    /// The key as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The last segment.
    pub fn last(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    /// The segments.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// Whether this key is `prefix` itself or lies under it.
    pub fn starts_with(&self, prefix: &ObjectKey) -> bool {
        self.0 == prefix.0
            || (self.0.starts_with(&prefix.0)
                && self.0.as_bytes().get(prefix.0.len()) == Some(&b'/'))
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectKey({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_segments_that_escape() {
        let root = ObjectKey::root("tenants").unwrap();
        for bad in ["", ".", "..", ".hidden", "a/b", "a\\b", "a b", "ä"] {
            assert!(root.join(bad).is_err(), "{bad:?}");
        }
        assert!(ObjectKey::parse("a//b").is_err());
        assert!(ObjectKey::parse("a/../b").is_err());
        assert!(root.join_path("x/../y").is_err());
    }

    #[test]
    fn prefixes_respect_segment_boundaries() {
        let a = ObjectKey::parse("t/a").unwrap();
        assert!(ObjectKey::parse("t/a/b").unwrap().starts_with(&a));
        assert!(ObjectKey::parse("t/a").unwrap().starts_with(&a));
        assert!(!ObjectKey::parse("t/ab").unwrap().starts_with(&a));
    }
}
