//! [`MemoryState`]: a [`StateStore`] in memory, for tests and examples. Not durable: it breaks the
//! contract's durability guarantee on purpose and must never back a real node.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use baton_core::GroupId;
use baton_state::{
    Expect, MAX_SECRET, RecordName, SecretStore, StateError, StateStore, Version, check_value,
};
use bytes::Bytes;

#[derive(Default)]
struct Inner {
    records: BTreeMap<(GroupId, RecordName), (Bytes, u64)>,
    next: u64,
}

/// Records in a map behind a mutex; versions come from one counter, so they are never reused.
#[derive(Default)]
pub struct MemoryState {
    inner: Mutex<Inner>,
}

impl MemoryState {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overwrites a record without any check, as a hostile or broken backend might; for tests of
    /// what readers do with corrupted state.
    pub fn tamper(&self, group: &GroupId, name: &RecordName, value: Bytes) {
        let mut inner = self.inner.lock().expect("state lock");
        inner.next += 1;
        let v = inner.next;
        inner
            .records
            .insert((group.clone(), name.clone()), (value, v));
    }
}

fn holds(current: Option<&(Bytes, u64)>, expect: &Expect) -> bool {
    match (expect, current) {
        (Expect::Any, _) => true,
        (Expect::Absent, None) => true,
        (Expect::Absent, Some(_)) => false,
        (Expect::Version(v), Some((_, n))) => v.0 == n.to_string(),
        (Expect::Version(_), None) => false,
    }
}

#[async_trait]
impl StateStore for MemoryState {
    async fn get(
        &self,
        group: &GroupId,
        name: &RecordName,
    ) -> Result<Option<(Bytes, Version)>, StateError> {
        let inner = self.inner.lock().expect("state lock");
        Ok(inner
            .records
            .get(&(group.clone(), name.clone()))
            .map(|(b, n)| (b.clone(), Version(n.to_string()))))
    }

    async fn put(
        &self,
        group: &GroupId,
        name: &RecordName,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StateError> {
        check_value(&value)?;
        let mut inner = self.inner.lock().expect("state lock");
        let key = (group.clone(), name.clone());
        if !holds(inner.records.get(&key), &expect) {
            return Err(StateError::Conflict);
        }
        inner.next += 1;
        let n = inner.next;
        inner.records.insert(key, (value, n));
        Ok(Version(n.to_string()))
    }

    async fn delete(
        &self,
        group: &GroupId,
        name: &RecordName,
        expect: Expect,
    ) -> Result<(), StateError> {
        let mut inner = self.inner.lock().expect("state lock");
        let key = (group.clone(), name.clone());
        if !holds(inner.records.get(&key), &expect) {
            return Err(StateError::Conflict);
        }
        inner.records.remove(&key);
        Ok(())
    }

    async fn list(
        &self,
        group: &GroupId,
        prefix: &RecordName,
        after: Option<&RecordName>,
        limit: usize,
    ) -> Result<Vec<RecordName>, StateError> {
        let inner = self.inner.lock().expect("state lock");
        Ok(inner
            .records
            .keys()
            .filter(|(g, n)| g == group && n.is_under(prefix))
            .map(|(_, n)| n)
            .filter(|n| after.is_none_or(|a| n.as_str() > a.as_str()))
            .take(limit)
            .cloned()
            .collect())
    }
}

/// Secrets in a map behind a mutex, for tests. Not protected by any hardware or operating system
/// store, and not durable.
#[derive(Default)]
pub struct MemorySecrets {
    secrets: Mutex<BTreeMap<RecordName, zeroize::Zeroizing<Vec<u8>>>>,
}

impl MemorySecrets {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SecretStore for MemorySecrets {
    async fn put(
        &self,
        name: &RecordName,
        secret: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<(), StateError> {
        if secret.len() > MAX_SECRET {
            return Err(StateError::TooLarge);
        }
        self.secrets
            .lock()
            .expect("secrets lock")
            .insert(name.clone(), secret);
        Ok(())
    }

    async fn get(
        &self,
        name: &RecordName,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, StateError> {
        Ok(self
            .secrets
            .lock()
            .expect("secrets lock")
            .get(name)
            .cloned())
    }

    async fn delete(&self, name: &RecordName) -> Result<(), StateError> {
        self.secrets.lock().expect("secrets lock").remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn conformance() {
        baton_state::testing::state(Arc::new(MemoryState::new())).await;
        baton_state::testing::secrets(Arc::new(MemorySecrets::new())).await;
    }
}
