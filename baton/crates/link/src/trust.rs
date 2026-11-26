use std::collections::BTreeSet;
use std::sync::RwLock;

use baton_identity::{PublicKey, RosterHandle};

/// Decides which peers this node talks to.
///
/// Guarantees an implementation must keep: the answer reflects the trust state at the moment of
/// the call (no caching that delays a revocation), and the call is cheap and never blocks on I/O,
/// because links ask it on every new connection and stream.
pub trait Trust: Send + Sync {
    /// Whether `peer` is allowed to exchange streams with this node right now.
    fn allows(&self, peer: &PublicKey) -> bool;
}

/// A roster-backed trust: exactly the members of the roster the handle holds at the moment of the
/// call. A revocation applies as soon as the handle moves to the new roster.
impl Trust for RosterHandle {
    fn allows(&self, peer: &PublicKey) -> bool {
        self.current().is_member(peer)
    }
}

/// A set of pinned keys, such as the node key pinned in the app at pairing.
///
/// Guarantees: [`Trust::allows`] answers from the set as it is at that moment; inserts and
/// removals are visible to every holder immediately.
#[derive(Debug, Default)]
pub struct PinnedKeys(RwLock<BTreeSet<PublicKey>>);

impl PinnedKeys {
    /// A set holding `keys`.
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self(RwLock::new(keys.into_iter().collect()))
    }

    /// Pins `key`. Returns whether it was new.
    pub fn insert(&self, key: PublicKey) -> bool {
        self.0.write().expect("pinned keys lock").insert(key)
    }

    /// Unpins `key`. Returns whether it was pinned.
    pub fn remove(&self, key: &PublicKey) -> bool {
        self.0.write().expect("pinned keys lock").remove(key)
    }

    /// The pinned keys, sorted.
    pub fn keys(&self) -> Vec<PublicKey> {
        self.0
            .read()
            .expect("pinned keys lock")
            .iter()
            .copied()
            .collect()
    }
}

impl Trust for PinnedKeys {
    fn allows(&self, peer: &PublicKey) -> bool {
        self.0.read().expect("pinned keys lock").contains(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baton_identity::{Identity, Roster};

    #[test]
    fn pinned_and_roster_trust() {
        let a = Identity::generate();
        let b = Identity::generate();
        let pins = PinnedKeys::new([a.public()]);
        assert!(pins.allows(&a.public()));
        assert!(!pins.allows(&b.public()));
        assert!(pins.insert(b.public()));
        assert!(pins.allows(&b.public()));
        assert!(pins.remove(&a.public()));
        assert!(!pins.allows(&a.public()));

        let r1 = Roster::genesis(&a, baton_core::GroupId::new("group-a").unwrap());
        let r2 = r1.with_member(&a, b.public()).unwrap();
        let handle = RosterHandle::new(r2.clone()).unwrap();
        assert!(handle.allows(&b.public()));
        handle
            .update(r2.without_member(&a, &b.public()).unwrap())
            .unwrap();
        assert!(!handle.allows(&b.public()));
        assert!(handle.allows(&a.public()));
    }
}
