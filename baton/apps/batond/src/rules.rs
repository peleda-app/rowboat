//! Who may talk to batond and what they may ask, decided from the group logs it holds.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use baton_core::{GroupId, LeaseKey, NodeId, ResourceId};
use baton_group::Capability;
use baton_group_server::{Admit, Clock, GroupLogs};
use baton_lease::{NodeClass, NodeProfile};
use baton_lease_server::Authorize;
use baton_link::{PublicKey, Trust};

/// The separator between a resource id and a job suffix in a lease key.
pub const KEY_SEPARATOR: &str = "--";

/// The resource a lease key is held on: the key itself, or the part before the first
/// [`KEY_SEPARATOR`] when the key has one followed by a non-empty suffix
/// (`mailbox-1--sync` is held on resource `mailbox-1`). Every key maps to at most one resource,
/// and only when the reading is unambiguous: a key whose resource part ends with `-` or whose
/// suffix starts with `-` (`vault---sync`, which could be `vault-` and `sync`) maps to none. So a
/// resource id that contains `--` cannot be leased through batond, and one that ends with `-` can
/// be leased only whole.
pub fn resource_of(key: &LeaseKey) -> Option<ResourceId> {
    match key.as_str().split_once(KEY_SEPARATOR) {
        None => ResourceId::new(key.as_str()).ok(),
        Some((_, "")) => None,
        Some((resource, suffix)) if resource.ends_with('-') || suffix.starts_with('-') => None,
        Some((resource, _)) => ResourceId::new(resource).ok(),
    }
}

/// batond's rules over its group logs, on its own wall clock:
///
/// - **Link trust** ([`Trust`]): a peer that is a counting node (certified, not revoked, member
///   in the group, not expired) of a held group, or a bootstrap peer of a held group that the
///   group's log has never certified.
/// - **Group log access** ([`Admit`]): bootstrap peers of that group while its log has no
///   genesis or has never certified their key, on top of its counting nodes. Once the log
///   certified a bootstrap key, only the log decides, so a revoked, removed or rekeyed founder is
///   refused like any other node.
/// - **Leases** ([`Authorize`]): a peer speaks only as its own node and only while it counts;
///   it reads liveness and holders of groups it counts in; it announces only a profile no
///   stronger than its certificate's class and never as a blind node; it acquires or takes over
///   a key only if it is not blind and has `Lead` on the key's resource ([`resource_of`]); it
///   releases its own leases whatever its rights are now.
///
/// Every answer is computed from the logs at the moment of the call, so an accepted revocation
/// applies to the next request.
pub struct Rules {
    logs: Arc<GroupLogs>,
    bootstrap: BTreeMap<GroupId, BTreeSet<PublicKey>>,
    clock: Clock,
}

impl Rules {
    /// Rules over `logs`, with per-group bootstrap peers, on `clock`.
    pub fn new(
        logs: Arc<GroupLogs>,
        bootstrap: BTreeMap<GroupId, BTreeSet<PublicKey>>,
        clock: Clock,
    ) -> Self {
        Self {
            logs,
            bootstrap,
            clock,
        }
    }

    fn counts(&self, peer: &PublicKey, group: &GroupId) -> bool {
        self.logs.counts(group, peer, (self.clock)())
    }

    fn bootstrap_admits(&self, peer: &PublicKey, group: &GroupId) -> bool {
        self.bootstrap.get(group).is_some_and(|k| k.contains(peer))
            && self.logs.holds(group)
            && self
                .logs
                .with(group, |l| !l.state().was_certified(peer))
                .unwrap_or(true)
    }

    fn class(&self, peer: &PublicKey, group: &GroupId) -> Option<NodeClass> {
        let now = (self.clock)();
        self.logs
            .with(group, |l| l.state().node(peer, now).map(|c| c.class))
            .flatten()
    }
}

impl Trust for Rules {
    fn allows(&self, peer: &PublicKey) -> bool {
        self.bootstrap
            .keys()
            .any(|g| self.bootstrap_admits(peer, g))
            || self.logs.counts_anywhere(peer, (self.clock)())
    }
}

impl Admit for Rules {
    fn admits(&self, peer: &PublicKey, group: &GroupId) -> bool {
        self.bootstrap_admits(peer, group)
    }
}

impl Authorize for Rules {
    fn node(&self, peer: &PublicKey) -> Option<NodeId> {
        self.logs
            .counts_anywhere(peer, (self.clock)())
            .then(|| peer.node_id())
    }

    fn member(&self, peer: &PublicKey, group: &GroupId) -> bool {
        self.counts(peer, group)
    }

    fn profile(&self, peer: &PublicKey, group: &GroupId, profile: &NodeProfile) -> bool {
        self.class(peer, group)
            .is_some_and(|c| c.may_lead() && profile.class >= c)
    }

    fn lease(&self, peer: &PublicKey, group: &GroupId, key: &LeaseKey) -> bool {
        let Some(resource) = resource_of(key) else {
            return false;
        };
        let now = (self.clock)();
        self.logs
            .with(group, |l| {
                let s = l.state();
                s.node(peer, now).is_some_and(|c| c.class.may_lead())
                    && s.may(peer, &resource, &Capability::Lead, now)
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> LeaseKey {
        LeaseKey::new(s).unwrap()
    }

    #[test]
    fn keys_map_to_one_resource() {
        let r = |s: &str| resource_of(&key(s)).map(|r| r.as_str().to_owned());
        assert_eq!(r("mailbox-1").as_deref(), Some("mailbox-1"));
        assert_eq!(r("mailbox-1--sync").as_deref(), Some("mailbox-1"));
        assert_eq!(r("a--b--c").as_deref(), Some("a"));
        assert_eq!(r("a-b_c").as_deref(), Some("a-b_c"));
        assert_eq!(r("a--"), None, "an empty suffix");
        assert_eq!(
            r("a---b"),
            None,
            "a resource part ending in '-' or a suffix starting with it"
        );
    }

    #[test]
    fn a_resource_ending_in_a_dash_never_lends_its_jobs_to_another() {
        let r = |s: &str| resource_of(&key(s)).map(|r| r.as_str().to_owned());
        assert_eq!(
            r("vault---sync"),
            None,
            "\"vault-\" + \"--\" + \"sync\" is not vault's"
        );
        assert_eq!(r("vault----sync"), None);
        assert_eq!(
            r("vault-").as_deref(),
            Some("vault-"),
            "the whole key is still its own"
        );
        assert_eq!(r("vault--sync-").as_deref(), Some("vault"));
    }

    proptest::proptest! {
        #[test]
        fn a_key_never_maps_to_a_resource_it_does_not_start_with(s in "[a-z0-9_][a-z0-9_-]{0,63}") {
            if let Ok(k) = LeaseKey::new(s)
                && let Some(r) = resource_of(&k)
            {
                proptest::prop_assert!(k.as_str().starts_with(r.as_str()));
                proptest::prop_assert!(!r.as_str().contains(KEY_SEPARATOR));
                let rest = &k.as_str()[r.as_str().len()..];
                proptest::prop_assert!(rest.is_empty() || rest.len() > KEY_SEPARATOR.len());
                if !rest.is_empty() {
                    proptest::prop_assert!(!r.as_str().ends_with('-'));
                    proptest::prop_assert!(rest.starts_with(KEY_SEPARATOR));
                    proptest::prop_assert!(!rest[KEY_SEPARATOR.len()..].starts_with('-'));
                }
            }
        }
    }
}
