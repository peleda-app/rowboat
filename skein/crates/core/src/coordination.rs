//! The one mapping between Skein's ids and the ids of Baton, the coordination library Skein uses
//! for leases, liveness and signals.
//!
//! - A tenant is the group of the same id: leases, heartbeats and signals of different tenants
//!   never mix, and Baton's records for a tenant live with that tenant's control records.
//! - An account is the lease key of the same id within its tenant's group: the node holding the
//!   lease on `(group(tenant), lease_key(account))` is the account's owner, and the lease's fencing
//!   token is what storage checks.
//!
//! [`TenantId`] and [`AccountId`] follow the same rules as Baton's ids, except that a tenant id
//! never starts with `_`. The mapping is one to one in both directions: every group maps to a
//! tenant, and a group starting with `_` (Skein's own, such as the group nodes heartbeat in) maps
//! to a reserved tenant that [`TenantId::new`] and deserializing refuse, so no API can register,
//! purge, export or read it.

use baton_core::{GroupId, LeaseKey};

use crate::{AccountId, TenantId};

/// The group of `tenant`: the same id.
pub fn group(tenant: &TenantId) -> GroupId {
    GroupId::new(tenant.as_str()).expect("tenant ids follow the rules of group ids")
}

/// The tenant of `group`: the same id. For a group starting with `_` it is a reserved tenant
/// ([`TenantId::is_reserved`]) that cannot be built any other way.
pub fn tenant(group: &GroupId) -> TenantId {
    TenantId::of_group(group.as_str())
}

/// The lease key of `account` within its tenant's group: the same id.
pub fn lease_key(account: &AccountId) -> LeaseKey {
    LeaseKey::new(account.as_str()).expect("account ids follow the rules of lease keys")
}

/// The account of a lease key: the same id.
pub fn account(key: &LeaseKey) -> AccountId {
    AccountId::new(key.as_str()).expect("lease keys follow the rules of account ids")
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn round_trips_and_keeps_the_id(s in "[a-z0-9_][a-z0-9_-]{0,63}") {
            if let Ok(t) = TenantId::new(s.clone()) {
                let g = group(&t);
                prop_assert_eq!(g.as_str(), t.as_str());
                prop_assert_eq!(tenant(&g), t);
            }
            if let Ok(a) = AccountId::new(s) {
                let k = lease_key(&a);
                prop_assert_eq!(k.as_str(), a.as_str());
                prop_assert_eq!(account(&k), a);
            }
        }
    }

    #[test]
    fn every_group_is_a_tenant() {
        for s in ["a", "acme", "_x", "x-y", &"z".repeat(64)] {
            let g = GroupId::new(s).unwrap();
            assert_eq!(tenant(&g).as_str(), s);
            assert_eq!(tenant(&g).is_reserved(), s.starts_with('_'));
            assert_eq!(group(&tenant(&g)), g);
            let k = LeaseKey::new(s).unwrap();
            assert_eq!(account(&k).as_str(), s);
        }
    }
}
