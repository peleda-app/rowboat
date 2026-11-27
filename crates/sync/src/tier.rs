use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;
use baton_core::ResourceId;
use baton_fetch::{ContentId, FetchError, Fetcher, LocalObjects};
use baton_group::Capability;
use baton_identity::PublicKey;
use bytes::Bytes;
use rowboat_group::{Membership, account_resource};
use skein_core::{AccountId, BlobHash, FencingToken, Seq, TenantId};
use skein_storage::{ReadTier, SegmentHash, SegmentRef, Storage, StorageError};

use crate::Host;

const MAX_OWNERS: usize = 4096;

/// Who to ask for an account's objects: its owner (the signer of the newest verified head)
/// first, then every other node that counts and may read it, in key order. Also holds the fetcher
/// once the node's link is up.
pub struct Peers {
    membership: Arc<Membership>,
    owners: Mutex<BTreeMap<AccountId, PublicKey>>,
    fetcher: RwLock<Option<Arc<Fetcher>>>,
}

impl Peers {
    /// No owner known yet, no fetcher.
    pub fn new(membership: Arc<Membership>) -> Self {
        Self {
            membership,
            owners: Mutex::new(BTreeMap::new()),
            fetcher: RwLock::new(None),
        }
    }

    /// The group view.
    pub fn membership(&self) -> &Arc<Membership> {
        &self.membership
    }

    /// The owner of `account` as far as this node knows: the signer of the newest head it
    /// verified, while that node still counts.
    pub fn owner(&self, account: &AccountId) -> Option<PublicKey> {
        let owner = *self.owners.lock().expect("owners lock").get(account)?;
        self.membership.counts(&owner).then_some(owner)
    }

    /// Records `node` as the owner of `account`. At most 4,096 accounts are remembered.
    pub fn set_owner(&self, account: &AccountId, node: PublicKey) {
        let mut owners = self.owners.lock().expect("owners lock");
        if owners.len() < MAX_OWNERS || owners.contains_key(account) {
            owners.insert(account.clone(), node);
        }
    }

    /// The nodes to ask for `account`'s objects, owner first.
    pub fn readers(&self, account: &AccountId) -> Vec<PublicKey> {
        let Some(resource) = account_resource(account.as_str()) else {
            return Vec::new();
        };
        let mut out: Vec<PublicKey> = self.owner(account).into_iter().collect();
        for peer in self.membership.counting_peers() {
            if !out.contains(&peer)
                && self
                    .membership
                    .node_may(&peer, &resource, &Capability::Read)
            {
                out.push(peer);
            }
        }
        out
    }

    /// The accounts this node may read, from the account resources of the group log.
    pub fn readable(&self) -> Vec<AccountId> {
        self.membership
            .resources()
            .into_iter()
            .filter(|r| self.membership.may(r, &Capability::Read))
            .filter_map(|r| {
                r.as_str()
                    .strip_prefix("acct-")
                    .and_then(|a| AccountId::new(a).ok())
            })
            .collect()
    }

    /// Sets the fetcher, once the link is up.
    pub fn set_fetcher(&self, fetcher: Option<Arc<Fetcher>>) {
        *self.fetcher.write().expect("fetcher lock") = fetcher;
    }

    /// The fetcher, when the link is up.
    pub fn fetcher(&self) -> Option<Arc<Fetcher>> {
        self.fetcher.read().expect("fetcher lock").clone()
    }
}

fn found(
    got: Result<(Bytes, baton_fetch::Origin), FetchError>,
    max: usize,
) -> Result<Option<Bytes>, StorageError> {
    match got {
        Ok((bytes, _)) if bytes.len() <= max => Ok(Some(bytes)),
        Ok(_) | Err(FetchError::NotFound) => Ok(None),
        Err(e) => Err(StorageError::backend(e.to_string())),
    }
}

/// A Skein [`ReadTier`] over the node's peers (`baton-fetch`): a segment is asked for under its
/// account's resource by its hash, with its name as the locator; a blob under each account
/// resource this node reads until one peer has it. Peers are asked owner first. Without a link it
/// has nothing. Every answer is checked by hash in `baton-fetch` and again by the caller.
pub struct PeerTier {
    peers: Arc<Peers>,
}

impl PeerTier {
    /// A tier over `peers`.
    pub fn new(peers: Arc<Peers>) -> Self {
        Self { peers }
    }
}

#[async_trait]
impl ReadTier for PeerTier {
    async fn segment(
        &self,
        _: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
        max_len: usize,
    ) -> Result<Option<Bytes>, StorageError> {
        let (Some(fetcher), Some(resource)) =
            (self.peers.fetcher(), account_resource(account.as_str()))
        else {
            return Ok(None);
        };
        let readers = self.peers.readers(account);
        let got = fetcher
            .fetch_located(
                &resource,
                &ContentId(segment.hash.0),
                segment.name().as_bytes(),
                &readers,
            )
            .await;
        found(got, max_len)
    }

    async fn blob(
        &self,
        _: &TenantId,
        hash: &BlobHash,
        max_len: usize,
    ) -> Result<Option<Bytes>, StorageError> {
        let Some(fetcher) = self.peers.fetcher() else {
            return Ok(None);
        };
        for account in self.peers.readable() {
            let Some(resource) = account_resource(account.as_str()) else {
                continue;
            };
            let readers = self.peers.readers(&account);
            if readers.is_empty() {
                continue;
            }
            let got = fetcher
                .fetch(&resource, &ContentId(*hash.as_bytes()), &readers)
                .await;
            if let Some(bytes) = found(got, max_len)? {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }
}

/// Runs the segment locator parser over `bytes`, for the fuzz target. Never panics; whatever it
/// accepts names a non-empty range.
pub fn fuzz_locator(bytes: &[u8]) {
    if let Some((s, e, _)) = parse_name(bytes) {
        assert!(s >= 1 && s <= e);
    }
}

fn parse_name(name: &[u8]) -> Option<(u64, u64, u64)> {
    let text = std::str::from_utf8(name).ok()?;
    let mut parts = text.split('-');
    let mut next = || -> Option<u64> {
        let p = parts.next()?;
        (p.len() == 20 && p.bytes().all(|b| b.is_ascii_digit()))
            .then(|| p.parse().ok())
            .flatten()
    };
    let (s, e, f) = (next()?, next()?, next()?);
    (parts.next().is_none() && s >= 1 && s <= e).then_some((s, e, f))
}

/// What this node serves to peers over `baton-fetch`, from its own local storage (never through
/// its tiers): a segment of an account, found by the name in the locator and served only when its
/// bytes hash to the requested id; a blob only when the [`Host`] says it belongs to the account
/// whose resource it was asked under. Who may ask for a resource is the fetch server's
/// `authorize` (read in the group log); for anything else the answer is "not here".
pub struct Served {
    tenant: TenantId,
    local: std::sync::Weak<Storage>,
    host: Arc<dyn Host>,
}

impl Served {
    /// Serves `tenant`'s objects from `local` while its owner keeps it; once the owner dropped it
    /// (the node shut down), nothing is served and nothing keeps the storage open.
    pub fn new(tenant: TenantId, local: &Arc<Storage>, host: Arc<dyn Host>) -> Self {
        Self {
            tenant,
            local: Arc::downgrade(local),
            host,
        }
    }
}

fn account_of(resource: &ResourceId) -> Option<AccountId> {
    resource
        .as_str()
        .strip_prefix("acct-")
        .and_then(|a| AccountId::new(a).ok())
}

#[async_trait]
impl LocalObjects for Served {
    async fn get(&self, resource: &ResourceId, id: &ContentId, locator: &[u8]) -> Option<Bytes> {
        let account = account_of(resource)?;
        let local = self.local.upgrade()?;
        if !locator.is_empty() {
            let (start, end, fence) = parse_name(locator)?;
            let segment = SegmentRef {
                start: Seq(start),
                end: Seq(end),
                fence: FencingToken(fence),
                hash: SegmentHash(id.0),
            };
            let bytes = local
                .log
                .segment(&self.tenant, &account, &segment)
                .await
                .ok()??;
            return (SegmentHash::of(&bytes) == segment.hash).then_some(bytes);
        }
        let blob = BlobHash::from_bytes(id.0);
        if !self.host.holds_blob(&account, &blob).await {
            return None;
        }
        let bytes = local.blobs.get(&self.tenant, &blob).await.ok()??;
        blob.matches(&bytes).then_some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_names_parse_strictly() {
        let r = SegmentRef {
            start: Seq(3),
            end: Seq(9),
            fence: FencingToken(2),
            hash: SegmentHash([0; 32]),
        };
        assert_eq!(parse_name(r.name().as_bytes()), Some((3, 9, 2)));
        for bad in [
            "",
            "3-9-2",
            "00000000000000000009-00000000000000000003-00000000000000000002",
            "00000000000000000000-00000000000000000003-00000000000000000002",
            "00000000000000000003-00000000000000000009-0000000000000000000x",
            "00000000000000000003-00000000000000000009-00000000000000000002-1",
        ] {
            assert_eq!(parse_name(bad.as_bytes()), None, "{bad}");
        }
        assert_eq!(parse_name(&[0xff, 0xfe]), None);
    }

    proptest::proptest! {
        #[test]
        fn any_locator_parses_without_panicking(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..80)) {
            fuzz_locator(&bytes);
        }
    }
}
