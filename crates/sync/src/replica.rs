use std::collections::BTreeSet;

use baton_signal::Signal;
use bytes::Bytes;
use futures::StreamExt;
use serde::Serialize;
use skein_core::{AccountId, BlobHash, EventBody, TenantId};
use skein_storage::{
    Expect, IntegrityError, JournalHead, SignedHead, Storage, StorageError, verify_segment,
};
use tracing::{info, warn};

use crate::{Host, SyncError};

/// Most blobs one catch-up fetches before it installs.
pub(crate) const MAX_PREFETCH: usize = 4096;
/// Blobs fetched at once during a catch-up: no more than a serving peer takes from one node
/// (`FetchConfig::max_per_peer`).
pub(crate) const PREFETCH_PARALLEL: usize = 4;
/// Catch-ups that may end with blobs missing before the head is installed anyway.
pub(crate) const MAX_ATTEMPTS: u32 = 3;

/// What one catch-up did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caught {
    /// The replica already holds this head.
    Current,
    /// The head is behind or below what the replica holds (an old announcement, a replay, a
    /// peer withholding newer events): nothing changed.
    Stale,
    /// The replica moved to this `seq`.
    Installed {
        /// The new head's `seq`.
        seq: u64,
    },
    /// Segments are staged but some blobs could not be fetched yet; try again later.
    Retry,
    /// The head and the replica disagree: the journal forked; nothing was installed.
    Forked,
    /// The head is under a higher fence and does not continue the replica: this node wrote
    /// past what the next holder continued from (it was deposed while it still wrote). Its
    /// replica of the account is to be dropped and followed again from the start.
    Deposed,
}

pub(crate) struct Replica<'a> {
    pub tenant: &'a TenantId,
    pub local: &'a Storage,
    pub through: &'a Storage,
    pub host: &'a dyn Host,
    pub signal: &'a dyn Signal,
}

fn storage(e: StorageError) -> SyncError {
    match e {
        StorageError::Integrity(IntegrityError::Fork { .. }) => SyncError::Fork,
        StorageError::Integrity(IntegrityError::Missing { .. })
        | StorageError::Integrity(IntegrityError::HashMismatch { .. }) => SyncError::Unreachable,
        StorageError::Integrity(_) | StorageError::Corrupt(_) => SyncError::Unverified,
        StorageError::Fenced | StorageError::Conflict => SyncError::Unverified,
        _ => SyncError::Storage,
    }
}

#[derive(Serialize)]
struct ForkRecord {
    local_seq: u64,
    local_digest: String,
    remote_seq: u64,
    remote_fence: u64,
    remote_digest: String,
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn blobs_of(body: &EventBody, into: &mut BTreeSet<BlobHash>) {
    match body {
        EventBody::MessageAdded { blob, .. }
        | EventBody::ObjectUpserted { blob, .. }
        | EventBody::ItipReceived { blob, .. }
            if into.len() < MAX_PREFETCH =>
        {
            into.insert(*blob);
        }
        _ => {}
    }
}

impl Replica<'_> {
    /// Brings the local replica of the account up to `remote`, a head already checked with
    /// [`crate::verify_remote`]. `attempts` counts the earlier catch-ups to this head that ended
    /// in [`Caught::Retry`].
    pub(crate) async fn catch_up(
        &self,
        remote: &SignedHead,
        attempts: u32,
    ) -> Result<Caught, SyncError> {
        let account = &remote.head.account;
        if &remote.head.tenant != self.tenant {
            return Err(SyncError::Malformed);
        }
        if self.host.leads(account) {
            return Err(SyncError::NotHere);
        }
        let local = self
            .local
            .log
            .signed_head(self.tenant, account)
            .await
            .map_err(storage)?;
        let (l, r) = (&local.head, &remote.head);
        if r.fence < l.fence {
            return Ok(Caught::Stale);
        }
        match l.check_successor(r) {
            Ok(()) => {}
            Err(IntegrityError::Rollback { .. } | IntegrityError::Fork { .. })
                if r.fence > l.fence =>
            {
                return Ok(self.deposed(l, r));
            }
            Err(IntegrityError::Rollback { .. }) => return Ok(Caught::Stale),
            Err(IntegrityError::Fork { .. }) => return self.forked(&local, remote).await,
            Err(_) => return Err(SyncError::Malformed),
        }
        if r.seq == l.seq && r.fence == l.fence {
            return Ok(Caught::Current);
        }
        let mut blobs = BTreeSet::new();
        if r.seq > l.seq {
            match self.stage(l, r, &mut blobs).await {
                Ok(()) => {}
                Err(SyncError::Fork) if r.fence > l.fence => return Ok(self.deposed(l, r)),
                Err(SyncError::Fork) => return self.forked(&local, remote).await,
                Err(e) => return Err(e),
            }
        }
        let missing = futures::stream::iter(blobs.into_iter().collect::<Vec<_>>())
            .map(|blob| async move {
                if self
                    .local
                    .blobs
                    .contains(self.tenant, &blob)
                    .await
                    .unwrap_or(false)
                {
                    return 0usize;
                }
                match self.through.blobs.get(self.tenant, &blob).await {
                    Ok(Some(bytes)) if blob.matches(&bytes) => 0,
                    _ => 1,
                }
            })
            .buffer_unordered(PREFETCH_PARALLEL)
            .fold(0usize, |n, m| async move { n + m })
            .await;
        if missing > 0 && attempts + 1 < MAX_ATTEMPTS {
            info!(account = %account, missing, "blobs missing; the head waits");
            return Ok(Caught::Retry);
        }
        match self.local.log.install(self.tenant, account, remote).await {
            Ok(()) => {}
            Err(StorageError::Integrity(IntegrityError::Fork { .. })) if r.fence > l.fence => {
                return Ok(self.deposed(l, r));
            }
            Err(StorageError::Integrity(IntegrityError::Fork { .. })) => {
                return self.forked(&local, remote).await;
            }
            Err(e) => return Err(storage(e)),
        }
        if missing > 0 {
            warn!(account = %account, missing, "head installed with blobs missing");
        }
        let _ = self
            .signal
            .publish(
                &skein_core::coordination::group(self.tenant),
                &format!("heads/{account}"),
                Bytes::from(r.seq.0.to_string()),
            )
            .await;
        self.host.installed(account, r.seq.0);
        Ok(Caught::Installed { seq: r.seq.0 })
    }

    async fn stage(
        &self,
        local: &JournalHead,
        remote: &JournalHead,
        blobs: &mut BTreeSet<BlobHash>,
    ) -> Result<(), SyncError> {
        if local.seq.0 > 0 && local.tip.is_none() {
            return Err(SyncError::Fork);
        }
        let account = &remote.account;
        let mut want = remote.tip.clone().ok_or(SyncError::Malformed)?;
        loop {
            let bytes = self
                .through
                .log
                .segment(self.tenant, account, &want)
                .await
                .map_err(storage)?
                .ok_or(SyncError::Unreachable)?;
            let segment = verify_segment(self.tenant, account, &want, &bytes)
                .map_err(|_| SyncError::Unreachable)?;
            if segment.segment.start <= local.seq {
                return Err(SyncError::Fork);
            }
            self.local
                .log
                .stage(self.tenant, account, &want, bytes)
                .await
                .map_err(storage)?;
            for e in &segment.events {
                blobs_of(&e.body, blobs);
            }
            if segment.prev == local.tip {
                if local.tip.is_none() && segment.segment.start.0 != 1 {
                    return Err(SyncError::Unreachable);
                }
                return Ok(());
            }
            if segment.segment.start.0 <= local.seq.0 + 1 {
                return Err(SyncError::Fork);
            }
            want = segment.prev.ok_or(SyncError::Unreachable)?;
        }
    }

    fn deposed(&self, local: &JournalHead, remote: &JournalHead) -> Caught {
        warn!(
            account = %remote.account,
            local_seq = local.seq.0,
            remote_seq = remote.seq.0,
            "a newer holder continued from an earlier head; this replica is dropped"
        );
        Caught::Deposed
    }

    async fn forked(&self, local: &SignedHead, remote: &SignedHead) -> Result<Caught, SyncError> {
        let account = &remote.head.account;
        let record = ForkRecord {
            local_seq: local.head.seq.0,
            local_digest: hex(&local.head.digest()),
            remote_seq: remote.head.seq.0,
            remote_fence: remote.head.fence.0,
            remote_digest: hex(&remote.head.digest()),
        };
        let path = fork_path(account);
        let _ = self
            .local
            .control
            .put(
                self.tenant,
                &path,
                Bytes::from(serde_json::to_vec(&record).expect("plain struct")),
                Expect::Any,
            )
            .await;
        warn!(account = %account, "the journal forked; following stopped");
        self.host.forked(account);
        Ok(Caught::Forked)
    }
}

/// Where the evidence of a fork of `account` is kept in the control store.
pub(crate) fn fork_path(account: &AccountId) -> String {
    format!("rowboat/forks/{account}")
}
