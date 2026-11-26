use std::time::Duration;

use skein_core::{AccountId, Seq, TenantId, Timestamp};
use skein_storage::{Snapshot, StorageError};
use tracing::info;

use crate::{Engine, EngineError};

/// When to snapshot and how long to keep events a snapshot already covers.
#[derive(Debug, Clone)]
pub struct Maintenance {
    /// Take a new snapshot once this many events were appended since the last one.
    pub snapshot_every: u64,
    /// Remove events covered by a snapshot once that snapshot is at least this old, so readers
    /// that fall behind by less than this never need the snapshot.
    pub retain: Duration,
}

impl Default for Maintenance {
    fn default() -> Self {
        Self {
            snapshot_every: 5_000,
            retain: Duration::from_secs(7 * 24 * 3600),
        }
    }
}

impl Engine {
    /// Folds the events since the latest snapshot into a new one, if at least `min_new` events
    /// were appended since. Returns the new snapshot's position. Any node may call it: a snapshot
    /// is derived from the committed log, so two nodes making the same one store it once.
    pub async fn snapshot_account(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        min_new: u64,
    ) -> Result<Option<Seq>, EngineError> {
        let log = &self.storage.log;
        let mut snapshot = log
            .latest_snapshot(tenant, account)
            .await?
            .unwrap_or_else(|| Snapshot::empty(account.clone()));
        let head = log.head(tenant, account).await?;
        if head.0.saturating_sub(snapshot.seq.0) < min_new.max(1) {
            return Ok(None);
        }
        while snapshot.seq < head {
            let page = log
                .read(tenant, account, snapshot.seq.next(), 5_000)
                .await?;
            if page.is_empty() {
                break;
            }
            for event in &page {
                snapshot.apply(event);
            }
        }
        snapshot.at = Timestamp::now();
        log.put_snapshot(tenant, account, &snapshot).await?;
        skein_metrics::global().snapshots.inc();
        info!(%account, seq = snapshot.seq.0, messages = snapshot.message_count(), "snapshot stored");
        Ok(Some(snapshot.seq))
    }

    /// Removes events covered by the latest snapshot once that snapshot is older than `retain`.
    /// Returns how many events were removed.
    pub async fn compact_account(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        retain: Duration,
    ) -> Result<u64, EngineError> {
        let Some(snapshot) = self.storage.log.latest_snapshot(tenant, account).await? else {
            return Ok(0);
        };
        let age = Timestamp::now().0 - snapshot.at.0;
        if age < retain.as_millis() as i64 {
            return Ok(0);
        }
        match self
            .storage
            .log
            .compact(tenant, account, snapshot.seq.next())
            .await
        {
            Ok(n) => {
                skein_metrics::global().events_compacted.add(n);
                if n > 0 {
                    info!(%account, removed = n, before = snapshot.seq.next().0, "log compacted");
                }
                Ok(n)
            }
            Err(StorageError::Conflict) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Snapshots and compacts the account as `policy` says.
    pub async fn maintain(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        policy: &Maintenance,
    ) -> Result<(), EngineError> {
        self.snapshot_account(tenant, account, policy.snapshot_every)
            .await?;
        self.compact_account(tenant, account, policy.retain).await?;
        Ok(())
    }
}
