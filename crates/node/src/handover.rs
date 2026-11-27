//! What the node does when an account's lease changes hands (GROUP.md, "Leases, handover and
//! credentials"), once leases are shared across nodes:
//!
//! - **Taking a lease.** Before the engine claims the log with the new token, the node asks its
//!   peers for newer heads, then opens the newest offer it holds for the account (the previous
//!   holder's record, credentials, cursors and queue) when it is newer than its own state of the
//!   account, and imports it. Without an offer and without state of its own it cannot continue,
//!   and the lease is given back. The claim then re-attests the head with this node's key and
//!   higher token, so the journal continues from the previous holder's last head. Without an
//!   offer newer than its own state it continues with its own record and credentials, and with
//!   neither it gives the lease back.
//! - **Giving a lease up.** At a clean point (the account's worker stopped), the node exports
//!   its state of the account and offers it to every node that may lead it, then releases.
//!
//! - **Taking over from a silent server.** Under a fallback arbiter entered because the server
//!   went silent (not on its leaving notice), the first time this node takes an account whose
//!   journal a server wrote last, every queued command that cannot be repeated is presumed
//!   started (Skein's `presume_started`): the server may still have been running the same queue
//!   when it was cut off, so those commands are reported uncertain instead of run twice.
//!
//! With the local arbiter (a group without a server) neither runs: each node leads what it added.

use std::sync::Weak;

use async_trait::async_trait;
use baton_lease::Lease;
use rowboat_api::NodeEvent;
use skein_core::{AccountId, TenantId};
use skein_engine::{EngineError, LeaseHooks};
use tracing::{info, warn};

use crate::boot::Core;

pub(crate) struct NodeHooks {
    pub core: Weak<Core>,
}

async fn state_fence(core: &Core, account: &AccountId) -> Option<u64> {
    let (bytes, _) = core
        .local
        .control
        .get(&core.tenant, &format!("state/{account}"))
        .await
        .ok()??;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("fence")?
        .as_u64()
}

/// Whether the account's journal was last written by a server node (the head this node is about
/// to continue).
async fn server_wrote_last(core: &Core, account: &AccountId) -> bool {
    let (Ok(m), Ok(head)) = (
        core.group.membership(),
        core.local.log.signed_head(&core.tenant, account).await,
    ) else {
        return false;
    };
    head.attestation
        .as_deref()
        .and_then(|a| rowboat_sync::attestation_signer(&head.head, a).ok())
        .is_some_and(|s| m.class_of(&s) == Some(baton_lease::NodeClass::Server))
}

pub(crate) async fn can_lead_alone(core: &Core, account: &AccountId) -> bool {
    let record = core
        .local
        .control
        .get(&core.tenant, &format!("accounts/{account}"))
        .await
        .ok()
        .flatten()
        .is_some();
    let credentials = core
        .local
        .control
        .list(&core.tenant, &format!("credentials/{account}"), None, 1)
        .await
        .is_ok_and(|l| !l.is_empty());
    record && credentials
}

#[async_trait]
impl LeaseHooks for NodeHooks {
    async fn acquired(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        lease: &Lease,
    ) -> Result<(), EngineError> {
        let Some(core) = self.core.upgrade() else {
            return Err(EngineError::NotOwner);
        };
        if tenant != &core.tenant || !core.arbiter.shared() {
            return Ok(());
        }
        let replication = core.replication().map_err(|_| EngineError::NotOwner)?;
        replication.round().await;
        let own = state_fence(&core, account).await;
        let offer = replication.staged(account).await;
        let newer = offer.as_ref().is_some_and(|o| {
            o.signed(&core.tenant)
                .is_ok_and(|h| own.is_none_or(|f| h.head.fence.0 > f))
        });
        if newer {
            let offer = offer.expect("checked above");
            let membership = core.group.membership().map_err(|_| EngineError::NotOwner)?;
            if let Err(e) = rowboat_sync::handover::import(
                &core.tenant,
                &core.local,
                &*core.keyring,
                &membership,
                &offer,
            )
            .await
            {
                warn!(%account, error = %e, "the account's state could not be taken over");
                return Err(EngineError::NotOwner);
            }
            info!(%account, fence = lease.fence.0, "took the account over with its state");
            core.hub.send(NodeEvent::AccountsChanged);
        } else if !can_lead_alone(&core, account).await {
            return Err(EngineError::NotOwner);
        }
        if server_wrote_last(&core, account).await && core.arbiter.presume_once(account.as_str()) {
            match skein_engine::presume_started(&core.storage, &core.tenant, account).await {
                Ok(n) if n > 0 => {
                    warn!(%account, commands = n, "taken over from a silent server: its queued commands are reported uncertain")
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(%account, error = %e, "the queue could not be marked");
                    return Err(EngineError::NotOwner);
                }
            }
        }
        if let Ok(id) = rowboat_api::AccountId::new(account.as_str())
            && let Some(mut meta) = crate::api::meta_of(&core, &id).await
            && meta.owner.is_some()
        {
            meta.owner = None;
            if crate::api::put_meta(&core, &meta).await.is_ok() {
                core.hub.send(NodeEvent::AccountsChanged);
            }
        }
        Ok(())
    }

    async fn releasing(&self, tenant: &TenantId, account: &AccountId, lease: &Lease) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        if tenant != &core.tenant || !core.arbiter.shared() {
            return;
        }
        offer(&core, account).await;
        info!(%account, fence = lease.fence.0, "handed the account over");
    }
}

/// Exports this node's state of `account` and offers it to the nodes that may lead it. Returns
/// how many took it.
pub(crate) async fn offer(core: &Core, account: &AccountId) -> usize {
    let (Ok(replication), Ok(membership)) = (core.replication(), core.group.membership()) else {
        return 0;
    };
    match rowboat_sync::handover::export(
        &core.tenant,
        &core.local,
        &*core.keyring,
        &membership,
        account,
    )
    .await
    {
        Ok(offer) => {
            let took = replication.hand_over(&offer).await;
            if took > 0 {
                let mut e = core.eligibility.lock().unwrap_or_else(|e| e.into_inner());
                e.handed.insert(account.to_string());
                e.sole.remove(account.as_str());
            }
            took
        }
        Err(e) => {
            warn!(%account, error = %e, "the account's state could not be offered");
            0
        }
    }
}
