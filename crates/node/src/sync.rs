//! The node's side of replication (`rowboat-sync`): what it tells replication about itself, the
//! replica accounts it shows, the commands it hands to the owner, and the loop that follows the
//! journals it reads and announces the ones it leads.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use baton_identity::PublicKey;
use rowboat_api::{
    AccountId, CommandId, CommandOutcome, EmailAddress, GroupEvent, MailboxId, NodeError,
    NodeEvent, SendOutcome, check,
};
use rowboat_sync::{About, Host, Settled, SyncError};
use skein_core::BlobHash;
use tokio::sync::watch;
use tracing::info;

use crate::boot::Core;
use crate::events::Chore;
use crate::records::{self, AccountMeta};

pub(crate) fn err(e: SyncError) -> NodeError {
    match e {
        SyncError::Busy => NodeError::QuotaFull,
        SyncError::Storage => NodeError::Storage,
        SyncError::NotAuthorized | SyncError::NotHere => NodeError::NotFound,
        SyncError::Unreachable | SyncError::TimedOut => NodeError::ServerUnreachable,
        _ => NodeError::Internal,
    }
}

/// What replication asks the node.
pub(crate) struct NodeHost {
    pub core: Weak<Core>,
}

fn skein_account(account: &skein_core::AccountId) -> Option<AccountId> {
    AccountId::new(account.as_str()).ok()
}

#[async_trait]
impl Host for NodeHost {
    fn leads(&self, account: &skein_core::AccountId) -> bool {
        self.core
            .upgrade()
            .is_some_and(|c| c.leads(account.as_str()))
    }

    async fn about(&self, account: &skein_core::AccountId) -> Option<About> {
        let core = self.core.upgrade()?;
        let meta = crate::api::meta_of(&core, &skein_account(account)?).await?;
        if meta.removing
            || !(core.leads(account.as_str())
                || crate::leases::wrote_last(&core, account, false).await)
        {
            return None;
        }
        Some(About {
            address: meta.address.to_string(),
            display_name: meta.display_name,
            archive: meta.archive.map(|m| m.to_string()),
        })
    }

    async fn holds_blob(&self, account: &skein_core::AccountId, blob: &BlobHash) -> bool {
        let Some(core) = self.core.upgrade() else {
            return false;
        };
        if core
            .replication
            .get()
            .is_some_and(|r| r.outbox_holds(account, blob))
        {
            return true;
        }
        let store = core.store.clone();
        let (name, hex, b) = (account.to_string(), blob.to_hex(), *blob);
        tokio::task::spawn_blocking(move || {
            store.has_message(&name, &hex).unwrap_or(false)
                || store.has_object(&name, &b).unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    }

    async fn described(&self, account: &skein_core::AccountId, owner: &PublicKey, about: &About) {
        let (Some(core), Some(account)) = (self.core.upgrade(), skein_account(account)) else {
            return;
        };
        let Ok(address) = EmailAddress::new(about.address.clone()) else {
            return;
        };
        let display_name = about
            .display_name
            .clone()
            .filter(|n| check::one_line(n, rowboat_api::MAX_NAME_CHARS));
        let archive = about.archive.clone().and_then(|a| MailboxId::new(a).ok());
        let existing = crate::api::meta_of(&core, &account).await;
        if core.leads(account.as_str())
            || existing
                .as_ref()
                .is_some_and(|m| m.removing || (m.owner.is_none() && !core.arbiter.shared()))
        {
            return;
        }
        let meta = AccountMeta {
            v: records::FORMAT,
            account: account.clone(),
            address,
            display_name,
            archive,
            removing: false,
            notify: existing.as_ref().is_none_or(|m| m.notify),
            created_at: existing
                .as_ref()
                .map_or_else(|| core.clock.now_ms(), |m| m.created_at),
            owner: Some(owner.node_id().to_string()),
        };
        if existing.as_ref() == Some(&meta) {
            return;
        }
        if crate::api::put_meta(&core, &meta).await.is_ok() {
            info!(account = %account, "following an account another node leads");
            core.hub.send(NodeEvent::AccountsChanged);
        }
    }

    async fn admits(
        &self,
        _: &skein_core::AccountId,
        signed: &skein_storage::SignedHead,
        remote: Option<&rowboat_sync::Grant>,
        local: Option<&rowboat_sync::Grant>,
    ) -> bool {
        match self.core.upgrade() {
            Some(core) => core.arbiter.admits(signed, remote, local).await,
            None => false,
        }
    }

    fn previous_owner_silent(&self, _: &skein_core::AccountId) -> bool {
        self.core.upgrade().is_some_and(|core| {
            core.arbiter.arbiter().fallback()
                && core.arbiter.fallback_reason() == Some(crate::fallback::Reason::Silence)
        })
    }

    async fn superseded(&self, account: &skein_core::AccountId, fence: u64) {
        if let Some(core) = self.core.upgrade() {
            info!(%account, node = %core.node_id, fence, "a later holder of an account this node leads exists; giving it up");
            core.arbiter.yield_account(account.as_str(), fence);
        }
    }

    fn installed(&self, _: &skein_core::AccountId, _: u64) {}

    fn forked(&self, account: &skein_core::AccountId) {
        if let (Some(core), Some(account)) = (self.core.upgrade(), skein_account(account)) {
            core.group.raise(GroupEvent::JournalForked { account });
        }
    }

    fn group_behind(&self, peer: &PublicKey) {
        if let Some(core) = self.core.upgrade() {
            core.group.catch_up_with(*peer);
        }
    }

    async fn reset(&self, account: &skein_core::AccountId) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        let purged = match core.local.log.purge_account(&core.tenant, account).await {
            Ok(_) => skein_storage::purge_account(&*core.objects, &core.tenant, account).await,
            Err(e) => Err(e),
        };
        if let Err(e) = purged {
            tracing::warn!(%account, error = %e, "dropping a deposed replica failed");
            return;
        }
        let store = core.store.clone();
        let name = account.to_string();
        let _ = tokio::task::spawn_blocking(move || store.forget_account(&name)).await;
        core.synced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(account.as_str());
        info!(%account, "a deposed replica was dropped; following again");
        core.hub.send(NodeEvent::AccountsChanged);
    }

    fn settled(&self, account: &skein_core::AccountId, command: &str, outcome: Settled) {
        let (Some(core), Some(account), Ok(id)) = (
            self.core.upgrade(),
            skein_account(account),
            CommandId::new(command.to_owned()),
        ) else {
            return;
        };
        core.overlay.settled(account.as_str(), command, false);
        if core.sends.remove(command) {
            let outcome = match outcome {
                Settled::Failed { reason } => SendOutcome::Failed { reason },
                Settled::Uncertain => SendOutcome::Uncertain,
            };
            let sent = !matches!(outcome, SendOutcome::Failed { .. });
            let _ = core.chores.try_send(Chore::SendDone {
                command: command.to_owned(),
                sent,
            });
            core.hub.send(NodeEvent::SendSettled {
                account,
                command: id,
                outcome,
            });
            return;
        }
        let outcome = match outcome {
            Settled::Failed { reason } => CommandOutcome::Failed { reason },
            Settled::Uncertain => CommandOutcome::Uncertain,
        };
        core.hub.send(NodeEvent::CommandSettled {
            account,
            command: id,
            outcome,
        });
    }
}

/// Follows the journals the node reads and announces those it leads: every `tick` the heads of
/// the led accounts are compared with what was last announced, and every `round` ticks the
/// node asks its peers for the heads of what it follows and delivers its outbox.
pub(crate) async fn run(
    core: Arc<Core>,
    tick: Duration,
    round_every: u32,
    mut stop: watch::Receiver<bool>,
) {
    let mut announced: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut offered: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut ticks: u32 = 0;
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            r = stop.wait_for(|s| *s) => {
                drop(r);
                break;
            }
        }
        crate::leases::refresh_eligibility(&core).await;
        let Some(replication) = core.replication.get().cloned() else {
            continue;
        };
        if !core.group.link_up().await {
            continue;
        }
        let round = round_every > 0 && ticks.is_multiple_of(round_every);
        if ticks.is_multiple_of(5) || core.arbiter.server_answers() {
            fallback_tails(&core, &replication).await;
        }
        if core.arbiter.shared() {
            let again = ticks.is_multiple_of(round_every.max(20));
            offer_states(&core, &mut offered, again).await;
        }
        for account in core.led_accounts().await {
            let Ok(id) = skein_core::AccountId::new(account.clone()) else {
                continue;
            };
            let Ok(head) = core.local.log.signed_head(&core.tenant, &id).await else {
                continue;
            };
            let now = (head.head.seq.0, head.head.fence.0);
            if now.0 == 0 || announced.get(&account) == Some(&now) {
                continue;
            }
            replication.announce(&id).await;
            announced.insert(account, now);
        }
        let work = async {
            if round {
                replication.round().await;
                replication.prune().await;
            } else if replication.outbox_len() > 0 {
                replication.flush().await;
            }
        };
        let stopped = tokio::select! {
            _ = work => false,
            r = stop.wait_for(|s| *s) => {
                drop(r);
                true
            }
        };
        if stopped {
            break;
        }
        ticks = ticks.wrapping_add(1);
    }
    if let Some(r) = core.replication.get() {
        r.detach().await;
    }
}

/// The journals this node wrote under a fallback arbiter's grant are announced again and again
/// from the moment the server answers again, while this node still arbitrates without it (the
/// server must learn of them before its lease server grants again, one time-to-live after it
/// started, or it leads its own journal and the devices' is lost), until this node continues
/// them under a grant of the server; one it has not continued two takeover delays after the
/// server came back (the server kept its own journal: another device held the account under it
/// all along) is dropped and followed again from the group.
async fn fallback_tails(core: &Core, replication: &rowboat_sync::Replication) {
    let in_fallback = core.arbiter.in_fallback();
    if in_fallback && !core.arbiter.server_answers() {
        return;
    }
    let tails: Vec<String> = core
        .eligibility
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .fallback_tail
        .iter()
        .cloned()
        .collect();
    let late = core
        .arbiter
        .back_for()
        .is_some_and(|b| b >= core.arbiter.fallback_timing().takeover * 2);
    for name in tails {
        let Ok(account) = skein_core::AccountId::new(name.clone()) else {
            continue;
        };
        if in_fallback {
            replication.announce(&account).await;
            continue;
        }
        if core.leads(&name) {
            continue;
        }
        if late {
            tracing::warn!(%account, "the group kept another journal of an account this node wrote without the server; dropping its own");
            replication.drop_replica(&account).await;
        } else {
            replication.announce(&account).await;
        }
    }
}

/// Offers this node's state of every account whose journal it wrote last (it leads it, or led it
/// and nobody wrote after) to the nodes that may lead it, when the head moved, and again every
/// round (every 20 ticks at least). Never while a worker of the account runs without the lease
/// (it took it under an arbiter that changed since): a node that took the offer could lead while
/// that worker still acts.
async fn offer_states(core: &Core, offered: &mut BTreeMap<String, (u64, u64)>, round: bool) {
    let me = core.group.membership().map(|m| m.node()).ok();
    let Ok(records) = core.accounts.list(&core.tenant).await else {
        return;
    };
    for record in records {
        let account = record.account;
        let Ok(head) = core.local.log.signed_head(&core.tenant, &account).await else {
            continue;
        };
        let mine = head
            .attestation
            .as_deref()
            .and_then(|a| rowboat_sync::attestation_signer(&head.head, a).ok())
            .is_some_and(|s| Some(s) == me);
        let at = (head.head.seq.0, head.head.fence.0);
        if !mine || (!round && offered.get(account.as_str()) == Some(&at)) {
            continue;
        }
        let stale_worker = core.engine.get().is_some_and(|e| {
            e.has_worker(&core.tenant, &account) && !e.holds_lease(&core.tenant, &account)
        });
        if stale_worker {
            continue;
        }
        if crate::handover::offer(core, &account).await > 0 {
            offered.insert(account.to_string(), at);
        }
    }
}
