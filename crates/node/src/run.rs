use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use baton_lease::{Leases, Liveness};
use baton_lease_cas::{CasLeases, CasLiveness};
use baton_state::StateStore;
use rowboat_api::{AccountId, DomainState, Health, NodeEvent};
use skein_accounts::{Directory, OAuthClients, Senders, TenantRegistry};
use skein_core::{AccountHealth, CommandBody, DomainStatus};
use skein_engine::{Engine, OneGroupLiveness, RunConfig, SendPolicy, node_profile};
use skein_keyring::KeyScope;
use skein_oauth::{OAuthError, TokenAnswer, TokenEndpoint};
use skein_storage::{ControlState, Expect, ObjectKey};
use skein_view::{Follower, Timing};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::boot::{Core, Node};
use crate::events::{Chore, Observer};
use crate::parser::ContentParser;

/// OAuth is not offered in phase 1: every token request fails without a connection.
pub(crate) struct NoTokens;

#[async_trait]
impl TokenEndpoint for NoTokens {
    async fn post_form(&self, _: &str, _: &[(String, String)]) -> Result<TokenAnswer, OAuthError> {
        Err(OAuthError::Connection("OAuth is not available".into()))
    }
}

impl Node {
    /// Starts the engine, the follower and the node's housekeeping. Calling it again does
    /// nothing.
    pub async fn start(&self) {
        let Some(chores) = self.chores.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return;
        };
        let core = self.core.clone();
        let timing = core.profile.timing();
        let mut tasks = Vec::new();

        let heartbeat_ms = timing.heartbeat.as_millis() as u64;
        let state: Arc<dyn StateStore> = Arc::new(ControlState::new(core.storage.control.clone()));
        let liveness: Arc<dyn Liveness> = Arc::new(OneGroupLiveness::nodes(Arc::new(
            CasLiveness::new(state.clone(), heartbeat_ms * 3),
        )));
        let cas = Arc::new(CasLeases::new(state, liveness.clone()).reuse_alive_for(heartbeat_ms));
        let _ = core.leases.set(cas.clone());
        let leases: Arc<dyn Leases> = cas;
        let profile = node_profile(
            baton_core::NodeId::new(core.node_id.clone()).expect("an identity's id"),
            1,
            false,
        );
        let engine = Engine::new(core.storage.clone(), leases, core.signal.clone(), profile)
            .without_message_inspection()
            .with_senders(Arc::new(Senders::new(
                core.accounts.clone(),
                core.tokens.clone(),
                OAuthClients::new(),
                core.providers.send.clone(),
            )))
            .with_send_policy(SendPolicy {
                undo_ms: timing.undo_ms,
                ..SendPolicy::default()
            });
        let directory = Arc::new(Directory::new(
            TenantRegistry::new(core.objects.clone()),
            core.accounts.clone(),
            core.tokens.clone(),
            OAuthClients::new(),
            core.providers.mail.clone(),
        ));
        let mut run = RunConfig::new(liveness);
        run.heartbeat = timing.heartbeat;
        run.interval = timing.interval;
        let mut stop = self.stop.subscribe();
        tasks.push(tokio::spawn(async move {
            skein_engine::run(engine, directory, run, async move {
                let _ = stop.wait_for(|s| *s).await;
            })
            .await;
        }));

        let parser = Arc::new(ContentParser::new(
            core.content.clone(),
            core.spam.clone(),
            core.category.clone(),
            Arc::new(crate::parser::AccountReceivers::new(
                core.accounts.clone(),
                core.storage.control.clone(),
                core.tenant.clone(),
            )),
            core.profile.content_workers(),
        ));
        let observer = Arc::new(Observer {
            hub: core.hub.clone(),
            overlay: core.overlay.clone(),
            sends: core.sends.clone(),
            chores: core.chores.clone(),
            synced: core.synced.clone(),
        });
        {
            let store = core.store.clone();
            let rows = tokio::task::spawn_blocking(move || store.accounts())
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
            let mut synced = core.synced.lock().unwrap_or_else(|e| e.into_inner());
            synced.extend(
                rows.into_iter()
                    .filter(|r| r.first_sync_completed)
                    .map(|r| r.account),
            );
        }
        let follower = Follower::new(
            core.storage.clone(),
            core.tenant.clone(),
            core.store.clone(),
        )
        .with_signal(core.signal.clone())
        .with_parser(parser)
        .with_observer(observer);
        let follow_timing = Timing {
            poll: timing.poll,
            safety: timing.poll * 60,
        };
        tasks.push(tokio::spawn(
            follower.run(follow_timing, self.stop.subscribe()),
        ));

        load_sends(&core).await;
        tasks.push(tokio::spawn(housekeeping(
            core.clone(),
            chores,
            timing.heartbeat,
            self.stop.subscribe(),
        )));
        for meta in crate::api::all_metas(&core).await.unwrap_or_default() {
            if meta.removing {
                spawn_removal(core.clone(), meta.account.clone());
            }
        }
        info!(node = %core.node_id, "node started");
        self.tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(tasks);
    }

    /// Stops the engine (which releases every lease it holds), the follower and housekeeping,
    /// waiting at most 30 s for each.
    pub async fn shutdown(&self) {
        let _ = self.stop.send(true);
        let tasks: Vec<_> =
            std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|e| e.into_inner()));
        for task in tasks {
            let _ = tokio::time::timeout(Duration::from_secs(30), task).await;
        }
        info!(node = %self.core.node_id, "node stopped");
    }
}

async fn load_sends(core: &Core) {
    for meta in crate::api::all_metas(core).await.unwrap_or_default() {
        let Ok(account) = skein_core::AccountId::new(meta.account.as_str()) else {
            continue;
        };
        if let Ok(pending) = core
            .storage
            .commands
            .pending(&core.tenant, &account, 1000)
            .await
        {
            for c in pending {
                if c.body.is_send() {
                    core.sends.add(c.id.as_str());
                }
            }
        }
    }
}

fn health(h: Option<AccountHealth>) -> Health {
    match h {
        None => Health::Unknown,
        Some(AccountHealth::Healthy) => Health::Healthy,
        Some(AccountHealth::ReauthRequired) => Health::ReauthRequired,
        Some(AccountHealth::Throttled) => Health::Throttled,
        Some(AccountHealth::Degraded) => Health::Degraded,
    }
}

pub(crate) fn domain(d: &DomainStatus) -> DomainState {
    DomainState {
        outcome: serde_json::to_value(d.outcome)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "other".into()),
        last_ok_at: d.last_ok_at.map(|t| t.0),
        last_error_at: d.last_error_at.map(|t| t.0),
    }
}

/// The account's status as the API shows it, from the engine's status record.
pub(crate) async fn status_of(
    core: &Core,
    account: &AccountId,
) -> (Health, Option<DomainState>, Option<DomainState>) {
    let Ok(id) = skein_core::AccountId::new(account.as_str()) else {
        return (Health::Unknown, None, None);
    };
    match skein_engine::load_status(&*core.storage.control, &core.tenant, &id).await {
        Ok(Some(s)) => (
            health(s.health()),
            s.mail.as_ref().map(domain),
            s.send.as_ref().map(domain),
        ),
        _ => (Health::Unknown, None, None),
    }
}

async fn housekeeping(
    core: Arc<Core>,
    mut chores: mpsc::Receiver<Chore>,
    every: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            chore = chores.recv() => match chore {
                Some(Chore::SendDone { command, sent }) => {
                    if let Err(e) = crate::api::settle_draft(&core, &command, sent).await {
                        warn!(command = %command, error = %e, "settling a draft failed");
                    }
                }
                Some(Chore::Arrived { account, added }) => {
                    crate::notify::arrived(&core, account, added).await;
                }
                None => break,
            },
            _ = tick.tick() => {
                core.overlay.expire(core.clock.now_ms());
                refresh_statuses(&core).await;
            }
        }
        if *stop.borrow() {
            break;
        }
    }
}

async fn refresh_statuses(core: &Core) {
    for meta in crate::api::all_metas(core).await.unwrap_or_default() {
        if meta.removing {
            continue;
        }
        let (health, mail, send) = status_of(core, &meta.account).await;
        let fingerprint = format!("{health:?}{mail:?}{send:?}");
        let changed = {
            let mut cache = core.statuses.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(meta.account.to_string(), fingerprint.clone()) != Some(fingerprint)
        };
        if changed {
            core.hub.send(NodeEvent::AccountStatus {
                account: meta.account.clone(),
                health,
                mail,
                send,
            });
        }
    }
}

/// Finishes removing an account in the background, after the engine let go of it.
pub(crate) fn spawn_removal(core: Arc<Core>, account: AccountId) {
    if !core
        .removing
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(account.to_string())
    {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(core.profile.timing().removal_grace).await;
        match remove_now(&core, &account).await {
            Ok(blobs) => info!(account = %account, blobs, "account removed"),
            Err(e) => {
                warn!(account = %account, error = %e, "removing an account failed; retried on the next start")
            }
        }
        core.removing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(account.as_str());
        core.hub.send(NodeEvent::AccountsChanged);
    });
}

async fn remove_now(core: &Core, account: &AccountId) -> Result<u64, rowboat_api::NodeError> {
    let id = skein_core::AccountId::new(account.as_str())
        .map_err(|_| rowboat_api::NodeError::Internal)?;
    let store = core.store.clone();
    let name = account.to_string();
    let mut named = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let s = store.clone();
        let n = name.clone();
        let a = after.clone();
        let page = tokio::task::spawn_blocking(move || s.blobs_of(&n, a.as_deref(), 1000))
            .await
            .map_err(|_| rowboat_api::NodeError::Internal)?
            .map_err(crate::errors::view)?;
        let full = page.len() == 1000;
        after = page.last().cloned();
        named.extend(page);
        if !full {
            break;
        }
    }
    match skein_accounts::admin::delete_account(&core.accounts, &core.tokens, &core.tenant, &id)
        .await
    {
        Ok(()) | Err(skein_accounts::admin::AdminError::NotFound) => {}
        Err(_) => return Err(rowboat_api::NodeError::Storage),
    }
    core.keyring
        .destroy(&KeyScope::account_of(&core.tenant, &id))
        .await
        .map_err(|_| rowboat_api::NodeError::Storage)?;
    skein_storage::purge_account(&*core.objects, &core.tenant, &id)
        .await
        .map_err(crate::errors::storage)?;
    if let Some(leases) = core.leases.get() {
        let forgotten = leases
            .forget(
                &skein_core::coordination::group(&core.tenant),
                &skein_core::coordination::lease_key(&id),
            )
            .await
            .map_err(|_| rowboat_api::NodeError::Storage)?;
        if !forgotten {
            warn!(account = %account, "the account's lease is still held; its record stays");
        }
    }
    let s = store.clone();
    let n = name.clone();
    tokio::task::spawn_blocking(move || s.forget_account(&n))
        .await
        .map_err(|_| rowboat_api::NodeError::Internal)?
        .map_err(crate::errors::view)?;

    let mut kept: BTreeSet<String> = BTreeSet::new();
    for meta in crate::api::all_metas(core).await? {
        if meta.account == *account {
            continue;
        }
        let Ok(other) = skein_core::AccountId::new(meta.account.as_str()) else {
            continue;
        };
        for c in core
            .storage
            .commands
            .pending(&core.tenant, &other, 10_000)
            .await
            .map_err(crate::errors::storage)?
        {
            if let CommandBody::Send { blob, .. } | CommandBody::Append { blob, .. } = c.body {
                kept.insert(blob.to_hex());
            }
        }
    }
    let mut swept = 0;
    for blob in named {
        if kept.contains(&blob) {
            continue;
        }
        let s = store.clone();
        let b = blob.clone();
        let known = tokio::task::spawn_blocking(move || s.knows_blob(&b))
            .await
            .map_err(|_| rowboat_api::NodeError::Internal)?
            .map_err(crate::errors::view)?;
        if known {
            continue;
        }
        let Ok(key) = ObjectKey::tenant(&core.tenant)
            .join("blobs")
            .and_then(|k| k.join(&blob))
        else {
            continue;
        };
        core.objects
            .delete(&key, Expect::Any)
            .await
            .map_err(crate::errors::storage)?;
        swept += 1;
    }
    crate::api::delete_meta(core, account).await?;
    Ok(swept)
}
