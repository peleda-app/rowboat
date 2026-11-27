use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use baton_command::{CommandError, CommandResult, Outcome, Request};
use baton_core::{ResourceId, Timestamp};
use baton_fetch::{ContentId, FetchConfig, Fetcher};
use baton_group::Capability;
use baton_identity::PublicKey;
use baton_link::{Duplex, Link, Protocol};
use baton_signal::Signal;
use bytes::Bytes;
use futures::StreamExt;
use rowboat_group::{Membership, Now, account_resource};
use skein_core::{AccountId, BlobHash, Command, CommandBody, CommandId, TenantId};
use skein_engine::{SubmitError, cancel_command, check_command, submit_command, wake_topic};
use skein_storage::{Expect, SignedHead, Storage, StorageError};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::commands::{
    CMDKEY_TTL_MS, COMMAND_PROTOCOL, COMMAND_TTL_MS, COMMAND_VERSION, CmdKey, CmdMsg, CmdState,
    MAX_FRAME, MAX_OUTBOX, OutboxEntry, RemoteRequest, SYNC_TTL_MS, decode_msg, decode_request,
    derive_queue_id, reason_ok,
};
use crate::handover::{HANDOVER_PROTOCOL, MAX_STATE, Offer};
use crate::heads::{HEAD_PROTOCOL, HEAD_VERSION, HeadMsg, MAX_ACCOUNTS, WireHead};
use crate::replica::{Caught, Replica, fork_path};
use crate::tier::{Peers, Served};
use crate::{Host, Settled, SyncError, verify_remote};

const OUTBOX: &str = "rowboat/outbox";
const STAGED: &str = "rowboat/handover";
const CMDKEYS: &str = "rowboat/cmdkeys";
const MAX_SERVED: usize = 8;
const MAX_PRUNE: usize = 10_000;

/// Limits of replication and commands.
#[derive(Debug, Clone)]
pub struct Config {
    /// How long one step of a protocol (opening a stream, one frame) may take.
    pub limit: Duration,
    /// The fetcher's and the fetch server's limits.
    pub fetch: FetchConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limit: Duration::from_secs(20),
            fetch: FetchConfig {
                peer_timeout: Duration::from_secs(20),
                header_timeout: Duration::from_secs(5),
                min_rate: 64 * 1024,
                ..FetchConfig::default()
            },
        }
    }
}

/// Replication of the journals this node reads and commands between this node and the owners
/// of the accounts it reads.
///
/// Guarantees:
///
/// - A replica moves only to a head [`verify_remote`] accepted, never back, never below a fence
///   it holds, never over an account this node leads ([`Host::leads`]), and only once the chain
///   from that head back to its own tip verified and is stored; a fork stops following the
///   account for good and keeps both heads' digests as evidence.
/// - Of the heads peers offer for one account, the newest verified one is followed.
/// - Heads, segments and blobs are served only to nodes that may read the account in the group
///   log; commands are run only for accounts this node leads.
/// - A command issued here stays in the outbox (at most [`MAX_OUTBOX`]) until a valid signed
///   result arrives, the owner refuses it, or it expires; it reaches Skein's queue at most once
///   per queue id, and a redelivery is answered from the owner's record.
pub struct Replication {
    tenant: TenantId,
    membership: Arc<Membership>,
    peers: Arc<Peers>,
    local: Storage,
    served: Arc<Storage>,
    through: Storage,
    signal: Arc<dyn Signal>,
    host: Arc<dyn Host>,
    now: Now,
    config: Config,
    link: RwLock<Option<Arc<dyn Link>>>,
    serving: Mutex<Vec<JoinHandle<()>>>,
    attempts: Mutex<BTreeMap<AccountId, ([u8; 32], u32)>>,
    forked: Mutex<BTreeSet<AccountId>>,
    outbox: Mutex<BTreeMap<String, OutboxEntry>>,
    catching: tokio::sync::Mutex<()>,
    flushing: tokio::sync::Mutex<()>,
    running: Arc<Mutex<BTreeSet<String>>>,
    fetches: Arc<std::sync::atomic::AtomicUsize>,
    attempted: Mutex<BTreeSet<String>>,
}

struct Running {
    set: Arc<Mutex<BTreeSet<String>>>,
    path: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.set.lock().expect("running lock").remove(&self.path);
    }
}

#[derive(Clone)]
struct Queuer {
    tenant: TenantId,
    local: Storage,
    signal: Arc<dyn Signal>,
}

impl Queuer {
    async fn put(&self, path: &str, key: &CmdKey, expect: Expect) -> Result<(), StorageError> {
        self.local
            .control
            .put(
                &self.tenant,
                path,
                Bytes::from(serde_json::to_vec(key).expect("plain struct")),
                expect,
            )
            .await
            .map(|_| ())
    }

    async fn submit(&self, path: &str, claim: CmdKey, command: &Command) -> Result<Outcome, ()> {
        let reason = match submit_command(&self.local, &*self.signal, &self.tenant, command).await {
            Ok(_) => None,
            Err(SubmitError::IdConflict) => Some("conflict"),
            Err(SubmitError::BlobMissing) => Some("blob_missing"),
            Err(SubmitError::Invalid { .. }) => Some("invalid"),
            Err(_) => return Err(()),
        };
        let record = CmdKey {
            state: match reason {
                None => CmdState::Queued,
                Some(r) => CmdState::Refused {
                    reason: r.to_owned(),
                },
            },
            ..claim
        };
        self.put(path, &record, Expect::Any).await.map_err(|_| ())?;
        info!(account = %command.account, command = %command.id, "a remote command was queued");
        Ok(match reason {
            None => Outcome::Applied,
            Some(r) => failed(r),
        })
    }
}

fn storage<E>(_: E) -> SyncError {
    SyncError::Storage
}

fn staged_path(account: &AccountId) -> String {
    format!("{STAGED}/{account}")
}

fn account_of(resource: &ResourceId) -> Option<AccountId> {
    resource
        .as_str()
        .strip_prefix("acct-")
        .and_then(|a| AccountId::new(a).ok())
}

fn refusal(e: &CommandError) -> &'static str {
    match e {
        CommandError::Malformed => "malformed",
        CommandError::BadSignature => "bad_signature",
        CommandError::WrongGroup => "wrong_group",
        CommandError::CatchUp => "catch_up",
        CommandError::Fork => "fork",
        CommandError::Expired => "expired",
        CommandError::NotAuthorized => "not_authorized",
        CommandError::Sealed => "sealed",
        CommandError::Invalid(_) => "invalid",
    }
}

fn failed(reason: &str) -> Outcome {
    Outcome::Failed {
        reason: reason.to_owned(),
    }
}

enum Delivery {
    Done,
    Settled(Settled),
    Keep,
}

impl Replication {
    /// Replication for `tenant`: `local` is the node's own storage (its journal attested by
    /// [`crate::NodeAttestor`]), `through` the same storage reading segments and blobs through a
    /// [`crate::PeerTier`] over `peers`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantId,
        peers: Arc<Peers>,
        local: Storage,
        through: Storage,
        signal: Arc<dyn Signal>,
        host: Arc<dyn Host>,
        now: Now,
        config: Config,
    ) -> Self {
        Self {
            tenant,
            membership: peers.membership().clone(),
            peers,
            served: Arc::new(local.clone()),
            local,
            through,
            signal,
            host,
            now,
            config,
            link: RwLock::new(None),
            serving: Mutex::new(Vec::new()),
            attempts: Mutex::new(BTreeMap::new()),
            forked: Mutex::new(BTreeSet::new()),
            outbox: Mutex::new(BTreeMap::new()),
            catching: tokio::sync::Mutex::new(()),
            flushing: tokio::sync::Mutex::new(()),
            running: Arc::default(),
            fetches: Arc::default(),
            attempted: Mutex::new(BTreeSet::new()),
        }
    }

    /// Loads the outbox and the accounts that forked from storage. Call once before use.
    pub async fn load(&self) -> Result<(), SyncError> {
        let mut after: Option<String> = None;
        loop {
            let page = self
                .local
                .control
                .list(&self.tenant, OUTBOX, after.as_deref(), 1000)
                .await
                .map_err(storage)?;
            for path in &page {
                if let Some((bytes, _)) = self
                    .local
                    .control
                    .get(&self.tenant, path)
                    .await
                    .map_err(storage)?
                    && let Ok(entry) = rowboat_group::wire::decode::<OutboxEntry>(&bytes)
                {
                    let mut outbox = self.outbox.lock().expect("outbox lock");
                    if outbox.len() < MAX_OUTBOX {
                        outbox.insert(entry.queue.clone(), entry);
                    }
                }
            }
            if page.len() < 1000 {
                break;
            }
            after = page.last().cloned();
        }
        let forks = self
            .local
            .control
            .list(&self.tenant, "rowboat/forks", None, MAX_ACCOUNTS * 16)
            .await
            .map_err(storage)?;
        let mut forked = self.forked.lock().expect("forked lock");
        for path in forks {
            if let Some(a) = path.rsplit('/').next().and_then(|a| AccountId::new(a).ok()) {
                forked.insert(a);
            }
        }
        Ok(())
    }

    /// Who to ask, and the fetcher.
    pub fn peers(&self) -> &Arc<Peers> {
        &self.peers
    }

    /// Whether following `account` stopped because its journal forked.
    pub fn is_forked(&self, account: &AccountId) -> bool {
        self.forked.lock().expect("forked lock").contains(account)
    }

    fn link(&self) -> Option<Arc<dyn Link>> {
        self.link.read().expect("link lock").clone()
    }

    /// Serves heads, objects and commands on `link` and fetches through it, until
    /// [`Replication::detach`]. Attaching again replaces the previous link.
    pub async fn attach(self: &Arc<Self>, link: Arc<dyn Link>) -> Result<(), SyncError> {
        self.detach().await;
        let fetcher = Arc::new(Fetcher::new(link.clone(), None, self.config.fetch.clone()));
        let m = self.membership.clone();
        let authorize: baton_fetch::Authorize =
            Arc::new(move |peer, resource| m.node_may(peer, resource, &Capability::Read));
        let served = Arc::new(Served::new(
            self.tenant.clone(),
            &self.served,
            self.host.clone(),
        ));
        let fetch = baton_fetch::serve(link.clone(), served, authorize, self.config.fetch.clone())
            .await
            .map_err(|_| SyncError::Unreachable)?;
        let heads = self.listen(&link, HEAD_PROTOCOL, Self::serve_head).await?;
        let commands = self
            .listen(&link, COMMAND_PROTOCOL, Self::serve_command)
            .await?;
        let handover = self
            .listen(&link, HANDOVER_PROTOCOL, Self::serve_offer)
            .await?;
        self.peers.set_fetcher(Some(fetcher));
        *self.link.write().expect("link lock") = Some(link);
        self.serving
            .lock()
            .expect("serving lock")
            .extend([fetch, heads, commands, handover]);
        Ok(())
    }

    /// Stops serving and fetching.
    pub async fn detach(&self) {
        let tasks = std::mem::take(&mut *self.serving.lock().expect("serving lock"));
        for t in &tasks {
            t.abort();
        }
        for t in tasks {
            let _ = t.await;
        }
        self.peers.set_fetcher(None);
        *self.link.write().expect("link lock") = None;
    }

    async fn listen<F, Fut>(
        self: &Arc<Self>,
        link: &Arc<dyn Link>,
        protocol: &str,
        handler: F,
    ) -> Result<JoinHandle<()>, SyncError>
    where
        F: Fn(Arc<Self>, PublicKey, Box<dyn Duplex>) -> Fut + Send + Sync + Copy + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let protocol = Protocol::new(protocol).expect("constant");
        let mut incoming = link
            .listen(&protocol)
            .await
            .map_err(|_| SyncError::Unreachable)?;
        let me = Arc::downgrade(self);
        Ok(tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            while let Some(inc) = incoming.next().await {
                while handlers.try_join_next().is_some() {}
                if handlers.len() >= MAX_SERVED {
                    continue;
                }
                let Some(me) = me.upgrade() else {
                    break;
                };
                handlers.spawn(handler(me, inc.peer, inc.stream));
            }
        }))
    }

    fn may_read(&self, peer: &PublicKey, account: &AccountId) -> bool {
        account_resource(account.as_str())
            .is_some_and(|r| self.membership.node_may(peer, &r, &Capability::Read))
    }

    async fn wire_head(&self, account: &AccountId) -> Option<WireHead> {
        let signed = self
            .local
            .log
            .signed_head(&self.tenant, account)
            .await
            .ok()?;
        if signed.head.seq.0 == 0 {
            return None;
        }
        let about = if self.host.leads(account) {
            self.host.about(account).await
        } else {
            None
        };
        Some(WireHead::new(&signed, about))
    }

    async fn serve_head(self: Arc<Self>, peer: PublicKey, mut stream: Box<dyn Duplex>) {
        let limit = self.config.limit;
        let Ok(msg) = crate::heads::recv(&mut *stream, limit).await else {
            return;
        };
        match msg {
            HeadMsg::Ask { accounts, .. } => {
                let mut entries = Vec::new();
                let mut seen = BTreeSet::new();
                for a in accounts {
                    let Ok(account) = AccountId::new(a) else {
                        continue;
                    };
                    if !seen.insert(account.clone()) || !self.may_read(&peer, &account) {
                        continue;
                    }
                    if let Some(w) = self.wire_head(&account).await {
                        entries.push(w);
                    }
                }
                let _ = crate::heads::send(&mut *stream, &HeadMsg::Heads { entries }, limit).await;
            }
            HeadMsg::Announce { entries, .. } => {
                let _ = crate::heads::send(&mut *stream, &HeadMsg::Ack, limit).await;
                self.consider(vec![(peer, entries)]).await;
            }
            _ => {}
        }
    }

    async fn ask(
        &self,
        link: &Arc<dyn Link>,
        peer: &PublicKey,
        accounts: &[AccountId],
    ) -> Result<Vec<WireHead>, SyncError> {
        let limit = self.config.limit;
        let protocol = Protocol::new(HEAD_PROTOCOL).expect("constant");
        let mut stream = tokio::time::timeout(limit, link.open(peer, &protocol))
            .await
            .map_err(|_| SyncError::TimedOut)?
            .map_err(|_| SyncError::Unreachable)?;
        crate::heads::send(
            &mut *stream,
            &HeadMsg::Ask {
                v: HEAD_VERSION,
                accounts: accounts.iter().map(|a| a.to_string()).collect(),
            },
            limit,
        )
        .await?;
        match crate::heads::recv(&mut *stream, limit).await? {
            HeadMsg::Heads { entries } => Ok(entries),
            _ => Err(SyncError::Malformed),
        }
    }

    /// The accounts this node follows: it reads them, does not lead them, and they did not fork.
    pub fn followed(&self) -> Vec<AccountId> {
        let forked = self.forked.lock().expect("forked lock").clone();
        self.peers
            .readable()
            .into_iter()
            .filter(|a| !self.host.leads(a) && !forked.contains(a))
            .collect()
    }

    /// Asks every peer that counts for the heads of the followed accounts and follows the newest
    /// verified head of each; then delivers the outbox. Returns what happened per account.
    pub async fn round(&self) -> Vec<(AccountId, Result<Caught, SyncError>)> {
        let Some(link) = self.link() else {
            return Vec::new();
        };
        let forked = self.forked.lock().expect("forked lock").clone();
        let accounts: Vec<AccountId> = self
            .peers
            .readable()
            .into_iter()
            .filter(|a| !forked.contains(a))
            .collect();
        let mut answers = Vec::new();
        if !accounts.is_empty() {
            for chunk in accounts.chunks(MAX_ACCOUNTS) {
                let asks: Vec<_> = self
                    .membership
                    .counting_peers()
                    .into_iter()
                    .map(|peer| {
                        let link = link.clone();
                        async move { (peer, self.ask(&link, &peer, chunk).await) }
                    })
                    .collect();
                let got: Vec<_> = futures::stream::iter(asks)
                    .buffer_unordered(MAX_SERVED)
                    .collect()
                    .await;
                for (peer, r) in got {
                    if let Ok(entries) = r {
                        answers.push((peer, entries));
                    }
                }
            }
        }
        let out = self.consider(answers).await;
        self.flush().await;
        out
    }

    async fn consider(
        &self,
        answers: Vec<(PublicKey, Vec<WireHead>)>,
    ) -> Vec<(AccountId, Result<Caught, SyncError>)> {
        let mut by_account: BTreeMap<AccountId, Vec<(PublicKey, SignedHead, PublicKey)>> =
            BTreeMap::new();
        let mut locals: BTreeMap<AccountId, Option<SignedHead>> = BTreeMap::new();
        for (peer, entries) in answers {
            for e in entries.into_iter().take(MAX_ACCOUNTS) {
                let Ok((signed, about)) = e.signed(&self.tenant) else {
                    continue;
                };
                let account = signed.head.account.clone();
                if self.is_forked(&account) || !self.peers.readable().contains(&account) {
                    continue;
                }
                let Ok(signer) = verify_remote(&self.membership, &signed, (self.now)()) else {
                    continue;
                };
                if !locals.contains_key(&account) {
                    let local = self
                        .local
                        .log
                        .signed_head(&self.tenant, &account)
                        .await
                        .ok();
                    locals.insert(account.clone(), local);
                }
                let local = locals.get(&account).cloned().flatten();
                if !self.admitted(&signed, local.as_ref()).await {
                    continue;
                }
                if self.host.leads(&account) {
                    if local
                        .as_ref()
                        .is_some_and(|l| signed.head.fence > l.head.fence)
                    {
                        self.host.superseded(&account, signed.head.fence.0).await;
                    }
                    continue;
                }
                if let Some(about) = about
                    && signer == peer
                {
                    self.host.described(&account, &signer, &about).await;
                }
                by_account
                    .entry(account)
                    .or_default()
                    .push((peer, signed, signer));
            }
        }
        let mut out = Vec::new();
        for (account, mut heads) in by_account {
            heads.sort_by(|a, b| {
                (b.1.head.fence, b.1.head.seq).cmp(&(a.1.head.fence, a.1.head.seq))
            });
            let mut result = Err(SyncError::Unreachable);
            for (_, signed, signer) in heads {
                let r = self.follow(&signed).await;
                if matches!(r, Ok(Caught::Installed { .. } | Caught::Current)) {
                    self.peers.set_owner(&account, signer);
                }
                let done = !matches!(r, Err(SyncError::Unreachable));
                result = r;
                if done {
                    break;
                }
            }
            out.push((account, result));
        }
        out
    }

    /// Whether the node admits `signed` (verified) over its own head `local`, by the grants
    /// behind both fences ([`Host::admits`]).
    async fn admitted(&self, signed: &SignedHead, local: Option<&SignedHead>) -> bool {
        let remote = crate::head_grant(signed);
        let local = local.and_then(crate::head_grant);
        self.host
            .admits(
                &signed.head.account,
                signed,
                remote.as_ref(),
                local.as_ref(),
            )
            .await
    }

    /// Follows one verified head now (a test and recovery hook; rounds and announcements call
    /// it for every head they verify).
    pub async fn follow(&self, signed: &SignedHead) -> Result<Caught, SyncError> {
        let _guard = self.catching.lock().await;
        let account = signed.head.account.clone();
        let digest = signed.head.digest();
        let attempts = {
            let a = self.attempts.lock().expect("attempts lock");
            a.get(&account)
                .filter(|(d, _)| *d == digest)
                .map_or(0, |(_, n)| *n)
        };
        let replica = Replica {
            tenant: &self.tenant,
            local: &self.local,
            through: &self.through,
            host: &*self.host,
            signal: &*self.signal,
        };
        let r = replica.catch_up(signed, attempts).await;
        {
            let mut a = self.attempts.lock().expect("attempts lock");
            match r {
                Ok(Caught::Retry) => {
                    a.insert(account.clone(), (digest, attempts + 1));
                }
                Ok(Caught::Forked) => {
                    a.remove(&account);
                    self.forked
                        .lock()
                        .expect("forked lock")
                        .insert(account.clone());
                }
                _ => {
                    a.remove(&account);
                }
            }
        }
        if matches!(r, Ok(Caught::Deposed)) {
            self.host.reset(&account).await;
            let _ = self
                .local
                .control
                .delete(&self.tenant, &staged_path(&account), Expect::Any)
                .await;
        }
        r
    }

    /// The offer of `account`'s state this node holds, if any (see [`crate::handover`]).
    pub async fn staged(&self, account: &AccountId) -> Option<Offer> {
        let (bytes, _) = self
            .local
            .control
            .get(&self.tenant, &staged_path(account))
            .await
            .ok()??;
        Offer::decode(&bytes).ok()
    }

    /// The accounts whose state this node holds an offer of.
    pub async fn staged_accounts(&self) -> Vec<AccountId> {
        let mut out = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let Ok(page) = self
                .local
                .control
                .list(&self.tenant, STAGED, after.as_deref(), 1000)
                .await
            else {
                return out;
            };
            out.extend(
                page.iter()
                    .filter_map(|p| p.rsplit('/').next())
                    .filter_map(|a| AccountId::new(a).ok()),
            );
            if page.len() < 1000 {
                return out;
            }
            after = page.last().cloned();
        }
    }

    /// Pushes `offer` to every peer that counts and may lead its account. Returns how many took
    /// it or already held one as new.
    pub async fn hand_over(&self, offer: &Offer) -> usize {
        let (Some(link), Some(account)) = (self.link(), offer.account()) else {
            return 0;
        };
        let Some(resource) = account_resource(account.as_str()) else {
            return 0;
        };
        let limit = self.config.limit;
        let protocol = Protocol::new(HANDOVER_PROTOCOL).expect("constant");
        let bytes = offer.encode();
        let peers: Vec<PublicKey> = self
            .membership
            .counting_peers()
            .into_iter()
            .filter(|p| self.membership.node_may(p, &resource, &Capability::Lead))
            .collect();
        let sends = peers.into_iter().map(|peer| {
            let (link, protocol, bytes) = (link.clone(), protocol.clone(), bytes.clone());
            async move {
                let mut s = tokio::time::timeout(limit, link.open(&peer, &protocol))
                    .await
                    .ok()?
                    .ok()?;
                rowboat_group::wire::write_frame(&mut *s, &bytes, limit)
                    .await
                    .ok()?;
                let reply = rowboat_group::wire::read_frame(&mut *s, 16, limit)
                    .await
                    .ok()?;
                (reply.as_slice() == [1]).then_some(())
            }
        });
        futures::stream::iter(sends)
            .buffer_unordered(MAX_SERVED)
            .filter_map(|r| async move { r })
            .count()
            .await
    }

    async fn serve_offer(self: Arc<Self>, peer: PublicKey, mut stream: Box<dyn Duplex>) {
        let limit = self.config.limit;
        let Ok(bytes) =
            rowboat_group::wire::read_frame(&mut *stream, MAX_STATE + 128 * 1024, limit).await
        else {
            return;
        };
        let taken = match Offer::decode(&bytes) {
            Ok(offer) => self.receive_offer(&peer, offer).await.is_ok(),
            Err(_) => false,
        };
        let _ = rowboat_group::wire::write_frame(&mut *stream, &[u8::from(taken)], limit).await;
    }

    /// Takes an offer `peer` sent: refused unless `peer` counts and may lead the account, this
    /// node may lead it and does not, the head verifies as `peer`'s own, it is not below the
    /// offer or the head this node holds (S4), and this node's replica reached it. An offer equal
    /// to the one held counts as taken. Only then is it stored, sealed as it came, with the
    /// account record beside it.
    pub async fn receive_offer(&self, peer: &PublicKey, offer: Offer) -> Result<(), SyncError> {
        let signed = offer.signed(&self.tenant)?;
        let account = signed.head.account.clone();
        let resource = account_resource(account.as_str()).ok_or(SyncError::NotAuthorized)?;
        if !self.membership.counts(peer)
            || !self.membership.node_may(peer, &resource, &Capability::Lead)
            || !self.membership.may(&resource, &Capability::Lead)
        {
            return Err(SyncError::NotAuthorized);
        }
        if self.host.leads(&account) {
            return Err(SyncError::NotHere);
        }
        let signer = verify_remote(&self.membership, &signed, (self.now)())?;
        if &signer != peer {
            return Err(SyncError::NotAuthorized);
        }
        let local_head = self
            .local
            .log
            .signed_head(&self.tenant, &account)
            .await
            .ok();
        if !self.admitted(&signed, local_head.as_ref()).await {
            return Err(SyncError::Unverified);
        }
        let position = |h: &SignedHead| (h.head.fence, h.head.seq);
        if let Some(held) = self.staged(&account).await
            && let Ok(h) = held.signed(&self.tenant)
        {
            if h.head.digest() == signed.head.digest() && held == offer {
                return Ok(());
            }
            if position(&h) >= position(&signed) {
                return Err(SyncError::Unverified);
            }
        }
        let local = self
            .local
            .log
            .signed_head(&self.tenant, &account)
            .await
            .map_err(storage)?;
        if local.head.fence > signed.head.fence {
            return Err(SyncError::Unverified);
        }
        match self.follow(&signed).await? {
            Caught::Installed { .. } | Caught::Current => {}
            _ => return Err(SyncError::Unreachable),
        }
        self.local
            .control
            .put(
                &self.tenant,
                &staged_path(&account),
                Bytes::from(offer.encode()),
                Expect::Any,
            )
            .await
            .map_err(storage)?;
        if let Some(record) = &offer.record {
            self.local
                .control
                .put(
                    &self.tenant,
                    &format!("accounts/{account}"),
                    Bytes::from(record.clone()),
                    Expect::Any,
                )
                .await
                .map_err(storage)?;
        }
        info!(account = %account, seq = signed.head.seq.0, "took a handover offer");
        Ok(())
    }

    /// Pushes this node's head of `account`, which it leads, to every peer that counts and may
    /// read it. Returns how many acknowledged.
    pub async fn announce(&self, account: &AccountId) -> usize {
        let (Some(link), Some(entry)) = (self.link(), self.wire_head(account).await) else {
            return 0;
        };
        let limit = self.config.limit;
        let protocol = Protocol::new(HEAD_PROTOCOL).expect("constant");
        let peers: Vec<PublicKey> = self
            .membership
            .counting_peers()
            .into_iter()
            .filter(|p| self.may_read(p, account))
            .collect();
        let sends = peers.into_iter().map(|peer| {
            let (link, protocol, entry) = (link.clone(), protocol.clone(), entry.clone());
            async move {
                let mut s = tokio::time::timeout(limit, link.open(&peer, &protocol))
                    .await
                    .ok()?
                    .ok()?;
                crate::heads::send(
                    &mut *s,
                    &HeadMsg::Announce {
                        v: HEAD_VERSION,
                        entries: vec![entry],
                    },
                    limit,
                )
                .await
                .ok()?;
                matches!(crate::heads::recv(&mut *s, limit).await, Ok(HeadMsg::Ack)).then_some(())
            }
        });
        futures::stream::iter(sends)
            .buffer_unordered(MAX_SERVED)
            .filter_map(|r| async move { r })
            .count()
            .await
    }

    fn issue(
        &self,
        account: &AccountId,
        request: &RemoteRequest,
        key: &str,
        ttl: i64,
    ) -> Result<Vec<u8>, SyncError> {
        let resource = account_resource(account.as_str()).ok_or(SyncError::NotAuthorized)?;
        let class = request.class().ok_or(SyncError::NotAuthorized)?;
        let log = self.membership.log();
        let epoch = log
            .state()
            .resource(&resource)
            .map(|r| r.epoch())
            .filter(|e| *e > 0)
            .ok_or(SyncError::NotAuthorized)?;
        let keys = self.membership.resource_keys(&resource, epoch)?;
        let command = baton_command::Command::issue(
            &self.membership.keys().identity,
            &log,
            Request {
                resource: &resource,
                epoch,
                data_key: &keys.data,
                class,
                idempotency_key: key,
                payload: &request.encode(),
            },
            (self.now)(),
            ttl,
        )
        .map_err(|_| SyncError::Malformed)?;
        Ok(command.encode())
    }

    async fn enqueue(self: &Arc<Self>, entry: OutboxEntry) -> Result<(), SyncError> {
        if self.outbox.lock().expect("outbox lock").len() >= MAX_OUTBOX {
            return Err(SyncError::Busy);
        }
        self.local
            .control
            .put(
                &self.tenant,
                &format!("{OUTBOX}/{}", entry.queue),
                Bytes::from(rowboat_group::wire::encode(&entry)),
                Expect::Any,
            )
            .await
            .map_err(storage)?;
        self.outbox
            .lock()
            .expect("outbox lock")
            .insert(entry.queue.clone(), entry);
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            if let Some(me) = me.upgrade() {
                me.flush().await;
            }
        });
        Ok(())
    }

    /// Issues `body` for `account` to its owner and returns the Skein command id the owner will
    /// queue it under, which the journal's outcome events name. Fails with
    /// [`SyncError::NotAuthorized`] for a body no remote call makes or an account this node holds
    /// no keys of, [`SyncError::Busy`] when the outbox is full.
    pub async fn submit(
        self: &Arc<Self>,
        account: &AccountId,
        body: CommandBody,
    ) -> Result<CommandId, SyncError> {
        let key = CommandId::generate();
        let resource = account_resource(account.as_str()).ok_or(SyncError::NotAuthorized)?;
        let me = self.membership.node().to_bytes();
        let queue =
            derive_queue_id(&me, resource.as_str(), key.as_str()).ok_or(SyncError::Malformed)?;
        let blob = match &body {
            CommandBody::Send { blob, .. } => Some(*blob.as_bytes()),
            _ => None,
        };
        let request = RemoteRequest::Submit {
            command: Box::new(Command {
                id: queue.clone(),
                account: account.clone(),
                created_at: skein_core::Timestamp((self.now)().0),
                trace: None,
                body,
            }),
        };
        let command = self.issue(account, &request, key.as_str(), COMMAND_TTL_MS)?;
        self.enqueue(OutboxEntry {
            v: 1,
            account: account.to_string(),
            queue: queue.to_string(),
            command,
            blob,
            expires_at: (self.now)().0 + COMMAND_TTL_MS,
        })
        .await?;
        Ok(queue)
    }

    /// Asks the owner of `account` to cancel the send `command` issued here.
    pub async fn cancel(
        self: &Arc<Self>,
        account: &AccountId,
        command: &CommandId,
    ) -> Result<(), SyncError> {
        let key = CommandId::generate();
        let request = RemoteRequest::Cancel {
            command: command.clone(),
        };
        let bytes = self.issue(account, &request, key.as_str(), COMMAND_TTL_MS)?;
        self.enqueue(OutboxEntry {
            v: 1,
            account: account.to_string(),
            queue: key.to_string(),
            command: bytes,
            blob: None,
            expires_at: (self.now)().0 + COMMAND_TTL_MS,
        })
        .await
    }

    /// Asks the owner of `account` to sync it now.
    pub async fn sync_now(self: &Arc<Self>, account: &AccountId) -> Result<(), SyncError> {
        let key = CommandId::generate();
        let bytes = self.issue(account, &RemoteRequest::SyncNow, key.as_str(), SYNC_TTL_MS)?;
        self.enqueue(OutboxEntry {
            v: 1,
            account: account.to_string(),
            queue: key.to_string(),
            command: bytes,
            blob: None,
            expires_at: (self.now)().0 + SYNC_TTL_MS,
        })
        .await
    }

    /// Whether a command waiting in the outbox for `account` names `blob`.
    pub fn outbox_holds(&self, account: &AccountId, blob: &BlobHash) -> bool {
        self.outbox
            .lock()
            .expect("outbox lock")
            .values()
            .any(|e| e.account == account.as_str() && e.blob.as_ref() == Some(blob.as_bytes()))
    }

    /// How many commands wait in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.outbox.lock().expect("outbox lock").len()
    }

    /// Delivers every command waiting in the outbox once.
    pub async fn flush(&self) {
        let _guard = self.flushing.lock().await;
        let entries: Vec<OutboxEntry> = self
            .outbox
            .lock()
            .expect("outbox lock")
            .values()
            .cloned()
            .collect();
        for entry in entries {
            let delivery = self.deliver(&entry).await;
            let settled = match delivery {
                Delivery::Keep => continue,
                Delivery::Done => None,
                Delivery::Settled(s) => Some(s),
            };
            let _ = self
                .local
                .control
                .delete(
                    &self.tenant,
                    &format!("{OUTBOX}/{}", entry.queue),
                    Expect::Any,
                )
                .await;
            self.outbox
                .lock()
                .expect("outbox lock")
                .remove(&entry.queue);
            self.attempted
                .lock()
                .expect("attempted lock")
                .remove(&entry.queue);
            if let (Some(s), Ok(account)) = (settled, AccountId::new(entry.account.clone())) {
                self.host.settled(&account, &entry.queue, s);
            }
        }
    }

    async fn deliver(&self, entry: &OutboxEntry) -> Delivery {
        let now = (self.now)();
        if now.0 > entry.expires_at {
            return Delivery::Settled(Settled::Failed {
                reason: "expired".into(),
            });
        }
        let Ok(account) = AccountId::new(entry.account.clone()) else {
            return Delivery::Keep;
        };
        let Ok(command) = baton_command::Command::decode(&entry.command) else {
            return Delivery::Settled(Settled::Failed {
                reason: "malformed".into(),
            });
        };
        if self.host.leads(&account) {
            let sent_before = self
                .attempted
                .lock()
                .expect("attempted lock")
                .contains(&entry.queue);
            if sent_before && self.host.previous_owner_silent(&account) {
                return Delivery::Settled(Settled::Uncertain);
            }
            let reply = self.handle(&entry.command).await;
            return self.settle(&command, Some(reply));
        }
        let Some(link) = self.link() else {
            return Delivery::Keep;
        };
        let Some(owner) = self.peers.owner(&account) else {
            return Delivery::Keep;
        };
        let limit = self.config.limit;
        let protocol = Protocol::new(COMMAND_PROTOCOL).expect("constant");
        let exchange = async {
            let mut s = tokio::time::timeout(limit, link.open(&owner, &protocol))
                .await
                .ok()?
                .ok()?;
            let msg = CmdMsg::Command {
                v: COMMAND_VERSION,
                bytes: entry.command.clone(),
            };
            rowboat_group::wire::write_frame(&mut *s, &rowboat_group::wire::encode(&msg), limit)
                .await
                .ok()?;
            self.attempted
                .lock()
                .expect("attempted lock")
                .insert(entry.queue.clone());
            let bytes = rowboat_group::wire::read_frame(&mut *s, MAX_FRAME, limit)
                .await
                .ok()?;
            decode_msg(&bytes).ok()
        };
        let reply = exchange.await;
        self.settle(&command, reply)
    }

    fn settle(&self, command: &baton_command::Command, reply: Option<CmdMsg>) -> Delivery {
        match reply {
            Some(CmdMsg::Result { bytes }) => {
                let Ok(result) = CommandResult::decode(&bytes) else {
                    return Delivery::Keep;
                };
                let Ok(keys) = self
                    .membership
                    .resource_keys(command.resource(), command.epoch())
                else {
                    return Delivery::Keep;
                };
                let log = self.membership.log();
                match result.check(command, &log, &keys.data, (self.now)()) {
                    Ok(Outcome::Applied) => Delivery::Done,
                    Ok(Outcome::Failed { reason }) => Delivery::Settled(Settled::Failed {
                        reason: if reason_ok(&reason) {
                            reason
                        } else {
                            "other".into()
                        },
                    }),
                    Ok(Outcome::Conflict { .. }) => Delivery::Settled(Settled::Failed {
                        reason: "conflict".into(),
                    }),
                    Ok(Outcome::Uncertain) => Delivery::Settled(Settled::Uncertain),
                    Err(e) => {
                        warn!(error = %e, "a command result was refused");
                        Delivery::Keep
                    }
                }
            }
            Some(CmdMsg::Refused { reason }) => Delivery::Settled(Settled::Failed { reason }),
            _ => Delivery::Keep,
        }
    }

    async fn serve_command(self: Arc<Self>, _peer: PublicKey, mut stream: Box<dyn Duplex>) {
        let limit = self.config.limit;
        let Ok(bytes) = rowboat_group::wire::read_frame(&mut *stream, MAX_FRAME, limit).await
        else {
            return;
        };
        let reply = match decode_msg(&bytes) {
            Ok(CmdMsg::Command { bytes, .. }) => self.handle(&bytes).await,
            _ => CmdMsg::Refused {
                reason: "malformed".into(),
            },
        };
        let _ = rowboat_group::wire::write_frame(
            &mut *stream,
            &rowboat_group::wire::encode(&reply),
            limit,
        )
        .await;
    }

    /// What the owner answers a command: a signed result, a refusal, "not here" (this node does
    /// not lead the account) or "later" (its group log must catch up, or storage failed).
    pub(crate) async fn handle(&self, bytes: &[u8]) -> CmdMsg {
        let refused = |reason: &str| CmdMsg::Refused {
            reason: reason.to_owned(),
        };
        let command = match baton_command::Command::decode(bytes) {
            Ok(c) => c,
            Err(e) => return refused(refusal(&e)),
        };
        let resource = command.resource().clone();
        let Some(account) = account_of(&resource) else {
            return refused("wrong_group");
        };
        if !self.host.leads(&account) {
            return CmdMsg::NotHere;
        }
        let known = self
            .membership
            .with_log(|l| l.state().resource(&resource).map_or(0, |r| r.epoch()));
        if command.epoch() > known {
            self.host.group_behind(command.issuer());
            return CmdMsg::Later;
        }
        let Ok(keys) = self.membership.resource_keys(&resource, command.epoch()) else {
            return refused("sealed");
        };
        let log = self.membership.log();
        let now = (self.now)();
        let checked = match command.check(&log, &resource, &keys.data, now) {
            Ok(c) => c,
            Err(CommandError::CatchUp) => return CmdMsg::Later,
            Err(e) => return refused(refusal(&e)),
        };
        let outcome = match self.run(&account, &checked, now).await {
            Ok(o) => o,
            Err(()) => return CmdMsg::Later,
        };
        match CommandResult::sign(
            &self.membership.keys().identity,
            &checked,
            &keys.data,
            &outcome,
            now,
        ) {
            Ok(r) => CmdMsg::Result { bytes: r.encode() },
            Err(_) => CmdMsg::Later,
        }
    }

    async fn run(
        &self,
        account: &AccountId,
        checked: &baton_command::Checked,
        now: Timestamp,
    ) -> Result<Outcome, ()> {
        let Ok(request) = decode_request(&checked.payload) else {
            return Ok(failed("malformed"));
        };
        if request.class() != Some(checked.class.as_str()) {
            return Ok(failed("wrong_class"));
        }
        match request {
            RemoteRequest::SyncNow => {
                let _ = self
                    .signal
                    .publish(
                        &skein_core::coordination::group(&self.tenant),
                        &wake_topic(account),
                        Bytes::from_static(b"wake"),
                    )
                    .await;
                Ok(Outcome::Applied)
            }
            RemoteRequest::Cancel { command } => {
                if !self.issued_send(account, &checked.issuer, &command).await? {
                    return Ok(failed("not_queued"));
                }
                match cancel_command(&self.local, &self.tenant, account, &command).await {
                    Ok(()) => Ok(Outcome::Applied),
                    Err(SubmitError::AlreadyStarted) => Ok(failed("already_started")),
                    Err(SubmitError::NotQueued) => Ok(failed("not_queued")),
                    Err(_) => Err(()),
                }
            }
            RemoteRequest::Submit { command } => self.queue(account, checked, *command, now).await,
        }
    }

    async fn issued_send(
        &self,
        account: &AccountId,
        issuer: &PublicKey,
        command: &CommandId,
    ) -> Result<bool, ()> {
        let path = format!("{CMDKEYS}/{account}/{command}");
        let Some((bytes, _)) = self
            .local
            .control
            .get(&self.tenant, &path)
            .await
            .map_err(|_| ())?
        else {
            return Ok(false);
        };
        let ours = serde_json::from_slice::<CmdKey>(&bytes)
            .is_ok_and(|k| k.issuer == issuer.node_id().to_string() && k.state == CmdState::Queued);
        if !ours {
            return Ok(false);
        }
        let queued = self
            .local
            .commands
            .get(&self.tenant, account, command)
            .await
            .map_err(|_| ())?;
        Ok(queued.is_some_and(|c| matches!(c.body, CommandBody::Send { .. })))
    }

    fn enter(&self, path: &str) -> Option<Running> {
        let mut set = self.running.lock().expect("running lock");
        set.insert(path.to_owned()).then(|| Running {
            set: self.running.clone(),
            path: path.to_owned(),
        })
    }

    fn queuer(&self) -> Queuer {
        Queuer {
            tenant: self.tenant.clone(),
            local: self.local.clone(),
            signal: self.signal.clone(),
        }
    }

    async fn queue(
        &self,
        account: &AccountId,
        checked: &baton_command::Checked,
        command: Command,
        now: Timestamp,
    ) -> Result<Outcome, ()> {
        if &command.account != account {
            return Ok(failed("wrong_account"));
        }
        let expected = derive_queue_id(
            &checked.issuer.to_bytes(),
            checked.resource.as_str(),
            &checked.idempotency_key,
        );
        if expected.as_ref() != Some(&command.id) {
            return Ok(failed("wrong_id"));
        }
        if check_command(&command.body).is_err() {
            return Ok(failed("invalid"));
        }
        if let CommandBody::Send { envelope, .. } = &command.body {
            let own = self.host.about(account).await;
            if !own.is_some_and(|a| a.address.eq_ignore_ascii_case(&envelope.from)) {
                return Ok(failed("wrong_sender"));
            }
        }
        let issuer = checked.issuer.node_id().to_string();
        let path = format!("{CMDKEYS}/{account}/{}", command.id);
        let Some(running) = self.enter(&path) else {
            return Err(());
        };
        let q = self.queuer();
        let record = match self.local.control.get(&self.tenant, &path).await {
            Err(_) => return Err(()),
            Ok(None) => None,
            Ok(Some((bytes, _))) => {
                let Ok(rec) = serde_json::from_slice::<CmdKey>(&bytes) else {
                    return Ok(Outcome::Uncertain);
                };
                if rec.issuer != issuer {
                    return Ok(failed("conflict"));
                }
                match rec.state {
                    CmdState::Queued => return Ok(Outcome::Applied),
                    CmdState::Refused { reason } => return Ok(failed(&reason)),
                    CmdState::Claimed => {
                        let pending = self
                            .local
                            .commands
                            .get(&self.tenant, account, &command.id)
                            .await
                            .map_err(|_| ())?;
                        if pending.is_none()
                            && !matches!(command.body, CommandBody::SetFlags { .. })
                        {
                            return Ok(Outcome::Uncertain);
                        }
                    }
                    CmdState::Fetching => {}
                }
                Some(rec.state)
            }
        };
        let missing = match &command.body {
            CommandBody::Send { blob, .. } => !self
                .local
                .blobs
                .contains(&self.tenant, blob)
                .await
                .map_err(|_| ())?,
            _ => false,
        };
        let key = |state| CmdKey {
            issuer: issuer.clone(),
            state,
            at: now.0,
        };
        if missing {
            if record.is_none() {
                q.put(&path, &key(CmdState::Fetching), Expect::Absent)
                    .await
                    .map_err(|_| ())?;
            }
            let CommandBody::Send { blob, .. } = &command.body else {
                unreachable!("only sends carry a blob")
            };
            let (Some(fetcher), Some(resource)) =
                (self.peers.fetcher(), account_resource(account.as_str()))
            else {
                return Err(());
            };
            let mut peers = vec![checked.issuer];
            peers.extend(self.peers.readers(account));
            let blob = *blob;
            let fetches = self.fetches.clone();
            fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let claim = key(CmdState::Claimed);
            tokio::spawn(async move {
                let _running = running;
                let got = fetcher
                    .fetch(&resource, &ContentId(*blob.as_bytes()), &peers)
                    .await;
                if let Ok((bytes, _)) = got
                    && q.local.blobs.put(&q.tenant, bytes).await.is_ok()
                    && q.put(&path, &claim, Expect::Any).await.is_ok()
                {
                    let _ = q.submit(&path, claim, &command).await;
                }
                fetches.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
            return Err(());
        }
        let claim = key(CmdState::Claimed);
        match record {
            None => q.put(&path, &claim, Expect::Absent).await,
            Some(CmdState::Fetching) => q.put(&path, &claim, Expect::Any).await,
            Some(_) => Ok(()),
        }
        .map_err(|_| ())?;
        let outcome = q.submit(&path, claim, &command).await;
        drop(running);
        outcome
    }

    #[cfg(test)]
    pub(crate) fn fetching(&self) -> usize {
        self.fetches.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Deletes `cmdkey` records older than [`CMDKEY_TTL_MS`], looking at most at 10,000.
    /// Returns how many were deleted.
    pub async fn prune(&self) -> usize {
        let now = (self.now)().0;
        let Ok(paths) = self
            .local
            .control
            .list(&self.tenant, CMDKEYS, None, MAX_PRUNE)
            .await
        else {
            return 0;
        };
        let mut removed = 0;
        for path in paths {
            let Ok(Some((bytes, _))) = self.local.control.get(&self.tenant, &path).await else {
                continue;
            };
            let old = serde_json::from_slice::<CmdKey>(&bytes)
                .map_or(true, |k| now.saturating_sub(k.at) > CMDKEY_TTL_MS);
            if old
                && self
                    .local
                    .control
                    .delete(&self.tenant, &path, Expect::Any)
                    .await
                    .is_ok()
            {
                removed += 1;
            }
        }
        removed
    }

    /// Considers `entries` as if `peer` had announced them: every head is verified, admitted
    /// and followed as an announcement's would be. A recovery and test hook.
    pub async fn hear(
        &self,
        peer: PublicKey,
        entries: Vec<WireHead>,
    ) -> Vec<(AccountId, Result<Caught, SyncError>)> {
        self.consider(vec![(peer, entries)]).await
    }

    /// Drops this node's replica of `account` (journal and what was derived from it, and any
    /// staged offer) through [`Host::reset`], so it is followed again from the start: for a
    /// journal this node wrote that the group did not take. Does nothing while this node leads
    /// the account.
    pub async fn drop_replica(&self, account: &AccountId) {
        if self.host.leads(account) {
            return;
        }
        let _guard = self.catching.lock().await;
        self.host.reset(account).await;
        let _ = self
            .local
            .control
            .delete(&self.tenant, &staged_path(account), Expect::Any)
            .await;
    }

    /// Forgets that `account` forked, so it is followed again (after the person resolved it).
    pub async fn clear_fork(&self, account: &AccountId) -> Result<(), SyncError> {
        self.local
            .control
            .delete(&self.tenant, &fork_path(account), Expect::Any)
            .await
            .map_err(storage)?;
        self.forked.lock().expect("forked lock").remove(account);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
