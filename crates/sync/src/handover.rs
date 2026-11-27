//! What moves with an account's lease (GROUP.md, "Credentials move with the lease", S3 and S4).
//!
//! The leaseholder's journal replicates on its own; the rest of what a new holder needs to
//! continue lives in the holder's control store: the account record, its credentials, the
//! engine's cursors, state and start markers, the push and status records, the node's own record
//! of the account (address, display name), the `cmdkey` records and the queued commands. [`export`] collects them into an [`Offer`]: the holder's signed head
//! in the clear, and the state sealed with the account resource's **secret key** (only nodes with
//! `lead` hold it) bound to that head, the account and the key epoch. Credentials travel as
//! plaintext inside the seal: at rest each node keeps them under its own keyring.
//!
//! A node with `lead` stores an offer sealed, without opening it (only the leaseholder decrypts,
//! [`import`] at the moment it takes the lease), after the checks of
//! [`crate::Replication`]: the sender counts and holds `lead`, the head verifies and is the
//! sender's, the fence and `seq` are not below what it holds (S4), and its own replica reached
//! the head, so a stored offer never claims events this node does not have.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::{AccountId, Command, TenantId};
use skein_keyring::{KeyScope, Keyring, open_account};
use skein_storage::{ACCOUNT_CONTROL_RECORDS, ACCOUNT_CONTROL_TREES, Expect, SignedHead, Storage};
use zeroize::Zeroizing;

use rowboat_group::{Membership, account_resource};

use crate::SyncError;
use crate::heads::WireHead;

/// The link protocol offers travel on.
pub const HANDOVER_PROTOCOL: &str = "handover";
/// The offer's wire format version.
pub const HANDOVER_VERSION: u8 = 1;
/// The largest sealed state an offer carries.
pub const MAX_STATE: usize = 32 * 1024 * 1024;
/// The most records (and, separately, queued commands) one state carries.
pub const MAX_RECORDS: usize = 100_000;
const PURPOSE: &str = "rowboat-handover-v1";
const CREDENTIALS: &str = "credentials";
const NODE_TREES: [&str; 1] = ["rowboat/cmdkeys"];
const NODE_RECORDS: [&str; 1] = ["rowboat/accounts"];
const PAGE: usize = 1000;

#[derive(Serialize, Deserialize)]
struct State {
    v: u8,
    records: Vec<(String, Vec<u8>)>,
    secrets: Vec<(String, Vec<u8>)>,
    commands: Vec<Vec<u8>>,
}

impl Drop for State {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (_, s) in &mut self.secrets {
            s.zeroize();
        }
    }
}

/// An account's state as a holder offers it to the nodes that may lead it next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// [`HANDOVER_VERSION`].
    pub v: u8,
    /// The holder's head the state goes with, attested by the holder.
    pub head: WireHead,
    /// The key epoch of the account resource the state is sealed under.
    pub epoch: u64,
    /// The account record (provider and settings, no secret), so a node holding the offer can
    /// compete for the lease before it opens anything.
    pub record: Option<Vec<u8>>,
    /// The sealed state.
    pub sealed: Vec<u8>,
}

impl Offer {
    /// The signed head of `tenant` it carries, or [`SyncError::Malformed`] when the offer breaks a
    /// rule (version, sizes, the head's own form). Nothing is verified yet.
    pub fn signed(&self, tenant: &TenantId) -> Result<SignedHead, SyncError> {
        if self.v != HANDOVER_VERSION
            || self.sealed.len() > MAX_STATE
            || self.record.as_ref().is_some_and(|r| r.len() > 64 * 1024)
        {
            return Err(SyncError::Malformed);
        }
        Ok(self.head.signed(tenant)?.0)
    }

    /// The account it is about.
    pub fn account(&self) -> Option<AccountId> {
        self.head.account()
    }

    /// The wire form.
    pub fn encode(&self) -> Vec<u8> {
        rowboat_group::wire::encode(self)
    }

    /// Parses the wire form; never panics.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        if bytes.len() > MAX_STATE + 128 * 1024 {
            return Err(SyncError::Malformed);
        }
        rowboat_group::wire::decode(bytes).map_err(|_| SyncError::Malformed)
    }
}

fn object(head: &SignedHead, epoch: u64) -> Vec<u8> {
    let mut out = head.head.digest().to_vec();
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(head.head.account.as_str().as_bytes());
    out
}

fn storage<E>(_: E) -> SyncError {
    SyncError::Storage
}

async fn paths(
    local: &Storage,
    tenant: &TenantId,
    prefix: &str,
    into: &mut Vec<String>,
) -> Result<(), SyncError> {
    let mut after: Option<String> = None;
    loop {
        let page = local
            .control
            .list(tenant, prefix, after.as_deref(), PAGE)
            .await
            .map_err(storage)?;
        if into.len() + page.len() > MAX_RECORDS {
            return Err(SyncError::Busy);
        }
        into.extend(page.iter().cloned());
        if page.len() < PAGE {
            return Ok(());
        }
        after = page.last().cloned();
    }
}

async fn account_paths(
    local: &Storage,
    tenant: &TenantId,
    account: &AccountId,
) -> Result<(Vec<String>, Vec<String>), SyncError> {
    let mut plain = Vec::new();
    for tree in ACCOUNT_CONTROL_TREES
        .iter()
        .filter(|t| **t != CREDENTIALS)
        .chain(NODE_TREES.iter())
    {
        paths(local, tenant, &format!("{tree}/{account}"), &mut plain).await?;
    }
    for record in ACCOUNT_CONTROL_RECORDS.iter().chain(NODE_RECORDS.iter()) {
        plain.push(format!("{record}/{account}"));
    }
    let mut secret = Vec::new();
    paths(
        local,
        tenant,
        &format!("{CREDENTIALS}/{account}"),
        &mut secret,
    )
    .await?;
    Ok((plain, secret))
}

/// Collects `account`'s state from `local` (secrets opened with `keyring`) and seals it under
/// the account resource's current secret key with the local head read last, so every cursor in
/// it is at or below that head. Fails with [`SyncError::NotAuthorized`] when this node holds no
/// secret key of the account, [`SyncError::NotHere`] when it holds no credentials of it (nothing
/// another node could lead with), [`SyncError::Busy`] when the state breaks a cap.
pub async fn export(
    tenant: &TenantId,
    local: &Storage,
    keyring: &dyn Keyring,
    membership: &Membership,
    account: &AccountId,
) -> Result<Offer, SyncError> {
    let resource = account_resource(account.as_str()).ok_or(SyncError::NotAuthorized)?;
    let epoch = membership
        .with_log(|l| l.state().resource(&resource).map(|r| r.epoch()))
        .filter(|e| *e > 0)
        .ok_or(SyncError::NotAuthorized)?;
    let keys = membership.resource_keys(&resource, epoch)?;
    let key = keys.secret.ok_or(SyncError::NotAuthorized)?;
    let (plain, secret) = account_paths(local, tenant, account).await?;
    let mut state = State {
        v: HANDOVER_VERSION,
        records: Vec::new(),
        secrets: Vec::new(),
        commands: Vec::new(),
    };
    for path in plain {
        if let Some((bytes, _)) = local.control.get(tenant, &path).await.map_err(storage)? {
            state.records.push((path, bytes.to_vec()));
        }
    }
    for path in secret {
        if let Some((sealed, _)) = local.control.get(tenant, &path).await.map_err(storage)? {
            let opened = open_account(keyring, tenant, account, &path, &sealed)
                .await
                .map_err(|_| SyncError::Unverified)?;
            state.secrets.push((path, opened.into_plaintext()));
        }
    }
    if state.secrets.is_empty() {
        return Err(SyncError::NotHere);
    }
    let mut after = None;
    loop {
        let page = local
            .commands
            .pending_after(tenant, account, after.as_ref(), PAGE)
            .await
            .map_err(storage)?;
        if state.commands.len() + page.len() > MAX_RECORDS {
            return Err(SyncError::Busy);
        }
        after = page.last().map(|c| c.id.clone());
        let full = page.len() == PAGE;
        for c in page {
            state
                .commands
                .push(serde_json::to_vec(&c).map_err(|_| SyncError::Malformed)?);
        }
        if !full {
            break;
        }
    }
    let head = local
        .log
        .signed_head(tenant, account)
        .await
        .map_err(storage)?;
    let plaintext = Zeroizing::new(rowboat_group::wire::encode(&state));
    let sealed = baton_seal::seal(
        &key,
        baton_seal::Context::new(PURPOSE, &object(&head, epoch)),
        &plaintext,
    )
    .map_err(|_| SyncError::Malformed)?;
    if sealed.len() > MAX_STATE {
        return Err(SyncError::Busy);
    }
    let record = state
        .records
        .iter()
        .find(|(p, _)| *p == format!("accounts/{account}"))
        .map(|(_, b)| b.clone());
    Ok(Offer {
        v: HANDOVER_VERSION,
        head: WireHead::new(&head, None),
        epoch,
        record,
        sealed,
    })
}

/// Opens `offer` and makes it `account`'s state in `local`: every record of the account in the
/// moved trees is replaced by the offer's, secrets are sealed again under `keyring`, and the
/// command queue becomes the offer's (commands the offer lacks are completed, its own queued
/// again; queueing is idempotent). Safe to repeat after a crash. Fails with
/// [`SyncError::Unverified`] when the seal does not open for this head, epoch and account (and
/// then nothing changed), [`SyncError::NotAuthorized`] when this node holds no secret key.
pub async fn import(
    tenant: &TenantId,
    local: &Storage,
    keyring: &dyn Keyring,
    membership: &Membership,
    offer: &Offer,
) -> Result<(), SyncError> {
    let head = offer.signed(tenant)?;
    let account = head.head.account.clone();
    let resource = account_resource(account.as_str()).ok_or(SyncError::NotAuthorized)?;
    let keys = membership.resource_keys(&resource, offer.epoch)?;
    let key = keys.secret.ok_or(SyncError::NotAuthorized)?;
    let plaintext = baton_seal::open(
        &key,
        baton_seal::Context::new(PURPOSE, &object(&head, offer.epoch)),
        &offer.sealed,
    )
    .map_err(|_| SyncError::Unverified)?;
    let state: State = rowboat_group::wire::decode(&plaintext).map_err(|_| SyncError::Malformed)?;
    if state.v != HANDOVER_VERSION
        || state.records.len() > MAX_RECORDS
        || state.secrets.len() > MAX_RECORDS
        || state.commands.len() > MAX_RECORDS
    {
        return Err(SyncError::Malformed);
    }
    let mut commands = Vec::with_capacity(state.commands.len());
    for c in &state.commands {
        let c: Command = serde_json::from_slice(c).map_err(|_| SyncError::Malformed)?;
        if c.account != account {
            return Err(SyncError::Malformed);
        }
        commands.push(c);
    }
    let owned = |path: &str| {
        ACCOUNT_CONTROL_TREES
            .iter()
            .chain(NODE_TREES.iter())
            .any(|t| path.starts_with(&format!("{t}/{account}/")))
            || ACCOUNT_CONTROL_RECORDS
                .iter()
                .chain(NODE_RECORDS.iter())
                .any(|r| path == format!("{r}/{account}"))
    };
    let secret_prefix = format!("{CREDENTIALS}/{account}/");
    let bad = state
        .records
        .iter()
        .any(|(p, _)| !owned(p) || p.starts_with(&secret_prefix))
        || state
            .secrets
            .iter()
            .any(|(p, _)| !p.starts_with(&secret_prefix));
    if bad {
        return Err(SyncError::Malformed);
    }
    let (plain, secret) = account_paths(local, tenant, &account).await?;
    for path in plain.iter().chain(secret.iter()) {
        let kept = state
            .records
            .iter()
            .chain(state.secrets.iter())
            .any(|(p, _)| p == path);
        if !kept {
            local
                .control
                .delete(tenant, path, Expect::Any)
                .await
                .map_err(storage)?;
        }
    }
    for (path, bytes) in &state.records {
        local
            .control
            .put(tenant, path, Bytes::from(bytes.clone()), Expect::Any)
            .await
            .map_err(storage)?;
    }
    let scope = KeyScope::account_of(tenant, &account);
    for (path, plain) in &state.secrets {
        let sealed = keyring
            .seal(&scope, path, plain)
            .await
            .map_err(|_| SyncError::Storage)?;
        local
            .control
            .put(tenant, path, Bytes::from(sealed), Expect::Any)
            .await
            .map_err(storage)?;
    }
    let mut after = None;
    loop {
        let page = local
            .commands
            .pending_after(tenant, &account, after.as_ref(), PAGE)
            .await
            .map_err(storage)?;
        after = page.last().map(|c| c.id.clone());
        let full = page.len() == PAGE;
        for c in page {
            if !commands.iter().any(|k| k.id == c.id) {
                local
                    .commands
                    .complete(tenant, &account, &c.id)
                    .await
                    .map_err(storage)?;
            }
        }
        if !full {
            break;
        }
    }
    for c in &commands {
        match local.commands.submit(tenant, c).await {
            Ok(_) => {}
            Err(skein_storage::StorageError::Conflict) => {
                local
                    .commands
                    .complete(tenant, &account, &c.id)
                    .await
                    .map_err(storage)?;
                local.commands.submit(tenant, c).await.map_err(storage)?;
            }
            Err(e) => return Err(storage(e)),
        }
    }
    Ok(())
}

/// Runs the offer decoder and its checks over `bytes`, for the fuzz target. Never panics.
pub fn fuzz_offer(bytes: &[u8]) {
    if let Ok(offer) = Offer::decode(bytes)
        && let Ok(tenant) = TenantId::new("gfuzz")
    {
        let _ = offer.signed(&tenant);
        let _ = offer.account();
    }
}
