//! Commands: requests a node sends to the leaseholder of a resource, and the results that come
//! back.
//!
//! A [`Command`] is signed by the issuing node and its payload is sealed under the resource's data
//! key of a named epoch, so only nodes that can read the resource can read it. It names the group
//! log head it was made against. [`Command::check`] is what a leaseholder runs before handing a
//! command to its worker: signature, group and head, expiry, the issuer still counting, the
//! issuer's capability for the command class at the leaseholder's current log, and the payload
//! opening. A [`CommandResult`] is signed by the leaseholder, sealed the same way, and checked by
//! the issuer ([`CommandResult::check`]): the signer must hold `Lead` on the resource.
//!
//! Deduplication by idempotency key belongs to the worker's durable queue (Skein's
//! `CommandQueue`), so delivery here is at least once; the claim-before-execute record and the
//! uncertain outcome belong there too. [`bus`] carries commands and results over the mesh.

pub mod bus;

use baton_core::{GroupId, ResourceId, Timestamp};
use baton_group::{Capability, GroupLog, HeadCheck};
use baton_identity::{Identity, PublicKey, Signature};
use baton_seal::{Context, Key};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The wire format version of commands and results.
pub const VERSION: u8 = 1;

/// The largest encoded command or result accepted, in bytes.
pub const MAX_ENCODED: usize = 64 * 1024;

/// The longest idempotency key, in bytes.
pub const MAX_IDEMPOTENCY_KEY: usize = 128;

/// The longest a command may stay valid, in milliseconds (one day).
pub const MAX_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// How far ahead of the checker's clock a command or result may be stamped, in milliseconds.
pub const MAX_SKEW_MS: i64 = 5 * 60 * 1000;

const COMMAND_CONTEXT: &str = "baton-command-v1";
const RESULT_CONTEXT: &str = "baton-command-result-v1";

/// Why a command or a result was refused. Carries no payload.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// Not a command or result, too large, non-canonical, or of an unknown version.
    #[error("malformed")]
    Malformed,
    /// The signature does not verify.
    #[error("bad signature")]
    BadSignature,
    /// Another group's, or another resource's than the checker expects.
    #[error("another group or resource")]
    WrongGroup,
    /// It names a group log head this node has not seen yet: catch up, then check again.
    #[error("the group log must catch up first")]
    CatchUp,
    /// It names a head that differs from this node's log at that position: the log forked.
    #[error("the group log forked")]
    Fork,
    /// Past its expiry, valid for longer than allowed, or stamped in the future.
    #[error("expired or out of its time window")]
    Expired,
    /// The issuer (or, for a result, the signer) is not allowed to.
    #[error("not authorized")]
    NotAuthorized,
    /// The payload does not open with the epoch's key, or was sealed for another command.
    #[error("payload cannot be opened")]
    Sealed,
    /// An argument outside the rules (class name, idempotency key, epoch, sizes).
    #[error("invalid: {0}")]
    Invalid(&'static str),
}

fn valid_class(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_IDEMPOTENCY_KEY
}

/// A command's unique id: 16 random bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommandId(pub [u8; 16]);

impl CommandId {
    fn generate() -> Self {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("the operating system provides randomness");
        Self(b)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CommandBody {
    v: u8,
    id: CommandId,
    group: GroupId,
    resource: ResourceId,
    epoch: u64,
    class: String,
    issuer: PublicKey,
    group_seq: u64,
    group_hash: [u8; 32],
    issued_at: Timestamp,
    expires_at: Timestamp,
    payload: Vec<u8>,
}

impl CommandBody {
    /// Everything the sealed payload is bound to: the whole body except the payload itself.
    fn binding(&self) -> [u8; 32] {
        let mut b = self.clone();
        b.payload.clear();
        *blake3::hash(&postcard::to_stdvec(&b).expect("a command serializes")).as_bytes()
    }
}

#[derive(Serialize, Deserialize)]
struct Inner {
    idempotency_key: String,
    payload: Vec<u8>,
}

/// A signed command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    body: CommandBody,
    signature: Signature,
}

/// What a leaseholder hands its worker once a command passed every check.
pub struct Checked {
    /// The command's id.
    pub id: CommandId,
    /// The resource.
    pub resource: ResourceId,
    /// The command class.
    pub class: String,
    /// The idempotency key. Deduplicate by `(issuer, resource, idempotency_key)`, never by the key
    /// alone, so one member cannot shadow another's command by reusing its key.
    pub idempotency_key: String,
    /// The issuing node.
    pub issuer: PublicKey,
    /// The epoch the payload was sealed under (results are sealed under it too).
    pub epoch: u64,
    /// The opened payload, wiped on drop.
    pub payload: Zeroizing<Vec<u8>>,
    group: GroupId,
}

impl std::fmt::Debug for Checked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checked")
            .field("id", &self.id)
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}

fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
    max: usize,
) -> Result<T, CommandError> {
    if bytes.len() > max {
        return Err(CommandError::Malformed);
    }
    let v: T = postcard::from_bytes(bytes).map_err(|_| CommandError::Malformed)?;
    if postcard::to_stdvec(&v).map_err(|_| CommandError::Malformed)? != bytes {
        return Err(CommandError::Malformed);
    }
    Ok(v)
}

/// What a command is about, given to [`Command::issue`].
pub struct Request<'a> {
    /// The resource.
    pub resource: &'a ResourceId,
    /// The epoch whose data key seals the payload (normally the current one).
    pub epoch: u64,
    /// That epoch's data key.
    pub data_key: &'a Key,
    /// The command class, 1–32 bytes of `[a-z0-9_-]`.
    pub class: &'a str,
    /// The idempotency key, 1–128 bytes; sealed with the payload, so carriers never see it.
    pub idempotency_key: &'a str,
    /// The payload.
    pub payload: &'a [u8],
}

impl Command {
    /// Issues a command from `identity` against the head of `log`, valid for `ttl_ms` (1 ms to
    /// [`MAX_TTL_MS`]) from `now`.
    pub fn issue(
        identity: &Identity,
        log: &GroupLog,
        req: Request<'_>,
        now: Timestamp,
        ttl_ms: i64,
    ) -> Result<Self, CommandError> {
        if !valid_class(req.class) {
            return Err(CommandError::Invalid(
                "a command class is 1-32 bytes of a-z, 0-9, '_' and '-'",
            ));
        }
        if !valid_key(req.idempotency_key) {
            return Err(CommandError::Invalid("an idempotency key is 1-128 bytes"));
        }
        if !(1..=MAX_TTL_MS).contains(&ttl_ms) {
            return Err(CommandError::Invalid(
                "a command is valid for 1 ms to one day",
            ));
        }
        let mut body = CommandBody {
            v: VERSION,
            id: CommandId::generate(),
            group: log.state().group().clone(),
            resource: req.resource.clone(),
            epoch: req.epoch,
            class: req.class.to_owned(),
            issuer: identity.public(),
            group_seq: log.head_seq(),
            group_hash: log.head_hash(),
            issued_at: now,
            expires_at: now.plus_ms(ttl_ms),
            payload: Vec::new(),
        };
        let inner = postcard::to_stdvec(&Inner {
            idempotency_key: req.idempotency_key.to_owned(),
            payload: req.payload.to_vec(),
        })
        .expect("an inner payload serializes");
        body.payload = baton_seal::seal(
            req.data_key,
            Context::new(COMMAND_CONTEXT, &body.binding()),
            &inner,
        )
        .map_err(|_| CommandError::Sealed)?;
        let bytes = postcard::to_stdvec(&body).expect("a command serializes");
        if bytes.len() + 64 > MAX_ENCODED {
            return Err(CommandError::Invalid(
                "the payload is too large for a command",
            ));
        }
        let signature = identity.sign(COMMAND_CONTEXT, &bytes);
        Ok(Self { body, signature })
    }

    /// The wire form.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("a command serializes")
    }

    /// Parses a command (size-limited, canonical) and checks its signature. Authorization is
    /// [`Command::check`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CommandError> {
        let c: Command = decode(bytes, MAX_ENCODED)?;
        if c.body.v != VERSION {
            return Err(CommandError::Malformed);
        }
        let body = postcard::to_stdvec(&c.body).expect("a command serializes");
        c.body
            .issuer
            .verify(COMMAND_CONTEXT, &body, &c.signature)
            .map_err(|_| CommandError::BadSignature)?;
        Ok(c)
    }

    /// The command's id.
    pub fn id(&self) -> CommandId {
        self.body.id
    }

    /// The resource it is for.
    pub fn resource(&self) -> &ResourceId {
        &self.body.resource
    }

    /// The epoch its payload is sealed under.
    pub fn epoch(&self) -> u64 {
        self.body.epoch
    }

    /// Everything a leaseholder of `resource` checks before handing a command to its worker:
    /// signature; same group and `resource`; a valid class; a time window of at most
    /// [`MAX_TTL_MS`], not stamped more than [`MAX_SKEW_MS`] ahead of `now` and not expired; that
    /// `log` has the head the command names (else [`CommandError::CatchUp`] or
    /// [`CommandError::Fork`]); an epoch the resource has; the issuer counting and holding
    /// `Command(class)` on the resource in `log`'s current state; and the payload opening with
    /// `data_key`, sealed for exactly this command (its whole body is bound to the seal).
    pub fn check(
        &self,
        log: &GroupLog,
        resource: &ResourceId,
        data_key: &Key,
        now: Timestamp,
    ) -> Result<Checked, CommandError> {
        let b = &self.body;
        let body = postcard::to_stdvec(b).expect("a command serializes");
        b.issuer
            .verify(COMMAND_CONTEXT, &body, &self.signature)
            .map_err(|_| CommandError::BadSignature)?;
        if b.group != *log.state().group() || &b.resource != resource {
            return Err(CommandError::WrongGroup);
        }
        if !valid_class(&b.class) {
            return Err(CommandError::Invalid(
                "a command class is 1-32 bytes of a-z, 0-9, '_' and '-'",
            ));
        }
        let window = b.expires_at.0.saturating_sub(b.issued_at.0);
        if !(0..=MAX_TTL_MS).contains(&window)
            || b.issued_at > now.plus_ms(MAX_SKEW_MS)
            || now > b.expires_at
        {
            return Err(CommandError::Expired);
        }
        match log.check_head(b.group_seq, b.group_hash) {
            HeadCheck::Same | HeadCheck::Behind => {}
            HeadCheck::Ahead => return Err(CommandError::CatchUp),
            HeadCheck::Fork => return Err(CommandError::Fork),
        }
        let state = log.state();
        let epochs = state.resource(resource).map_or(0, |r| r.epoch());
        if b.epoch == 0 || b.epoch > epochs {
            return Err(CommandError::Invalid("no such epoch"));
        }
        let at = state.last_at().max(now);
        if !state.may(
            &b.issuer,
            resource,
            &Capability::Command(b.class.clone()),
            at,
        ) {
            return Err(CommandError::NotAuthorized);
        }
        let plain = baton_seal::open(
            data_key,
            Context::new(COMMAND_CONTEXT, &b.binding()),
            &b.payload,
        )
        .map_err(|_| CommandError::Sealed)?;
        let inner: Inner = decode(&plain, MAX_ENCODED)?;
        if !valid_key(&inner.idempotency_key) {
            return Err(CommandError::Invalid("an idempotency key is 1-128 bytes"));
        }
        Ok(Checked {
            id: b.id,
            resource: b.resource.clone(),
            class: b.class.clone(),
            idempotency_key: inner.idempotency_key,
            issuer: b.issuer,
            epoch: b.epoch,
            payload: Zeroizing::new(inner.payload),
            group: b.group.clone(),
        })
    }
}

/// How a command ended, as the worker reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// Done.
    Applied,
    /// Refused or failed; nothing changed.
    Failed {
        /// Why, for the issuer.
        reason: String,
    },
    /// The resource changed meanwhile; the current state for the issuer to merge or retry.
    Conflict {
        /// The current state, as the application encodes it.
        state: Vec<u8>,
    },
    /// The request may or may not have taken effect (the leaseholder changed between claim and
    /// result); the application decides.
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ResultBody {
    v: u8,
    command: CommandId,
    group: GroupId,
    resource: ResourceId,
    epoch: u64,
    by: PublicKey,
    at: Timestamp,
    outcome: Vec<u8>,
}

impl ResultBody {
    fn binding(&self) -> [u8; 32] {
        let mut b = self.clone();
        b.outcome.clear();
        *blake3::hash(&postcard::to_stdvec(&b).expect("a result serializes")).as_bytes()
    }
}

/// A signed result of a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResult {
    body: ResultBody,
    signature: Signature,
}

impl CommandResult {
    /// The leaseholder `identity` reports `outcome` for `command`, sealed under `data_key` (the
    /// key of the command's epoch) and bound to the whole result body.
    pub fn sign(
        identity: &Identity,
        command: &Checked,
        data_key: &Key,
        outcome: &Outcome,
        at: Timestamp,
    ) -> Result<Self, CommandError> {
        let mut body = ResultBody {
            v: VERSION,
            command: command.id,
            group: command.group.clone(),
            resource: command.resource.clone(),
            epoch: command.epoch,
            by: identity.public(),
            at,
            outcome: Vec::new(),
        };
        let plain = postcard::to_stdvec(outcome).expect("an outcome serializes");
        body.outcome = baton_seal::seal(
            data_key,
            Context::new(RESULT_CONTEXT, &body.binding()),
            &plain,
        )
        .map_err(|_| CommandError::Sealed)?;
        let bytes = postcard::to_stdvec(&body).expect("a result serializes");
        if bytes.len() + 64 > MAX_ENCODED {
            return Err(CommandError::Invalid(
                "the outcome is too large for a result",
            ));
        }
        let signature = identity.sign(RESULT_CONTEXT, &bytes);
        Ok(Self { body, signature })
    }

    /// The wire form.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("a result serializes")
    }

    /// Parses a result (size-limited, canonical) and checks its signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, CommandError> {
        let r: CommandResult = decode(bytes, MAX_ENCODED)?;
        if r.body.v != VERSION {
            return Err(CommandError::Malformed);
        }
        let body = postcard::to_stdvec(&r.body).expect("a result serializes");
        r.body
            .by
            .verify(RESULT_CONTEXT, &body, &r.signature)
            .map_err(|_| CommandError::BadSignature)?;
        Ok(r)
    }

    /// The command this result answers.
    pub fn command(&self) -> CommandId {
        self.body.command
    }

    /// The issuer's check at its own time `now`: a result for `command` (id, resource, epoch),
    /// not stamped more than [`MAX_SKEW_MS`] ahead of `now`, signed by a node holding `Lead` on
    /// the resource in `log` (its certificate judged at the latest of `now`, the log's last entry
    /// and the result's stamp), opening with `data_key`. Any node holding `Lead` may sign a result;
    /// which of them actually ran the command is the application's knowledge (the lease fence).
    pub fn check(
        &self,
        command: &Command,
        log: &GroupLog,
        data_key: &Key,
        now: Timestamp,
    ) -> Result<Outcome, CommandError> {
        let b = &self.body;
        let body = postcard::to_stdvec(b).expect("a result serializes");
        b.by.verify(RESULT_CONTEXT, &body, &self.signature)
            .map_err(|_| CommandError::BadSignature)?;
        if b.command != command.id()
            || b.resource != command.body.resource
            || b.epoch != command.body.epoch
        {
            return Err(CommandError::Invalid("a result for another command"));
        }
        if b.group != *log.state().group() {
            return Err(CommandError::WrongGroup);
        }
        if b.at > now.plus_ms(MAX_SKEW_MS) {
            return Err(CommandError::Expired);
        }
        let at = log.state().last_at().max(now).max(b.at);
        if !log.state().may(&b.by, &b.resource, &Capability::Lead, at) {
            return Err(CommandError::NotAuthorized);
        }
        let plain = baton_seal::open(
            data_key,
            Context::new(RESULT_CONTEXT, &b.binding()),
            &b.outcome,
        )
        .map_err(|_| CommandError::Sealed)?;
        decode(&plain, MAX_ENCODED)
    }
}

#[cfg(test)]
mod tests;
