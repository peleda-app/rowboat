//! Commands from a node that reads an account to the node that leads it (GROUP.md, "Commands
//! from any node").
//!
//! The issuer wraps a Skein command in a [`RemoteRequest`], issues a signed, sealed Baton command
//! for the account's resource (`baton-command`) and keeps it in a durable outbox until a valid
//! result comes back or it expires. The Skein command's id is derived from the issuer, the
//! resource and the idempotency key ([`derive_queue_id`]), so both sides know it without being
//! told, two issuers never share one, and the owner's journal events about it settle the issuer's
//! overlay exactly as a local command's do. The owner checks the command against its group log
//! (`Command::check`), then its own rules (the class matches the request, Skein's checks, a send
//! from the account's own address), claims a `cmdkey` record once per queue id and only then
//! queues the command in Skein's `CommandQueue`; a second delivery is answered from that record.
//! Results are signed by the owner (`CommandResult`); a refusal before a command opens travels as
//! a plain reason over the authenticated link.

use serde::{Deserialize, Serialize};
use skein_core::{Command, CommandBody, CommandId};

use crate::SyncError;

/// The link protocol of commands.
pub const COMMAND_PROTOCOL: &str = "command";
/// The protocol's wire format version.
pub const COMMAND_VERSION: u8 = 1;
/// How long a command stays valid, in milliseconds.
pub const COMMAND_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// How long a sync request stays valid, in milliseconds.
pub const SYNC_TTL_MS: i64 = 60 * 60 * 1000;
/// How long the owner keeps a `cmdkey` record, in milliseconds: longer than any command's
/// validity plus skew, so an expired replay can never run again.
pub const CMDKEY_TTL_MS: i64 = 2 * 24 * 60 * 60 * 1000;
/// The most commands waiting in one node's outbox.
pub const MAX_OUTBOX: usize = 10_000;
pub(crate) const MAX_FRAME: usize = baton_command::MAX_ENCODED + 1024;
const QUEUE_CONTEXT: &str = "rowboat-command-id-v1";

/// What a remote command asks the owner to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteRequest {
    /// Queue a Skein command (flags, move, delete, send).
    Submit {
        /// The command; its id must be [`derive_queue_id`] of the issuer, the resource and the
        /// idempotency key.
        command: Box<Command>,
    },
    /// Cancel a send inside its undo window.
    Cancel {
        /// The queued command.
        command: CommandId,
    },
    /// Sync the account now.
    SyncNow,
}

impl RemoteRequest {
    /// The command class it travels under (`rowboat-api`'s reserved classes), `None` for a Skein
    /// command no remote call makes.
    pub fn class(&self) -> Option<&'static str> {
        use rowboat_api::CommandClass as C;
        Some(
            match self {
                Self::Submit { command } => match command.body {
                    CommandBody::SetFlags { .. } => C::Flags,
                    CommandBody::Move { .. } => C::Move,
                    CommandBody::Delete { to_trash: true, .. } => C::Delete,
                    CommandBody::Delete {
                        to_trash: false, ..
                    } => C::DeleteForever,
                    CommandBody::Send { .. } => C::Send,
                    _ => return None,
                },
                Self::Cancel { .. } => C::SendCancel,
                Self::SyncNow => C::Sync,
            }
            .as_str(),
        )
    }

    /// The JSON form.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a request serializes")
    }
}

/// Reads a request from an opened command payload: at most `baton_command::MAX_ENCODED` bytes of
/// JSON with every id checked on the way in. Never panics.
pub fn decode_request(bytes: &[u8]) -> Result<RemoteRequest, SyncError> {
    if bytes.len() > baton_command::MAX_ENCODED {
        return Err(SyncError::Malformed);
    }
    serde_json::from_slice(bytes).map_err(|_| SyncError::Malformed)
}

/// The Skein command id of a remote command: the timestamp of the idempotency key (a ULID) and 80
/// bits of a keyed hash of the issuer, the resource and the key. Equal inputs give equal ids;
/// another issuer or resource gives another id. `None` when the key is not a ULID.
pub fn derive_queue_id(issuer: &[u8; 32], resource: &str, key: &str) -> Option<CommandId> {
    let u = ulid::Ulid::from_string(key).ok()?;
    if u.to_string() != key {
        return None;
    }
    let mut h = blake3::Hasher::new_derive_key(QUEUE_CONTEXT);
    h.update(issuer);
    h.update(&(resource.len() as u64).to_le_bytes());
    h.update(resource.as_bytes());
    h.update(key.as_bytes());
    let digest = h.finalize();
    let mut random = [0u8; 16];
    random[6..].copy_from_slice(&digest.as_bytes()[..10]);
    let id = ulid::Ulid::from_parts(u.timestamp_ms(), u128::from_be_bytes(random));
    CommandId::new(id.to_string()).ok()
}

/// The messages of the command protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum CmdMsg {
    Command { v: u8, bytes: Vec<u8> },
    Result { bytes: Vec<u8> },
    Refused { reason: String },
    NotHere,
    Later,
}

pub(crate) fn decode_msg(bytes: &[u8]) -> Result<CmdMsg, SyncError> {
    if bytes.len() > MAX_FRAME {
        return Err(SyncError::Malformed);
    }
    let msg: CmdMsg = rowboat_group::wire::decode(bytes).map_err(|_| SyncError::Malformed)?;
    match &msg {
        CmdMsg::Command { v, .. } if *v != COMMAND_VERSION => Err(SyncError::Malformed),
        CmdMsg::Refused { reason } if !reason_ok(reason) => Err(SyncError::Malformed),
        _ => Ok(msg),
    }
}

/// Whether `reason` is one word of `[a-z0-9_]`, at most 32 bytes.
pub(crate) fn reason_ok(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 32
        && reason
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A durable outbox entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OutboxEntry {
    pub v: u8,
    pub account: String,
    pub queue: String,
    pub command: Vec<u8>,
    pub blob: Option<[u8; 32]>,
    pub expires_at: i64,
}

/// The owner's record of one remote command, at `rowboat/cmdkeys/{account}/{queue id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CmdKey {
    pub issuer: String,
    pub state: CmdState,
    pub at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CmdState {
    Fetching,
    Claimed,
    Queued,
    Refused { reason: String },
}

/// Runs the command protocol's decoders over `bytes`, for the fuzz target. Never panics.
pub fn fuzz_decoders(bytes: &[u8]) {
    let _ = decode_msg(bytes);
    let _ = decode_request(bytes);
    let _ = rowboat_group::wire::decode::<OutboxEntry>(bytes);
    let _ = serde_json::from_slice::<CmdKey>(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn queue_ids_are_per_issuer_and_resource() {
        let key = ulid::Ulid::from_parts(1_800_000_000_000, 77).to_string();
        let a = derive_queue_id(&[1; 32], "acct-a", &key).unwrap();
        assert_eq!(a, derive_queue_id(&[1; 32], "acct-a", &key).unwrap());
        assert_ne!(a, derive_queue_id(&[2; 32], "acct-a", &key).unwrap());
        assert_ne!(a, derive_queue_id(&[1; 32], "acct-b", &key).unwrap());
        let parsed = ulid::Ulid::from_string(a.as_str()).unwrap();
        assert_eq!(parsed.timestamp_ms(), 1_800_000_000_000);
        assert!(derive_queue_id(&[1; 32], "acct-a", "not-a-ulid").is_none());
        assert!(derive_queue_id(&[1; 32], "acct-a", &key.to_lowercase()).is_none());
    }

    #[test]
    fn requests_map_to_classes_and_refuse_strangers() {
        let sync = RemoteRequest::SyncNow;
        assert_eq!(sync.class(), Some("mail-sync"));
        assert_eq!(decode_request(&sync.encode()).unwrap(), sync);
        assert!(decode_request(br#"{"op":"cancel","command":"nope"}"#).is_err());
        assert!(
            decode_request(br#"{"op":"cancel","command":"01ARZ3NDEKTSV4RRFFQ69G5FAV","x":1}"#)
                .is_err()
        );
        assert!(decode_request(&vec![b' '; baton_command::MAX_ENCODED + 1]).is_err());
        let create = RemoteRequest::Submit {
            command: Box::new(Command {
                id: CommandId::generate(),
                account: skein_core::AccountId::new("a").unwrap(),
                created_at: skein_core::Timestamp(0),
                trace: None,
                body: CommandBody::CreateMailbox { path: "x".into() },
            }),
        };
        assert_eq!(create.class(), None, "not a remote call");
    }

    #[test]
    fn reasons_are_one_word() {
        assert!(reason_ok("not_authorized"));
        for bad in ["", "Bad", "two words", &"a".repeat(33), "a\n"] {
            assert!(!reason_ok(bad));
        }
        let bad = rowboat_group::wire::encode(&CmdMsg::Refused {
            reason: "x y".into(),
        });
        assert!(decode_msg(&bad).is_err());
    }

    proptest! {
        #[test]
        fn any_bytes_decode_without_panicking(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            fuzz_decoders(&bytes);
        }
    }
}
