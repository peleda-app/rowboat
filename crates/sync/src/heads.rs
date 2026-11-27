//! The head protocol (`head`, `peleda/head/1` on iroh): a node asks a peer for the signed heads
//! of the accounts it reads, and an owner pushes its new heads to the peers that read them. Heads
//! are hints: a receiver checks every one with [`crate::verify_remote`] and the replica's ordering
//! before it acts. A peer answers only for accounts the asking node may read in the group log, and
//! a refusal looks like an account it does not hold.

use std::time::Duration;

use baton_link::Duplex;
use serde::{Deserialize, Serialize};
use skein_core::{AccountId, FencingToken, Seq, TenantId};
use skein_storage::{JournalHead, SegmentHash, SegmentRef, SignedHead};

use crate::SyncError;

/// The link protocol of heads.
pub const HEAD_PROTOCOL: &str = "head";
/// The protocol's wire format version.
pub const HEAD_VERSION: u8 = 1;
/// The most accounts one request or answer names.
pub const MAX_ACCOUNTS: usize = 256;
/// The largest frame of the protocol, in bytes.
pub const MAX_FRAME: usize = 256 * 1024;
const MAX_TEXT: usize = 512;
const MAX_ATTESTATION: usize = crate::MAX_ATTESTATION;

/// What an owner tells readers about an account it leads, for display: the address, the display
/// name and the archive mailbox. Display only: it never raises a privilege (SEC-8), and a send is
/// checked against the owner's own record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct About {
    /// The account's address.
    pub address: String,
    /// Its display name.
    pub display_name: Option<String>,
    /// The mailbox archiving moves to, when the account has no archive role.
    pub archive: Option<String>,
}

impl About {
    fn check(&self) -> bool {
        let text = |t: &str| t.len() <= MAX_TEXT && !t.chars().any(char::is_control);
        !self.address.is_empty()
            && text(&self.address)
            && self.display_name.as_deref().is_none_or(text)
            && self.archive.as_deref().is_none_or(text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WireRef {
    start: u64,
    end: u64,
    fence: u64,
    hash: [u8; 32],
}

/// One account's head as it travels: the head fields, its attestation and, from the owner, what
/// it says about the account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireHead {
    account: String,
    seq: u64,
    fence: u64,
    tip: Option<WireRef>,
    attestation: Vec<u8>,
    about: Option<About>,
}

impl WireHead {
    /// The wire form of `signed`, with `about` when this node leads the account.
    pub fn new(signed: &SignedHead, about: Option<About>) -> Self {
        let h = &signed.head;
        Self {
            account: h.account.to_string(),
            seq: h.seq.0,
            fence: h.fence.0,
            tip: h.tip.as_ref().map(|t| WireRef {
                start: t.start.0,
                end: t.end.0,
                fence: t.fence.0,
                hash: t.hash.0,
            }),
            attestation: signed
                .attestation
                .as_ref()
                .map(|a| a.to_vec())
                .unwrap_or_default(),
            about,
        }
    }

    /// The account it is about, when the id is valid.
    pub fn account(&self) -> Option<AccountId> {
        AccountId::new(self.account.clone()).ok()
    }

    /// The signed head of `tenant` it carries, or [`SyncError::Malformed`] when an id, the
    /// attestation's size or what the owner says about the account breaks a rule. The head is
    /// still unverified.
    pub fn signed(&self, tenant: &TenantId) -> Result<(SignedHead, Option<About>), SyncError> {
        let account = self.account().ok_or(SyncError::Malformed)?;
        if self.attestation.len() > MAX_ATTESTATION
            || self.about.as_ref().is_some_and(|a| !a.check())
        {
            return Err(SyncError::Malformed);
        }
        let head = JournalHead {
            tenant: tenant.clone(),
            account,
            seq: Seq(self.seq),
            fence: FencingToken(self.fence),
            tip: self.tip.as_ref().map(|t| SegmentRef {
                start: Seq(t.start),
                end: Seq(t.end),
                fence: FencingToken(t.fence),
                hash: SegmentHash(t.hash),
            }),
        };
        head.check().map_err(|_| SyncError::Malformed)?;
        let attestation =
            (!self.attestation.is_empty()).then(|| bytes::Bytes::from(self.attestation.clone()));
        Ok((SignedHead { head, attestation }, self.about.clone()))
    }
}

/// The messages of the head protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum HeadMsg {
    Ask { v: u8, accounts: Vec<String> },
    Heads { entries: Vec<WireHead> },
    Announce { v: u8, entries: Vec<WireHead> },
    Ack,
}

impl HeadMsg {
    fn check(&self) -> Result<(), SyncError> {
        let ok = match self {
            Self::Ask { v, accounts } => *v == HEAD_VERSION && accounts.len() <= MAX_ACCOUNTS,
            Self::Heads { entries } => entries.len() <= MAX_ACCOUNTS,
            Self::Announce { v, entries } => *v == HEAD_VERSION && entries.len() <= MAX_ACCOUNTS,
            Self::Ack => true,
        };
        if ok {
            Ok(())
        } else {
            Err(SyncError::Malformed)
        }
    }
}

pub(crate) fn decode(bytes: &[u8]) -> Result<HeadMsg, SyncError> {
    if bytes.len() > MAX_FRAME {
        return Err(SyncError::Malformed);
    }
    let msg: HeadMsg = rowboat_group::wire::decode(bytes).map_err(|_| SyncError::Malformed)?;
    msg.check()?;
    Ok(msg)
}

pub(crate) async fn send(
    stream: &mut dyn Duplex,
    msg: &HeadMsg,
    limit: Duration,
) -> Result<(), SyncError> {
    rowboat_group::wire::write_frame(stream, &rowboat_group::wire::encode(msg), limit)
        .await
        .map_err(SyncError::from)
}

pub(crate) async fn recv(stream: &mut dyn Duplex, limit: Duration) -> Result<HeadMsg, SyncError> {
    let bytes = rowboat_group::wire::read_frame(stream, MAX_FRAME, limit)
        .await
        .map_err(SyncError::from)?;
    decode(&bytes)
}

/// Runs the head protocol's decoder over `bytes`, for the fuzz target. Never panics.
pub fn fuzz_decoder(bytes: &[u8]) {
    if let Ok(HeadMsg::Heads { entries } | HeadMsg::Announce { entries, .. }) = decode(bytes) {
        let tenant = TenantId::new("t").expect("constant");
        for e in entries {
            let _ = e.signed(&tenant);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn head() -> SignedHead {
        SignedHead {
            head: JournalHead {
                tenant: TenantId::new("t").unwrap(),
                account: AccountId::new("a").unwrap(),
                seq: Seq(4),
                fence: FencingToken(2),
                tip: Some(SegmentRef {
                    start: Seq(3),
                    end: Seq(4),
                    fence: FencingToken(2),
                    hash: SegmentHash([9; 32]),
                }),
            },
            attestation: Some(bytes::Bytes::from_static(b"sig")),
        }
    }

    #[test]
    fn heads_round_trip_and_bad_ones_are_refused() {
        let t = TenantId::new("t").unwrap();
        let about = About {
            address: "ada@example.com".into(),
            display_name: Some("Ada".into()),
            archive: None,
        };
        let w = WireHead::new(&head(), Some(about.clone()));
        assert_eq!(w.signed(&t).unwrap(), (head(), Some(about.clone())));
        let mut bad = w.clone();
        bad.seq = 5;
        assert!(bad.signed(&t).is_err(), "tip does not end at seq");
        let mut bad = w.clone();
        bad.account = "../x".into();
        assert!(bad.signed(&t).is_err());
        let mut bad = w.clone();
        bad.attestation = vec![0; MAX_ATTESTATION + 1];
        assert!(bad.signed(&t).is_err());
        let mut bad = w.clone();
        bad.about = Some(About {
            address: "a\r\nb".into(),
            ..about
        });
        assert!(bad.signed(&t).is_err());
    }

    #[test]
    fn limits_and_versions() {
        let many = HeadMsg::Ask {
            v: HEAD_VERSION,
            accounts: vec!["a".into(); MAX_ACCOUNTS + 1],
        };
        assert!(decode(&rowboat_group::wire::encode(&many)).is_err());
        let old = HeadMsg::Ask {
            v: 9,
            accounts: Vec::new(),
        };
        assert!(decode(&rowboat_group::wire::encode(&old)).is_err());
        let ok = HeadMsg::Announce {
            v: HEAD_VERSION,
            entries: vec![WireHead::new(&head(), None)],
        };
        let bytes = rowboat_group::wire::encode(&ok);
        assert_eq!(decode(&bytes).unwrap(), ok);
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode(&longer).is_err());
    }

    proptest! {
        #[test]
        fn any_bytes_decode_without_panicking(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            fuzz_decoder(&bytes);
        }
    }
}
