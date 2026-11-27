//! Revocation notices (GROUP.md, B4; `revoked`, `peleda/revoked/1` on iroh): a node that the
//! log revoked is refused on every other protocol, so it would never learn why. On this one
//! protocol, which [`Membership::trust`] opens to revoked nodes only (and to counting nodes, who
//! are told they are not revoked), it offers its head and gets the log entries from that head up
//! to and including the `RevokeNode` entry that names it. They are the same signed entries any
//! node could verify: the asker applies them only through [`Membership::apply_remote`] after each
//! one verified against a working copy of its own log, so nothing that does not chain from its
//! head and verify is ever taken. A notice carries at most [`crate::sync::MAX_BATCH`] entries and
//! [`crate::sync::MAX_BATCH_BYTES`]; an asker further behind asks again.

use std::sync::Arc;
use std::time::Duration;

use baton_core::GroupId;
use baton_group::{Entry, Op};
use baton_identity::PublicKey;
use baton_link::{Duplex, Link, Protocol};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::membership::Membership;
use crate::sync::{MAX_BATCH, MAX_BATCH_BYTES};
use crate::{MembershipError, wire};

/// The link protocol of revocation notices.
pub const NOTICE_PROTOCOL: &str = "revoked";
/// The notice's wire format version.
pub const NOTICE_VERSION: u8 = 1;
const MAX_ASK: usize = 1024;
const MAX_SERVED: usize = 4;

#[derive(Serialize, Deserialize)]
enum NoticeMsg {
    Ask {
        v: u8,
        group: GroupId,
        genesis: [u8; 32],
        seq: u64,
        hash: [u8; 32],
    },
    NotRevoked,
    Unknown,
    Entry {
        bytes: Vec<u8>,
    },
    End,
}

/// What asking for a notice did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Noticed {
    /// The peer does not consider this node revoked.
    NotRevoked,
    /// The peer's log does not contain this node's head (another group, a fork, or a peer
    /// behind): nothing was taken.
    Unknown,
    /// This node took this many entries; [`Membership::is_revoked`] says whether the revocation
    /// was among them (a notice longer than one batch takes several asks).
    Applied(usize),
}

fn protocol() -> Protocol {
    Protocol::new(NOTICE_PROTOCOL).expect("constant")
}

async fn send(
    stream: &mut dyn Duplex,
    msg: &NoticeMsg,
    limit: Duration,
) -> Result<(), MembershipError> {
    wire::write_frame(stream, &wire::encode(msg), limit).await
}

async fn recv(
    stream: &mut dyn Duplex,
    max: usize,
    limit: Duration,
) -> Result<NoticeMsg, MembershipError> {
    wire::decode(&wire::read_frame(stream, max, limit).await?)
}

/// Asks `peer` whether this node was revoked, offering this node's head, and applies the notice
/// it answers with. Fails with [`MembershipError::Unreachable`] when the peer cannot be reached
/// on the protocol, and with an error of verification when the entries it sends do not chain or
/// do not verify (then nothing changed).
pub async fn ask(
    m: &Membership,
    link: &Arc<dyn Link>,
    peer: &PublicKey,
    limit: Duration,
) -> Result<Noticed, MembershipError> {
    let mut stream = tokio::time::timeout(limit, link.open(peer, &protocol()))
        .await
        .map_err(|_| MembershipError::TimedOut)?
        .map_err(|_| MembershipError::Unreachable)?;
    let (seq, hash) = m.head();
    send(
        &mut *stream,
        &NoticeMsg::Ask {
            v: NOTICE_VERSION,
            group: m.group().clone(),
            genesis: m.genesis_hash(),
            seq,
            hash,
        },
        limit,
    )
    .await?;
    receive(&mut *stream, m, limit).await
}

pub(crate) async fn receive(
    stream: &mut dyn Duplex,
    m: &Membership,
    limit: Duration,
) -> Result<Noticed, MembershipError> {
    let mut entries = Vec::new();
    let mut staged = m.log();
    let mut total = 0;
    loop {
        match recv(stream, baton_group::MAX_ENTRY + 64, limit).await? {
            NoticeMsg::NotRevoked if entries.is_empty() => return Ok(Noticed::NotRevoked),
            NoticeMsg::Unknown if entries.is_empty() => return Ok(Noticed::Unknown),
            NoticeMsg::Entry { bytes } => {
                total += bytes.len();
                if entries.len() as u64 >= MAX_BATCH || total > MAX_BATCH_BYTES {
                    return Err(MembershipError::Malformed);
                }
                let e = Entry::decode(&bytes).map_err(|_| MembershipError::Unverified)?;
                crate::sync::stage(&mut staged, &e, m)?;
                entries.push(e);
            }
            NoticeMsg::End => break,
            _ => return Err(MembershipError::Malformed),
        }
    }
    let n = m.apply_remote(entries).await?;
    Ok(Noticed::Applied(n))
}

enum Plan {
    Reply(NoticeMsg),
    Send(Vec<Vec<u8>>),
}

fn plan(m: &Membership, peer: &PublicKey, seq: u64, hash: [u8; 32]) -> Plan {
    if m.counts(peer) || !m.is_revoked_node(peer) {
        return Plan::Reply(NoticeMsg::NotRevoked);
    }
    let known = m.with_log(|log| {
        log.entries()
            .get(seq as usize)
            .is_some_and(|at| at.hash() == hash)
    });
    if !known {
        return Plan::Reply(NoticeMsg::Unknown);
    }
    Plan::Send(entries_for(m, peer, seq))
}

fn entries_for(m: &Membership, peer: &PublicKey, seq: u64) -> Vec<Vec<u8>> {
    m.with_log(|log| {
        let revoked_at = log
            .entries()
            .iter()
            .position(|e| matches!(e.op(), Op::RevokeNode { node } if node == peer))
            .unwrap_or(0) as u64;
        let end = revoked_at.min(seq + MAX_BATCH);
        let mut out = Vec::new();
        if end <= seq {
            return out;
        }
        let mut total = 0;
        for e in &log.entries()[(seq + 1) as usize..=end as usize] {
            let bytes = e.encode();
            total += bytes.len();
            if total > MAX_BATCH_BYTES && !out.is_empty() {
                break;
            }
            out.push(bytes);
        }
        out
    })
}

async fn answer(
    mut stream: Box<dyn Duplex>,
    m: &Membership,
    peer: &PublicKey,
    limit: Duration,
) -> Result<(), MembershipError> {
    let NoticeMsg::Ask {
        v,
        group,
        genesis,
        seq,
        hash,
    } = recv(&mut *stream, MAX_ASK, limit).await?
    else {
        return Err(MembershipError::Malformed);
    };
    if v != NOTICE_VERSION {
        return Err(MembershipError::Malformed);
    }
    if &group != m.group() || genesis != m.genesis_hash() {
        return send(&mut *stream, &NoticeMsg::Unknown, limit).await;
    }
    match plan(m, peer, seq, hash) {
        Plan::Reply(msg) => send(&mut *stream, &msg, limit).await,
        Plan::Send(entries) => {
            for bytes in entries {
                send(&mut *stream, &NoticeMsg::Entry { bytes }, limit).await?;
            }
            send(&mut *stream, &NoticeMsg::End, limit).await
        }
    }
}

/// Serves revocation notices on `link` until the link closes or the task is aborted, at most 4
/// at once.
pub async fn serve(
    m: Arc<Membership>,
    link: Arc<dyn Link>,
    limit: Duration,
) -> Result<JoinHandle<()>, MembershipError> {
    let mut incoming = link
        .listen(&protocol())
        .await
        .map_err(|_| MembershipError::Unreachable)?;
    let slots = Arc::new(Semaphore::new(MAX_SERVED));
    Ok(tokio::spawn(async move {
        while let Some(inc) = incoming.next().await {
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let m = m.clone();
            tokio::spawn(async move {
                let _ = answer(inc.stream, &m, &inc.peer, limit).await;
                drop(slot);
            });
        }
    }))
}

/// Runs the decoder of notice messages over `bytes`, for the fuzz target. Never panics.
pub fn fuzz_decoders(bytes: &[u8]) {
    let _ = wire::decode::<NoticeMsg>(bytes);
}

#[cfg(test)]
mod tests;
