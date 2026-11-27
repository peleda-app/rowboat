//! The group log exchange between nodes (`group`, `peleda/group/1` on iroh): both sides offer
//! their head, and the side that is ahead sends the entries the other lacks. The link admits only
//! nodes the log counts, so a revoked node or a node of another group never gets here; what a
//! peer sends is applied only through [`Membership::apply_remote`], so a shorter, older or forked
//! log never replaces this node's. Each entry is checked against a working copy of the log as it
//! arrives, and the stream is dropped at the first that fails; one exchange carries at most
//! [`MAX_BATCH`] entries and [`MAX_BATCH_BYTES`]. The receiving side acknowledges with `End` once it stored what
//! it took, so a sender's [`Synced::Sent`] means the peer has it.

use std::sync::Arc;
use std::time::Duration;

use baton_core::GroupId;
use baton_group::Entry;
use baton_identity::PublicKey;
use baton_link::{Duplex, Link, Protocol};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::invite::WireHint;
use crate::membership::{Membership, PeerRecord};
use crate::{MembershipError, wire};

/// The link protocol of the exchange.
pub const GROUP_PROTOCOL: &str = "group";
/// The exchange's wire format version.
pub const SYNC_VERSION: u8 = 1;
/// The most entries one exchange carries; a peer further behind catches up over several.
pub const MAX_BATCH: u64 = 4096;
/// The most entry bytes one exchange carries (at least one entry is always sent).
pub const MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;
const MAX_OFFER: usize = 8 * 1024;
const MAX_SERVED: usize = 8;

#[derive(Serialize, Deserialize)]
enum SyncMsg {
    Offer {
        v: u8,
        group: GroupId,
        genesis: [u8; 32],
        seq: u64,
        hash: [u8; 32],
        hint: WireHint,
    },
    Entry {
        bytes: Vec<u8>,
    },
    End,
}

/// What one exchange did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Synced {
    /// Both had the same head.
    Same,
    /// This node sent the peer this many entries.
    Sent(usize),
    /// This node took this many entries from the peer.
    Received(usize),
    /// The logs disagree at a position both have: one side was given a forged or forked log.
    Forked,
}

fn protocol() -> Protocol {
    Protocol::new(GROUP_PROTOCOL).expect("constant")
}

async fn send(
    stream: &mut dyn Duplex,
    msg: &SyncMsg,
    limit: Duration,
) -> Result<(), MembershipError> {
    wire::write_frame(stream, &wire::encode(msg), limit).await
}

async fn recv(
    stream: &mut dyn Duplex,
    max: usize,
    limit: Duration,
) -> Result<SyncMsg, MembershipError> {
    wire::decode(&wire::read_frame(stream, max, limit).await?)
}

async fn exchange(
    mut stream: Box<dyn Duplex>,
    m: &Membership,
    peer: &PublicKey,
    hint: &WireHint,
    limit: Duration,
) -> Result<Synced, MembershipError> {
    let (seq, hash) = m.head();
    let genesis = m.genesis_hash();
    send(
        &mut *stream,
        &SyncMsg::Offer {
            v: SYNC_VERSION,
            group: m.group().clone(),
            genesis,
            seq,
            hash,
            hint: hint.clone(),
        },
        limit,
    )
    .await?;
    let SyncMsg::Offer {
        v,
        group,
        genesis: their_genesis,
        seq: their_seq,
        hash: their_hash,
        hint: their_hint,
    } = recv(&mut *stream, MAX_OFFER, limit).await?
    else {
        return Err(MembershipError::Malformed);
    };
    if v != SYNC_VERSION {
        return Err(MembershipError::Malformed);
    }
    if &group != m.group() || their_genesis != genesis {
        return Ok(Synced::Forked);
    }
    if their_hint.check().is_ok() {
        m.remember_peer(
            peer,
            PeerRecord {
                hint: their_hint,
                label: None,
            },
        )
        .await?;
    }
    if their_seq == seq {
        return Ok(if their_hash == hash {
            Synced::Same
        } else {
            Synced::Forked
        });
    }
    if their_seq < seq {
        let entries: Option<Vec<Vec<u8>>> = m.with_log(|log| {
            let at = log.entries().get(their_seq as usize)?;
            if at.hash() != their_hash {
                return None;
            }
            let end = seq.min(their_seq + MAX_BATCH);
            let mut out = Vec::new();
            let mut total = 0;
            for e in &log.entries()[(their_seq + 1) as usize..=end as usize] {
                let bytes = e.encode();
                total += bytes.len();
                if total > MAX_BATCH_BYTES && !out.is_empty() {
                    break;
                }
                out.push(bytes);
            }
            Some(out)
        });
        let Some(entries) = entries else {
            return Ok(Synced::Forked);
        };
        let n = entries.len();
        for bytes in entries {
            send(&mut *stream, &SyncMsg::Entry { bytes }, limit).await?;
        }
        send(&mut *stream, &SyncMsg::End, limit).await?;
        return match recv(&mut *stream, MAX_OFFER, limit).await {
            Ok(SyncMsg::End) => Ok(Synced::Sent(n)),
            Ok(_) => Err(MembershipError::Malformed),
            Err(e) => Err(e),
        };
    }
    let mut entries = Vec::new();
    let mut staged = m.log();
    let mut total = 0;
    loop {
        match recv(&mut *stream, baton_group::MAX_ENTRY + 64, limit).await? {
            SyncMsg::Entry { bytes } => {
                total += bytes.len();
                if entries.len() as u64 >= MAX_BATCH || total > MAX_BATCH_BYTES {
                    return Err(MembershipError::Malformed);
                }
                let e = Entry::decode(&bytes).map_err(|_| MembershipError::Unverified)?;
                match stage(&mut staged, &e, m) {
                    Ok(()) => entries.push(e),
                    Err(MembershipError::Fork) => return Ok(Synced::Forked),
                    Err(err) => return Err(err),
                }
            }
            SyncMsg::End => break,
            SyncMsg::Offer { .. } => return Err(MembershipError::Malformed),
        }
    }
    match m.apply_remote(entries).await {
        Ok(n) => {
            send(&mut *stream, &SyncMsg::End, limit).await?;
            Ok(Synced::Received(n))
        }
        Err(MembershipError::Fork) => Ok(Synced::Forked),
        Err(e) => Err(e),
    }
}

pub(crate) fn stage(
    log: &mut baton_group::GroupLog,
    e: &Entry,
    m: &Membership,
) -> Result<(), MembershipError> {
    if e.group() != m.group() {
        return Err(MembershipError::Fork);
    }
    if e.seq() <= log.head_seq() {
        return if log.entries()[e.seq() as usize].hash() == e.hash() {
            Ok(())
        } else {
            Err(MembershipError::Fork)
        };
    }
    log.apply_fresh(e.clone(), m.now(), crate::MAX_SKEW_MS)
        .map_err(MembershipError::from)
}

/// Exchanges heads with `peer` over `link` and moves whichever side is behind. `hint` is where
/// this node's link is reached; the peer's hint is remembered.
pub async fn exchange_with(
    m: &Membership,
    link: &Arc<dyn Link>,
    peer: &PublicKey,
    hint: &WireHint,
    limit: Duration,
) -> Result<Synced, MembershipError> {
    if let Some(record) = m.peer(peer)
        && let Ok(h) = record.hint.to_peer()
    {
        let _ = link.add_hint(peer, h);
    }
    let stream = tokio::time::timeout(limit, link.open(peer, &protocol()))
        .await
        .map_err(|_| MembershipError::TimedOut)?
        .map_err(|_| MembershipError::Unreachable)?;
    exchange(stream, m, peer, hint, limit).await
}

/// Runs [`exchange_with`] with every node that counts, at most 8 at once; returns each peer's
/// result. Unreachable peers are reported, not retried.
pub async fn announce(
    m: &Arc<Membership>,
    link: &Arc<dyn Link>,
    hint: &WireHint,
    limit: Duration,
) -> Vec<(PublicKey, Result<Synced, MembershipError>)> {
    let peers = m.counting_peers();
    futures::stream::iter(peers)
        .map(|peer| async move {
            let r = exchange_with(m, link, &peer, hint, limit).await;
            (peer, r)
        })
        .buffer_unordered(MAX_SERVED)
        .collect()
        .await
}

/// Serves exchanges on `link` until the link closes or the task is aborted, at most 8 at once.
pub async fn serve(
    m: Arc<Membership>,
    link: Arc<dyn Link>,
    hint: WireHint,
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
            let hint = hint.clone();
            tokio::spawn(async move {
                let _ = exchange(inc.stream, &m, &inc.peer, &hint, limit).await;
                drop(slot);
            });
        }
    }))
}

/// Runs the decoder of exchange messages over `bytes`, for the fuzz target. Never panics.
pub fn fuzz_decoders(bytes: &[u8]) {
    let _ = wire::decode::<SyncMsg>(bytes);
}

#[cfg(test)]
mod tests;
