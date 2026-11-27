//! Pairing (GROUP.md, "Pairing"): a joiner dials the inviter's short-lived pairing endpoint
//! (protocol `pair`, `peleda/pair/1` on iroh), both run CPace over the invite secret and confirm
//! the key in both directions, and everything after travels sealed. Then the candidate (the node
//! that joins or is adopted) offers its keys, the certifier (the member device) answers with the
//! certificate's terms, both screens show the same six-digit fingerprint, the person confirms, and
//! the certifier appends `CertifyNode`, shares the resource epochs (a server gets only the
//! resources in [`Certifier::server_grants`]), hands a device the member key
//! and sends the whole log, which the candidate verifies from genesis.
//!
//! Who certifies depends on the invite: a [`InviteKind::Device`] invite is made by the certifier
//! (the joiner becomes a desktop or phone of the same member); a [`InviteKind::Server`] invite is
//! made by the candidate (a server asking the app to adopt it).
//!
//! Limits ([`Limits`]): an invite lives 10 minutes; a QR attempt that fails the key confirmation
//! kills the invite, a short code allows three failed attempts in total, and only a valid PAKE
//! message followed by a failed key confirmation counts as one; an attempt against an invite that
//! does not exist runs a decoy PAKE and looks exactly like a wrong code; at most two handshakes at
//! once, each message of the handshake within 10 seconds, and a failed handshake holds its slot one
//! second longer; every message before the key confirmation is at most 8 KiB; each step
//! before the person's confirmation has 60 seconds, the confirmation 2 minutes; a candidate
//! verifies the log entry by entry as it arrives and takes at most 100,000 entries and 64 MiB.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use baton_core::{GroupId, Timestamp};
use baton_group::{Entry, GroupLog, NodeCert};
use baton_identity::{Identity, Pake, PakeRole, PakeSession, PublicKey, Signature};
use baton_keys::{KemPublic, KemSecret, SealedBox, open_box, seal_box};
use baton_lease::NodeClass;
use baton_link::{Duplex, Incoming, Link, PinnedKeys, Protocol};
use futures::StreamExt;
use futures::stream::BoxStream;
use rowboat_endpoint::Endpoints;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::invite::{Invite, InviteKind, PairAddress, PairingCode, ShortCode, WireHint};
use crate::membership::{Membership, PeerRecord};
use crate::wire::{self, Sealed};
use crate::{DAY_MS, MembershipError, Now};

/// The link protocol of the pairing endpoint.
pub const PAIR_PROTOCOL: &str = "pair";
/// The pairing wire format version.
pub const PAIR_VERSION: u8 = 1;
/// The longest label a node may give, in characters.
pub const MAX_LABEL: usize = 64;

const MEMBER_BOX: &[u8] = b"rowboat-member-key-v1\0";

/// The limits of pairing; [`Limits::default`] is what GROUP.md specifies.
#[derive(Debug, Clone)]
pub struct Limits {
    /// How long an invite lives, in milliseconds.
    pub ttl_ms: i64,
    /// The time for each step before the person's confirmation.
    pub step: Duration,
    /// The time an unauthenticated joiner has for each handshake message (the hello and the key
    /// confirmation), which the joiner's software sends without asking anyone.
    pub handshake: Duration,
    /// How much longer a handshake that failed keeps its slot.
    pub fail_delay: Duration,
    /// The time the person has to confirm the fingerprint.
    pub confirm: Duration,
    /// Handshakes at once on one inviter.
    pub concurrent: usize,
    /// Invites pending at once on one inviter.
    pub max_pending: usize,
    /// Failed attempts a short code allows in total.
    pub short_attempts: u8,
    /// The largest message before the key confirmation, and of every small sealed message.
    pub max_small: usize,
    /// The largest sealed message (one log entry).
    pub max_frame: usize,
    /// The most log entries a candidate accepts.
    pub max_entries: usize,
    /// The most log bytes a candidate accepts.
    pub max_log_bytes: usize,
    /// The term of a server certificate, in milliseconds.
    pub server_term_ms: i64,
    /// The term of a desktop or phone certificate, in milliseconds.
    pub device_term_ms: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            ttl_ms: 10 * 60 * 1000,
            step: Duration::from_secs(60),
            handshake: Duration::from_secs(10),
            fail_delay: Duration::from_secs(1),
            confirm: Duration::from_secs(120),
            concurrent: 2,
            max_pending: 8,
            short_attempts: 3,
            max_small: 8 * 1024,
            max_frame: baton_group::MAX_ENTRY + 4096,
            max_entries: 100_000,
            max_log_bytes: 64 * 1024 * 1024,
            server_term_ms: 90 * DAY_MS,
            device_term_ms: 400 * DAY_MS,
        }
    }
}

impl Limits {
    /// The certificate term for `class`.
    pub fn term(&self, class: NodeClass) -> i64 {
        match class {
            NodeClass::Server | NodeClass::Blind => self.server_term_ms,
            NodeClass::Desktop | NodeClass::Phone => self.device_term_ms,
        }
    }
}

/// Which side of the certificate this node is on in a pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairRole {
    /// This node certifies the other.
    Certifier,
    /// This node is certified.
    Candidate,
}

/// What both screens show before the person confirms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCheck {
    /// The invite's public number.
    pub invite: u64,
    /// Which side this node is on.
    pub role: PairRole,
    /// The other node's key.
    pub peer: PublicKey,
    /// The candidate's class.
    pub class: NodeClass,
    /// The candidate's label (display only, never trusted; `None` on the candidate side).
    pub label: Option<String>,
    /// Six digits in two groups, `123 456`, the same on both screens only when nobody stands in
    /// between.
    pub fingerprint: String,
}

/// The person's answer to a [`PairingCheck`].
#[async_trait]
pub trait Confirm: Send + Sync {
    /// Whether the person confirmed that both screens show the same fingerprint. A certifier
    /// must ask; a candidate device may show the fingerprint and answer `true`. Pairing gives up
    /// after [`Limits::confirm`] and treats that as `false`.
    async fn confirm(&self, check: &PairingCheck) -> bool;
}

/// What a certifier brings to a pairing.
pub struct Certifier {
    /// The group the candidate enters.
    pub membership: Arc<Membership>,
    /// Asks the person.
    pub confirm: Arc<dyn Confirm>,
    /// Where this node's own link is reached.
    pub hint: WireHint,
    /// The resources an adopted server gets read and lead on (the accounts the person moves to
    /// it); a server holds nothing else. Ignored for devices.
    pub server_grants: Vec<baton_core::ResourceId>,
}

/// What a candidate brings to a pairing.
pub struct Candidate<'a> {
    /// The node's signing key.
    pub identity: &'a Identity,
    /// The node's KEM key.
    pub kem: &'a KemSecret,
    /// The node's class.
    pub class: NodeClass,
    /// A label for the certifier's list of nodes (display only).
    pub label: String,
    /// Where this node's own link is reached.
    pub hint: WireHint,
    /// For a server tenant already bound to a group: that group's genesis hash. Terms of any other
    /// group are refused.
    pub bound: Option<[u8; 32]>,
    /// Shows the fingerprint (and, on a server console, asks).
    pub confirm: Arc<dyn Confirm>,
}

/// The side this node plays.
pub enum Side<'a> {
    /// It certifies.
    Certifier(&'a Certifier),
    /// It is certified.
    Candidate(&'a Candidate<'a>),
}

/// A node this node certified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certified {
    /// Its key.
    pub node: PublicKey,
    /// Its class.
    pub class: NodeClass,
    /// Its label.
    pub label: String,
    /// Where it is reached.
    pub hint: WireHint,
}

/// The group this node was certified into.
pub struct Joined {
    /// The whole log, verified from genesis, listing this node.
    pub log: GroupLog,
    /// The member key, for a desktop or phone.
    pub member: Option<Identity>,
    /// The node that certified this one.
    pub certifier: PublicKey,
    /// Where the group's nodes are reached.
    pub peers: Vec<(PublicKey, PeerRecord)>,
}

impl std::fmt::Debug for Joined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Joined")
            .field("group", self.log.state().group())
            .field("certifier", &self.certifier)
            .finish_non_exhaustive()
    }
}

/// How a pairing ended for this node.
#[derive(Debug)]
pub enum Outcome {
    /// It certified a node.
    Certified(Box<Certified>),
    /// It was certified.
    Joined(Box<Joined>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum InviteRef {
    Qr(u64),
    Short(u16),
}

#[derive(Serialize, Deserialize)]
struct Hello {
    v: u8,
    invite: InviteRef,
    message: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Reply {
    message: [u8; 32],
    tag: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Confirmation {
    tag: [u8; 32],
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
enum Msg {
    Candidate {
        node: PublicKey,
        kem: KemPublic,
        class: NodeClass,
        label: String,
        hint: WireHint,
    },
    Terms {
        group: GroupId,
        genesis: [u8; 32],
        certifier: PublicKey,
        member: PublicKey,
        expires: Timestamp,
        hint: WireHint,
    },
    Proof {
        signature: Signature,
    },
    Welcome {
        entries: u32,
        member_box: Option<SealedBox>,
        peers: Vec<(PublicKey, WireHint)>,
    },
    Entry {
        bytes: Vec<u8>,
    },
    Done,
    Refuse,
}

type Reserved = (u64, InviteKind, Option<GroupId>, Zeroizing<Vec<u8>>);

struct Pending {
    kind: InviteKind,
    group: Option<GroupId>,
    secret: Zeroizing<[u8; 16]>,
    short: Option<(u16, Zeroizing<[u8; 5]>)>,
    expires: Timestamp,
    failures: u8,
    busy: bool,
}

/// An invite just issued: what to show.
#[derive(Debug)]
pub struct Issued {
    /// The invite for the QR code.
    pub invite: Invite,
    /// The short code (server invites only).
    pub short: Option<ShortCode>,
    /// Where a joiner with the short code dials.
    pub address: PairAddress,
}

/// The invites one node has issued and serves on its pairing endpoint.
///
/// Guarantees: every invite is used at most once (a key confirmation consumes it, whatever
/// happens after); an expired, cancelled, used-up or unknown invite never pairs, and an attempt
/// against one looks to the joiner exactly like a wrong code; failed attempts are counted only
/// after a valid PAKE message and a failed key confirmation; at most [`Limits::concurrent`]
/// handshakes at once, a stream waits at most [`Limits::handshake`] for a slot and is dropped
/// unanswered after that. Pending invites live in memory only.
pub struct Inviter {
    pending: Mutex<BTreeMap<u64, Pending>>,
    slots: Arc<Semaphore>,
    limits: Limits,
    now: Now,
}

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("the operating system's random source");
    out
}

fn channel_id(endpoint: &PublicKey, joiner: &PublicKey) -> Vec<u8> {
    let mut v = b"rowboat-pair-v1\0".to_vec();
    v.extend(endpoint.to_bytes());
    v.extend(joiner.to_bytes());
    v
}

fn session_id(invite: InviteRef, group: Option<&GroupId>) -> Vec<u8> {
    let mut v = wire::encode(&invite);
    if let Some(g) = group {
        v.extend(g.as_str().as_bytes());
    }
    v
}

/// The six-digit fingerprint of a pairing: a keyed hash, under a key from the PAKE session, of
/// both node keys and the group. Equal on both sides only when both ran the PAKE with each other.
fn fingerprint(
    key: &[u8; 32],
    candidate: &PublicKey,
    certifier: &PublicKey,
    group: &GroupId,
) -> String {
    let mut input = Vec::with_capacity(64 + group.as_str().len());
    input.extend(candidate.to_bytes());
    input.extend(certifier.to_bytes());
    input.extend(group.as_str().as_bytes());
    let hash = blake3::keyed_hash(key, &input);
    let n = u64::from_be_bytes(hash.as_bytes()[..8].try_into().expect("8 bytes")) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

fn member_box_aad(group: &GroupId, node: &PublicKey) -> Vec<u8> {
    let mut v = MEMBER_BOX.to_vec();
    v.extend(group.as_str().as_bytes());
    v.push(0);
    v.extend(node.to_bytes());
    v
}

fn valid_label(label: &str) -> bool {
    label.chars().count() <= MAX_LABEL && !label.chars().any(char::is_control)
}

struct Channel {
    stream: Box<dyn Duplex>,
    sealed: Sealed,
    fp_key: Zeroizing<[u8; 32]>,
    limits: Limits,
    invite: u64,
}

impl Channel {
    fn new(
        stream: Box<dyn Duplex>,
        session: &PakeSession,
        role: PakeRole,
        limits: &Limits,
        invite: u64,
    ) -> Self {
        let i2r = session.derive("rowboat-pair-i2r");
        let r2i = session.derive("rowboat-pair-r2i");
        let (tx, rx) = match role {
            PakeRole::Initiator => (*i2r, *r2i),
            PakeRole::Responder => (*r2i, *i2r),
        };
        Self {
            stream,
            sealed: Sealed::new(tx, rx),
            fp_key: session.derive("rowboat-pair-fingerprint-v1"),
            limits: limits.clone(),
            invite,
        }
    }

    async fn send(&mut self, msg: &Msg) -> Result<(), MembershipError> {
        let sealed = self.sealed.seal(&wire::encode(msg))?;
        wire::write_frame(&mut *self.stream, &sealed, self.limits.step)
            .await
            .map_err(|e| match e {
                MembershipError::Unreachable => MembershipError::Refused,
                e => e,
            })
    }

    async fn recv(&mut self, max: usize) -> Result<Msg, MembershipError> {
        let frame = wire::read_frame(
            &mut *self.stream,
            max + baton_seal::OVERHEAD,
            self.limits.step,
        )
        .await
        .map_err(|e| match e {
            MembershipError::Unreachable => MembershipError::Refused,
            e => e,
        })?;
        wire::decode(&self.sealed.open(&frame)?)
    }

    async fn refuse(&mut self, why: MembershipError) -> MembershipError {
        let _ = self.send(&Msg::Refuse).await;
        let _ = tokio::time::timeout(self.limits.step, self.stream.shutdown()).await;
        why
    }
}

async fn ask(limit: Duration, confirm: &Arc<dyn Confirm>, check: &PairingCheck) -> bool {
    tokio::time::timeout(limit, confirm.confirm(check))
        .await
        .unwrap_or(false)
}

impl Inviter {
    /// No pending invites.
    pub fn new(limits: Limits, now: Now) -> Self {
        Self {
            pending: Mutex::new(BTreeMap::new()),
            slots: Arc::new(Semaphore::new(limits.concurrent)),
            limits,
            now,
        }
    }

    /// The limits in force.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Issues an invite served by the pairing endpoint `endpoint` reachable at `hint`. A device
    /// invite names the group and the inviting node; a server invite names neither and also gets
    /// a short code. Fails with [`MembershipError::Busy`] when [`Limits::max_pending`] invites are
    /// pending.
    pub fn issue(
        &self,
        kind: InviteKind,
        group: Option<GroupId>,
        inviter: Option<PublicKey>,
        endpoint: PublicKey,
        hint: WireHint,
    ) -> Result<Issued, MembershipError> {
        let now = (self.now)();
        let mut pending = self.pending.lock().expect("invites lock");
        pending.retain(|_, p| p.expires >= now);
        if pending.len() >= self.limits.max_pending {
            return Err(MembershipError::Busy);
        }
        let (group, inviter) = match kind {
            InviteKind::Device => (
                Some(group.ok_or(MembershipError::Invalid)?),
                Some(inviter.ok_or(MembershipError::Invalid)?),
            ),
            InviteKind::Server => (None, None),
        };
        let id = loop {
            let id = u64::from_be_bytes(random());
            if !pending.contains_key(&id) {
                break id;
            }
        };
        let short = match kind {
            InviteKind::Device => None,
            InviteKind::Server => {
                let taken: Vec<u16> = pending
                    .values()
                    .filter_map(|p| p.short.as_ref().map(|s| s.0))
                    .collect();
                let sid = loop {
                    let s = u16::from_be_bytes(random()) & 0x3ff;
                    if !taken.contains(&s) {
                        break s;
                    }
                };
                Some(ShortCode::new(sid, random()))
            }
        };
        let secret: [u8; 16] = random();
        let expires = now.plus_ms(self.limits.ttl_ms);
        pending.insert(
            id,
            Pending {
                kind,
                group: group.clone(),
                secret: Zeroizing::new(secret),
                short: short
                    .as_ref()
                    .map(|s| (s.id(), Zeroizing::new(*s.secret()))),
                expires,
                failures: 0,
                busy: false,
            },
        );
        let invite = Invite::new(
            kind,
            group,
            inviter,
            id,
            secret,
            endpoint,
            hint.clone(),
            expires,
        );
        Ok(Issued {
            invite,
            short,
            address: PairAddress { endpoint, hint },
        })
    }

    /// Withdraws an invite. Unknown ids are ignored.
    pub fn cancel(&self, id: u64) {
        self.pending.lock().expect("invites lock").remove(&id);
    }

    /// Whether the invite is still pending (not used up, cancelled or expired).
    pub fn is_pending(&self, id: u64) -> bool {
        let now = (self.now)();
        self.pending
            .lock()
            .expect("invites lock")
            .get(&id)
            .is_some_and(|p| p.expires >= now)
    }

    /// How many invites are pending.
    pub fn pending(&self) -> usize {
        let now = (self.now)();
        self.pending
            .lock()
            .expect("invites lock")
            .values()
            .filter(|p| p.expires >= now)
            .count()
    }

    fn reserve(&self, r: InviteRef) -> Option<Reserved> {
        let now = (self.now)();
        let mut pending = self.pending.lock().expect("invites lock");
        pending.retain(|_, p| p.expires >= now);
        let (id, p) = match r {
            InviteRef::Qr(id) => (id, pending.get_mut(&id)?),
            InviteRef::Short(s) => pending
                .iter_mut()
                .find(|(_, p)| p.short.as_ref().is_some_and(|x| x.0 == s))
                .map(|(id, p)| (*id, p))?,
        };
        if p.busy {
            return None;
        }
        p.busy = true;
        let password = match r {
            InviteRef::Qr(_) => Zeroizing::new(p.secret.to_vec()),
            InviteRef::Short(_) => Zeroizing::new(p.short.as_ref()?.1.to_vec()),
        };
        Some((id, p.kind, p.group.clone(), password))
    }

    fn failed(&self, id: u64, r: InviteRef) {
        let mut pending = self.pending.lock().expect("invites lock");
        let Some(p) = pending.get_mut(&id) else {
            return;
        };
        p.failures = p.failures.saturating_add(1);
        p.busy = false;
        let dead = match r {
            InviteRef::Qr(_) => true,
            InviteRef::Short(_) => p.failures >= self.limits.short_attempts,
        };
        if dead {
            pending.remove(&id);
        }
    }

    fn release(&self, id: u64) {
        if let Some(p) = self.pending.lock().expect("invites lock").get_mut(&id) {
            p.busy = false;
        }
    }

    /// Serves one stream the pairing endpoint accepted from `joiner`. `endpoint` is the pairing
    /// endpoint's own key. The side must match the invite: a certifier for device invites, a
    /// candidate for server invites. Returns the invite and the outcome. A handshake that fails
    /// before the key confirmation keeps its slot [`Limits::fail_delay`] longer, so wrong codes
    /// and unknown ids are paced.
    pub async fn serve(
        &self,
        stream: Box<dyn Duplex>,
        joiner: PublicKey,
        endpoint: PublicKey,
        side: Side<'_>,
    ) -> Result<(u64, Outcome), MembershipError> {
        let Ok(Ok(_slot)) =
            tokio::time::timeout(self.limits.handshake, self.slots.clone().acquire_owned()).await
        else {
            return Err(MembershipError::Busy);
        };
        let (id, kind, group, mut channel) = match self.handshake(stream, joiner, endpoint).await {
            Ok(done) => done,
            Err(e) => {
                tokio::time::sleep(self.limits.fail_delay).await;
                return Err(e);
            }
        };
        let outcome = match (kind, side) {
            (InviteKind::Device, Side::Certifier(c)) => Outcome::Certified(Box::new(
                certify(&mut channel, c, InviteKind::Device).await?,
            )),
            (InviteKind::Server, Side::Candidate(c)) => {
                Outcome::Joined(Box::new(candidate(&mut channel, c, None, group).await?))
            }
            _ => return Err(channel.refuse(MembershipError::Invalid).await),
        };
        Ok((id, outcome))
    }

    async fn handshake(
        &self,
        mut stream: Box<dyn Duplex>,
        joiner: PublicKey,
        endpoint: PublicKey,
    ) -> Result<(u64, InviteKind, Option<GroupId>, Channel), MembershipError> {
        let hello: Hello = wire::decode(
            &wire::read_frame(&mut *stream, self.limits.max_small, self.limits.handshake).await?,
        )?;
        if hello.v != PAIR_VERSION {
            return Err(MembershipError::Malformed);
        }
        let reserved = self.reserve(hello.invite);
        let (password, group) = match &reserved {
            Some((_, _, group, password)) => (password.clone(), group.clone()),
            None => (Zeroizing::new(random::<16>().to_vec()), None),
        };
        let pake = Pake::start(
            PakeRole::Responder,
            &password,
            &channel_id(&endpoint, &joiner),
            &session_id(hello.invite, group.as_ref()),
            b"",
        );
        let reply_message = pake.message();
        let session = match pake.finish(&hello.message, b"") {
            Ok(s) => s,
            Err(_) => {
                if let Some((id, ..)) = &reserved {
                    self.release(*id);
                }
                return Err(MembershipError::Refused);
            }
        };
        let fail = |e: MembershipError| {
            if let Some((id, ..)) = &reserved {
                self.failed(*id, hello.invite);
            }
            e
        };
        let sent = wire::write_frame(
            &mut *stream,
            &wire::encode(&Reply {
                message: reply_message,
                tag: session.confirmation(),
            }),
            self.limits.handshake,
        )
        .await;
        if let Err(e) = sent {
            return Err(fail(e));
        }
        let confirmed = match wire::read_frame(
            &mut *stream,
            self.limits.max_small,
            self.limits.handshake,
        )
        .await
        {
            Ok(frame) => wire::decode::<Confirmation>(&frame)
                .ok()
                .is_some_and(|c| session.check_confirmation(&c.tag).is_ok()),
            Err(_) => false,
        };
        let Some((id, kind, group, _)) = reserved else {
            return Err(MembershipError::Refused);
        };
        if !confirmed {
            self.failed(id, hello.invite);
            return Err(MembershipError::Refused);
        }
        self.pending.lock().expect("invites lock").remove(&id);
        let channel = Channel::new(stream, &session, PakeRole::Responder, &self.limits, id);
        Ok((id, kind, group, channel))
    }
}

struct Anyone;

impl baton_link::Trust for Anyone {
    fn allows(&self, _: &PublicKey) -> bool {
        true
    }
}

/// A pairing endpoint: an ephemeral identity that accepts streams from anyone on
/// [`PAIR_PROTOCOL`] and nothing else. Close it when its invites are used up or expired.
pub struct PairingEndpoint {
    key: PublicKey,
    hint: WireHint,
    link: Arc<dyn Link>,
    incoming: tokio::sync::Mutex<BoxStream<'static, Incoming>>,
}

impl PairingEndpoint {
    /// Binds a new pairing endpoint through `endpoints`.
    pub async fn open(endpoints: &dyn Endpoints) -> Result<Self, MembershipError> {
        let identity = Identity::generate();
        let bound = endpoints
            .bind(&identity, Arc::new(Anyone))
            .await
            .map_err(|_| MembershipError::Unreachable)?;
        let incoming = bound
            .link
            .listen(&Protocol::new(PAIR_PROTOCOL).expect("constant"))
            .await
            .map_err(|_| MembershipError::Unreachable)?;
        Ok(Self {
            key: identity.public(),
            hint: WireHint::from_peer(&bound.hint),
            link: bound.link,
            incoming: tokio::sync::Mutex::new(incoming),
        })
    }

    /// The endpoint's key, for invites.
    pub fn key(&self) -> PublicKey {
        self.key
    }

    /// Where it listens, for invites.
    pub fn hint(&self) -> &WireHint {
        &self.hint
    }

    /// The next stream a joiner opened; `None` once the endpoint is closed. Callers take turns.
    pub async fn next(&self) -> Option<Incoming> {
        self.incoming.lock().await.next().await
    }

    /// Closes the endpoint; streams in progress are severed.
    pub async fn close(&self) {
        self.link.close().await;
    }
}

impl std::fmt::Debug for PairingEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PairingEndpoint({:?})", self.key)
    }
}

impl std::fmt::Debug for Inviter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Inviter({} pending)", self.pending())
    }
}

/// Joins with `code`: binds an ephemeral endpoint through `endpoints`, dials the pairing endpoint
/// and plays `side`, which must match the invite (a candidate for a device invite, a certifier for
/// a server invite). The ephemeral endpoint is closed before this returns.
pub async fn join(
    endpoints: &dyn Endpoints,
    code: &PairingCode,
    side: Side<'_>,
    limits: &Limits,
) -> Result<Outcome, MembershipError> {
    match (code.kind(), &side) {
        (InviteKind::Device, Side::Candidate(_)) | (InviteKind::Server, Side::Certifier(_)) => {}
        _ => return Err(MembershipError::Invalid),
    }
    let (endpoint, hint) = code.endpoint();
    let me = Identity::generate();
    let bound = endpoints
        .bind(&me, Arc::new(PinnedKeys::new([endpoint])))
        .await
        .map_err(|_| MembershipError::Unreachable)?;
    let link = bound.link;
    let result = async {
        link.add_hint(&endpoint, hint.to_peer()?)
            .map_err(|_| MembershipError::Malformed)?;
        let protocol = Protocol::new(PAIR_PROTOCOL).expect("constant");
        let stream = tokio::time::timeout(limits.step, link.open(&endpoint, &protocol))
            .await
            .map_err(|_| MembershipError::TimedOut)?
            .map_err(|_| MembershipError::Unreachable)?;
        run_joiner(stream, me.public(), code, side, limits).await
    }
    .await;
    link.close().await;
    result
}

async fn run_joiner(
    mut stream: Box<dyn Duplex>,
    me: PublicKey,
    code: &PairingCode,
    side: Side<'_>,
    limits: &Limits,
) -> Result<Outcome, MembershipError> {
    let (endpoint, _) = code.endpoint();
    let (invite, password, group, id): (InviteRef, Zeroizing<Vec<u8>>, Option<GroupId>, u64) =
        match code {
            PairingCode::Qr(i) => (
                InviteRef::Qr(i.id),
                Zeroizing::new(i.secret().to_vec()),
                i.group.clone(),
                i.id,
            ),
            PairingCode::Short { code, .. } => (
                InviteRef::Short(code.id()),
                Zeroizing::new(code.secret().to_vec()),
                None,
                u64::from(code.id()),
            ),
        };
    let pake = Pake::start(
        PakeRole::Initiator,
        &password,
        &channel_id(&endpoint, &me),
        &session_id(invite, group.as_ref()),
        b"",
    );
    wire::write_frame(
        &mut *stream,
        &wire::encode(&Hello {
            v: PAIR_VERSION,
            invite,
            message: pake.message(),
        }),
        limits.step,
    )
    .await?;
    let reply: Reply =
        wire::decode(&wire::read_frame(&mut *stream, limits.max_small, limits.step).await?)
            .map_err(|_| MembershipError::WrongCode)?;
    let session = pake
        .finish(&reply.message, b"")
        .map_err(|_| MembershipError::WrongCode)?;
    session
        .check_confirmation(&reply.tag)
        .map_err(|_| MembershipError::WrongCode)?;
    wire::write_frame(
        &mut *stream,
        &wire::encode(&Confirmation {
            tag: session.confirmation(),
        }),
        limits.step,
    )
    .await?;
    let mut channel = Channel::new(stream, &session, PakeRole::Initiator, limits, id);
    match side {
        Side::Certifier(c) => Ok(Outcome::Certified(Box::new(
            certify(&mut channel, c, InviteKind::Server).await?,
        ))),
        Side::Candidate(c) => {
            let expected = match code {
                PairingCode::Qr(i) => i.inviter,
                PairingCode::Short { .. } => None,
            };
            Ok(Outcome::Joined(Box::new(
                candidate(&mut channel, c, expected, group).await?,
            )))
        }
    }
}

async fn certify(
    ch: &mut Channel,
    c: &Certifier,
    kind: InviteKind,
) -> Result<Certified, MembershipError> {
    let m = &c.membership;
    let member = match m.member_key() {
        Ok(k) => k.public(),
        Err(e) => return Err(ch.refuse(e).await),
    };
    let Msg::Candidate {
        node,
        kem,
        class,
        label,
        hint,
    } = ch.recv(ch.limits.max_small).await?
    else {
        return Err(ch.refuse(MembershipError::Malformed).await);
    };
    let class_ok = match kind {
        InviteKind::Device => matches!(class, NodeClass::Desktop | NodeClass::Phone),
        InviteKind::Server => class == NodeClass::Server,
    };
    let known = m.with_log(|l| l.state().was_certified(&node));
    if !class_ok || !valid_label(&label) || hint.check().is_err() || known {
        return Err(ch.refuse(MembershipError::Invalid).await);
    }
    let expires = m.now().plus_ms(ch.limits.term(class));
    let group = m.group().clone();
    ch.send(&Msg::Terms {
        group: group.clone(),
        genesis: m.genesis_hash(),
        certifier: m.node(),
        member,
        expires,
        hint: c.hint.clone(),
    })
    .await?;
    let Msg::Proof { signature } = ch.recv(ch.limits.max_small).await? else {
        return Err(MembershipError::Refused);
    };
    let member_key = m.member_key()?;
    let cert = match NodeCert::assemble(member_key, node, kem.clone(), class, expires, signature) {
        Ok(cert) => cert,
        Err(_) => return Err(ch.refuse(MembershipError::Unverified).await),
    };
    let check = PairingCheck {
        invite: ch.invite,
        role: PairRole::Certifier,
        peer: node,
        class,
        label: Some(label.clone()),
        fingerprint: fingerprint(&ch.fp_key, &node, &m.node(), &group),
    };
    if !ask(ch.limits.confirm, &c.confirm, &check).await {
        return Err(ch.refuse(MembershipError::Rejected).await);
    }
    if let Err(e) = m.certify(cert).await {
        return Err(ch.refuse(e).await);
    }
    if class == NodeClass::Server
        && !c.server_grants.is_empty()
        && let Err(e) = m.grant_server(&node, &c.server_grants).await
    {
        return Err(ch.refuse(e).await);
    }
    m.remember_peer(
        &node,
        PeerRecord {
            hint: hint.clone(),
            label: Some(label.clone()),
        },
    )
    .await?;
    let member_box = match class {
        NodeClass::Server | NodeClass::Blind => None,
        NodeClass::Desktop | NodeClass::Phone => Some(
            seal_box(
                &kem,
                &member_box_aad(&group, &node),
                &member_key.secret_bytes()[..],
            )
            .map_err(|_| MembershipError::Invalid)?,
        ),
    };
    let entries: Vec<Vec<u8>> = m.with_log(|l| l.entries().iter().map(Entry::encode).collect());
    let peers = m
        .peers()
        .into_iter()
        .filter(|(k, _)| k != &node)
        .map(|(k, p)| (k, p.hint))
        .take(256)
        .collect();
    ch.send(&Msg::Welcome {
        entries: entries.len() as u32,
        member_box,
        peers,
    })
    .await?;
    for bytes in entries {
        ch.send(&Msg::Entry { bytes }).await?;
    }
    let _ = ch.recv(ch.limits.max_small).await;
    Ok(Certified {
        node,
        class,
        label,
        hint,
    })
}

async fn candidate(
    ch: &mut Channel,
    c: &Candidate<'_>,
    inviter: Option<PublicKey>,
    group: Option<GroupId>,
) -> Result<Joined, MembershipError> {
    let me = c.identity.public();
    ch.send(&Msg::Candidate {
        node: me,
        kem: c.kem.public(),
        class: c.class,
        label: c.label.clone(),
        hint: c.hint.clone(),
    })
    .await?;
    let Msg::Terms {
        group: terms_group,
        genesis,
        certifier,
        member,
        expires,
        hint,
    } = ch.recv(ch.limits.max_small).await?
    else {
        return Err(MembershipError::Refused);
    };
    let wrong = group.as_ref().is_some_and(|g| g != &terms_group)
        || inviter.is_some_and(|i| i != certifier)
        || c.bound.is_some_and(|b| b != genesis)
        || hint.check().is_err();
    if wrong {
        return Err(ch.refuse(MembershipError::Refused).await);
    }
    let check = PairingCheck {
        invite: ch.invite,
        role: PairRole::Candidate,
        peer: certifier,
        class: c.class,
        label: None,
        fingerprint: fingerprint(&ch.fp_key, &me, &certifier, &terms_group),
    };
    if !ask(ch.limits.confirm, &c.confirm, &check).await {
        return Err(ch.refuse(MembershipError::Rejected).await);
    }
    let signature = NodeCert::node_proof(c.identity, &c.kem.public(), c.class, &member, expires);
    ch.send(&Msg::Proof { signature }).await?;
    let Msg::Welcome {
        entries: count,
        member_box,
        peers,
    } = ch.recv(ch.limits.max_small * 64).await?
    else {
        return Err(MembershipError::Refused);
    };
    if count as usize > ch.limits.max_entries || count == 0 || peers.len() > 256 {
        return Err(MembershipError::Malformed);
    }
    let mut log: Option<GroupLog> = None;
    let mut total = 0usize;
    for _ in 0..count {
        let Msg::Entry { bytes } = ch.recv(ch.limits.max_frame).await? else {
            return Err(MembershipError::Malformed);
        };
        total += bytes.len();
        if total > ch.limits.max_log_bytes {
            return Err(MembershipError::Malformed);
        }
        let e = Entry::decode(&bytes).map_err(|_| MembershipError::Unverified)?;
        match &mut log {
            None => log = Some(GroupLog::verify(vec![e]).map_err(|_| MembershipError::Unverified)?),
            Some(l) => l.apply(e).map_err(|_| MembershipError::Unverified)?,
        }
    }
    let log = log.ok_or(MembershipError::Malformed)?;
    let state = log.state();
    let at = state.last_at();
    let certifier_ok = state
        .node(&certifier, at)
        .is_some_and(|cert| cert.member == member);
    let mine_ok = state.node(&me, at).is_some_and(|cert| {
        cert.member == member && cert.kem == c.kem.public() && cert.class == c.class
    });
    if state.group() != &terms_group || log.genesis_hash() != genesis || !certifier_ok || !mine_ok {
        return Err(MembershipError::Unverified);
    }
    let member_key = match (c.class, member_box) {
        (NodeClass::Desktop | NodeClass::Phone, Some(b)) => {
            let bytes = open_box(c.kem, &member_box_aad(&terms_group, &me), &b)
                .map_err(|_| MembershipError::Unverified)?;
            let secret: [u8; 32] = bytes[..]
                .try_into()
                .map_err(|_| MembershipError::Unverified)?;
            let key = Identity::from_secret_bytes(&secret);
            if key.public() != member {
                return Err(MembershipError::Unverified);
            }
            Some(key)
        }
        (NodeClass::Server | NodeClass::Blind, None) => None,
        _ => return Err(MembershipError::Unverified),
    };
    let _ = ch.send(&Msg::Done).await;
    let mut known = vec![(certifier, PeerRecord { hint, label: None })];
    for (k, h) in peers {
        if k != me && k != certifier && h.check().is_ok() {
            known.push((
                k,
                PeerRecord {
                    hint: h,
                    label: None,
                },
            ));
        }
    }
    Ok(Joined {
        log,
        member: member_key,
        certifier,
        peers: known,
    })
}

/// Runs every decoder of pairing messages over `bytes`, for the fuzz target. Never panics.
pub fn fuzz_decoders(bytes: &[u8]) {
    let _ = wire::decode::<Hello>(bytes);
    let _ = wire::decode::<Reply>(bytes);
    let _ = wire::decode::<Confirmation>(bytes);
    let _ = wire::decode::<Msg>(bytes);
    let mut sealed = Sealed::new([1; 32], [2; 32]);
    let _ = sealed.open(bytes);
}

#[cfg(test)]
mod tests;
