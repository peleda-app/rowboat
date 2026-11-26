//! [`Wake`] over any [`Mailbox`]: every node has a wake box; a wake is a `put` of the sealed
//! payload into the target's box with a per-box writer key, and `listen` long-polls the node's
//! own box and acknowledges what it took.
//!
//! The target is the wake box's 32-byte id, which is bound to the box's reader key
//! ([`BoxId::of_reader`]), so nobody else can create the box, also after it expired. The reader
//! key is derived from the node's seed and a 32-byte slot; a node whose box is lost recreates it
//! under the same slot, or under a fresh slot (and so a fresh target) if it wants a new one. A
//! sender's writer key for a target is derived from its seed and that box
//! ([`MailboxWake::writer_key`]); the target node lists the writer keys of the nodes allowed to
//! wake it in its box's policy (the group log records which node owns which key), so a stranger's
//! wake is refused by the mailbox.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use baton_identity::PublicKey;
use baton_mailbox::{Admission, BoxId, BoxKey, BoxPolicy, BoxRole, Mailbox, MailboxError, Message};
use baton_wake::{MAX_WAKE, Wake, WakeError, WakeTarget, Woken};
use bytes::Bytes;
use zeroize::Zeroizing;

/// Wakes kept in a wake box at most.
pub const WAKE_BOX_MESSAGES: u32 = 64;

/// How long a wake is kept: one day.
pub const WAKE_TTL_MS: u64 = 24 * 3600 * 1000;

#[derive(Default)]
struct Listening {
    pending: VecDeque<Message>,
}

/// A [`Wake`] channel over a [`Mailbox`].
pub struct MailboxWake {
    mailbox: Arc<dyn Mailbox>,
    seed: Zeroizing<[u8; 32]>,
    own: BoxId,
    reader: BoxKey,
    listening: tokio::sync::Mutex<Listening>,
}

impl MailboxWake {
    /// A channel with keys derived from `seed` (32 secret bytes the node keeps in its
    /// `SecretStore`); its wake box's reader key comes from `seed` and `slot` (32 bytes the node
    /// keeps, not secret), and the box id from that key.
    pub fn new(mailbox: Arc<dyn Mailbox>, seed: &[u8; 32], slot: &[u8; 32]) -> Self {
        let reader = BoxKey::derive(seed, &BoxId(*slot), BoxRole::Reader);
        Self {
            own: BoxId::of_reader(&reader.public()),
            reader,
            mailbox,
            seed: Zeroizing::new(*seed),
            listening: tokio::sync::Mutex::new(Listening::default()),
        }
    }

    /// The target naming wake box `id`.
    pub fn target_of(id: &BoxId) -> WakeTarget {
        WakeTarget::new(Bytes::copy_from_slice(id.as_bytes())).expect("32 bytes fit a target")
    }

    fn box_of(target: &WakeTarget) -> Result<BoxId, WakeError> {
        <[u8; 32]>::try_from(target.as_bytes())
            .map(BoxId)
            .map_err(|_| WakeError::InvalidTarget)
    }

    /// The key this node writes to `target`'s wake box with: the target lists it among its
    /// writers. `None` for a target that is not a wake box id.
    pub fn writer_key(&self, target: &WakeTarget) -> Option<PublicKey> {
        Self::box_of(target)
            .ok()
            .map(|id| BoxKey::derive(&self.seed, &id, BoxRole::Writer).public())
    }

    /// Creates this node's wake box, accepting wakes from `writers` (their
    /// [`MailboxWake::writer_key`] for this node's target).
    pub async fn create_own(
        &self,
        writers: Vec<PublicKey>,
        admission: &Admission,
    ) -> Result<(), MailboxError> {
        let policy = self.policy(writers);
        self.mailbox
            .create(&self.own, &policy, &self.reader, admission)
            .await
    }

    /// Replaces who may wake this node.
    pub async fn set_wakers(&self, writers: &[PublicKey]) -> Result<(), MailboxError> {
        self.mailbox
            .set_writers(&self.own, &self.reader, writers)
            .await
    }

    fn policy(&self, writers: Vec<PublicKey>) -> BoxPolicy {
        BoxPolicy {
            reader: self.reader.public(),
            writers,
            max_bytes: u64::from(WAKE_BOX_MESSAGES) * MAX_WAKE as u64,
            max_messages: WAKE_BOX_MESSAGES,
            ttl_ms: WAKE_TTL_MS,
        }
    }
}

fn wake_err(e: MailboxError) -> WakeError {
    match e {
        MailboxError::TooLarge => WakeError::TooLarge,
        MailboxError::Denied | MailboxError::UnknownBox => WakeError::Denied,
        other => WakeError::unavailable(other),
    }
}

#[async_trait]
impl Wake for MailboxWake {
    fn target(&self) -> WakeTarget {
        Self::target_of(&self.own)
    }

    async fn wake(&self, target: &WakeTarget, sealed: Bytes) -> Result<(), WakeError> {
        if sealed.len() > MAX_WAKE {
            return Err(WakeError::TooLarge);
        }
        let id = Self::box_of(target)?;
        let key = BoxKey::derive(&self.seed, &id, BoxRole::Writer);
        self.mailbox
            .put(&id, &key, sealed)
            .await
            .map(|_| ())
            .map_err(wake_err)
    }

    /// Takes wakes in batches and acknowledges each batch as soon as it is taken: a wake is a
    /// hint, so one lost to a crash costs nothing but a later connection. Takes always start at
    /// the front of the box (acknowledged wakes are gone), so a box that was re-created, whose
    /// ids start again at 1, is read like a new one.
    async fn listen(&self) -> Result<Woken, WakeError> {
        let mut l = self.listening.lock().await;
        loop {
            if let Some(m) = l.pending.pop_front() {
                return Ok(Woken { sealed: m.bytes });
            }
            let wait = self.mailbox.limits().max_wait.max(Duration::from_millis(1));
            let got = self
                .mailbox
                .take(&self.own, &self.reader, None, 16, wait)
                .await
                .map_err(wake_err)?;
            if let Some(last) = got.last().map(|m| m.id) {
                self.mailbox
                    .ack(&self.own, &self.reader, last)
                    .await
                    .map_err(wake_err)?;
                l.pending
                    .extend(got.into_iter().filter(|m| m.bytes.len() <= MAX_WAKE));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use baton_core::Timestamp;
    use baton_drop::Clock;
    use baton_drop::admission::AdmissionConfig;
    use baton_mailbox_memory::MemoryMailbox;

    use super::*;

    async fn mailbox() -> Arc<dyn Mailbox> {
        let now = Arc::new(AtomicI64::new(1_800_000_000_000));
        let clock: Clock = Arc::new(move || Timestamp(now.load(Ordering::SeqCst)));
        Arc::new(
            MemoryMailbox::new(AdmissionConfig::open(), clock)
                .await
                .unwrap(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn conformance_over_memory_mailbox() {
        let mb = mailbox().await;
        let sender = Arc::new(MailboxWake::new(mb.clone(), &[1; 32], &[11; 32]));
        let receiver = Arc::new(MailboxWake::new(mb.clone(), &[2; 32], &[12; 32]));
        let stranger = Arc::new(MailboxWake::new(mb.clone(), &[3; 32], &[13; 32]));
        let target = receiver.target();
        receiver
            .create_own(vec![sender.writer_key(&target).unwrap()], &Admission::None)
            .await
            .unwrap();
        baton_wake::testing::wake(
            sender,
            receiver,
            stranger,
            WakeTarget::new(Bytes::from_static(b"short")).unwrap(),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_removed_waker_is_refused_and_unknown_targets_too() {
        let mb = mailbox().await;
        let sender = MailboxWake::new(mb.clone(), &[1; 32], &[11; 32]);
        let receiver = MailboxWake::new(mb.clone(), &[2; 32], &[12; 32]);
        let target = receiver.target();
        let key = sender.writer_key(&target).unwrap();
        receiver
            .create_own(vec![key], &Admission::None)
            .await
            .unwrap();
        sender
            .wake(&target, Bytes::from_static(b"a"))
            .await
            .unwrap();
        receiver.set_wakers(&[]).await.unwrap();
        assert!(matches!(
            sender.wake(&target, Bytes::from_static(b"b")).await,
            Err(WakeError::Denied)
        ));
        assert_eq!(
            receiver.listen().await.unwrap().sealed,
            Bytes::from_static(b"a")
        );
        let nowhere = MailboxWake::target_of(&BoxId::random());
        assert!(matches!(
            sender.wake(&nowhere, Bytes::from_static(b"c")).await,
            Err(WakeError::Denied)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wakes_arrive_after_the_wake_box_is_recreated() {
        let mb = mailbox().await;
        let sender = MailboxWake::new(mb.clone(), &[1; 32], &[11; 32]);
        let receiver = MailboxWake::new(mb.clone(), &[2; 32], &[12; 32]);
        let target = receiver.target();
        let key = sender.writer_key(&target).unwrap();
        receiver
            .create_own(vec![key], &Admission::None)
            .await
            .unwrap();
        for b in [&b"a"[..], b"b", b"c"] {
            sender
                .wake(&target, Bytes::copy_from_slice(b))
                .await
                .unwrap();
        }
        for _ in 0..3 {
            receiver.listen().await.unwrap();
        }
        mb.delete_box(&receiver.own, &receiver.reader)
            .await
            .unwrap();
        receiver
            .create_own(vec![key], &Admission::None)
            .await
            .unwrap();
        sender
            .wake(&target, Bytes::from_static(b"after"))
            .await
            .unwrap();
        let woken = tokio::time::timeout(Duration::from_secs(5), receiver.listen())
            .await
            .expect("the wake in the new box is seen")
            .unwrap();
        assert_eq!(woken.sealed, Bytes::from_static(b"after"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lost_wake_box_cannot_be_squatted() {
        let mb = mailbox().await;
        let receiver = MailboxWake::new(mb.clone(), &[2; 32], &[12; 32]);
        let squatter = BoxKey::generate();
        let policy = BoxPolicy {
            reader: squatter.public(),
            ..receiver.policy(vec![])
        };
        assert!(matches!(
            mb.create(&receiver.own, &policy, &squatter, &Admission::None)
                .await,
            Err(MailboxError::Denied)
        ));
        receiver
            .create_own(vec![], &Admission::None)
            .await
            .expect("the owner of the slot creates its box");
        let again = MailboxWake::new(mb.clone(), &[2; 32], &[12; 32]);
        assert_eq!(again.target(), receiver.target(), "a slot names one target");
        let fresh = MailboxWake::new(mb, &[2; 32], &[14; 32]);
        assert_ne!(fresh.target(), receiver.target());
    }

    #[test]
    fn writer_keys_are_per_target() {
        let a = MailboxWake::target_of(&BoxId([1; 32]));
        let b = MailboxWake::target_of(&BoxId([2; 32]));
        let k = |seed: u8, t: &WakeTarget| {
            BoxKey::derive(
                &[seed; 32],
                &MailboxWake::box_of(t).unwrap(),
                BoxRole::Writer,
            )
            .public()
        };
        assert_ne!(
            k(1, &a),
            k(1, &b),
            "one node's keys do not link its targets"
        );
        assert_ne!(k(1, &a), k(2, &a));
    }
}
