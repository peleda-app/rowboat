//! An in-process [`Mailbox`]: the drop client talking to a [`DropService`] in the same process,
//! so every rule (signatures, freshness, replay, admission, quotas, time-to-live) is the drop
//! service's own. Over [`MemoryDropStore`] it keeps nothing across a restart.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use baton_drop::admission::AdmissionConfig;
use baton_drop::{Clock, DropConfig, DropMailbox, DropService, Exchange, MemoryDropStore, wire};
use baton_identity::PublicKey;
use baton_mailbox::{
    Admission, BoxId, BoxKey, BoxPolicy, Mailbox, MailboxError, MailboxLimits, Message, MessageId,
};
use bytes::Bytes;

/// The realm of an in-process service.
pub const REALM: &str = "memory.invalid";

struct InProcess(Arc<DropService>);

#[async_trait]
impl Exchange for InProcess {
    async fn info(&self) -> Result<Vec<u8>, MailboxError> {
        Ok(wire::encode_info(&self.0.info()))
    }

    async fn exchange(&self, request: Vec<u8>, _wait: Duration) -> Result<Vec<u8>, MailboxError> {
        Ok(self.0.handle(&request).await)
    }
}

/// A [`Mailbox`] backed by a [`DropService`] in this process.
pub struct MemoryMailbox {
    inner: DropMailbox,
    service: Arc<DropService>,
}

impl MemoryMailbox {
    /// A mailbox over `service`, stamping requests with `clock`.
    pub async fn over(service: Arc<DropService>, clock: Clock) -> Result<Self, MailboxError> {
        let realm = service.config().realm.clone();
        let inner =
            DropMailbox::connect(Arc::new(InProcess(service.clone())), realm, clock).await?;
        Ok(Self { inner, service })
    }

    /// A fresh service over a [`MemoryDropStore`] with the default limits, realm [`REALM`],
    /// `admission` and `clock`, and a mailbox over it.
    pub async fn new(admission: AdmissionConfig, clock: Clock) -> Result<Self, MailboxError> {
        let service = DropService::new(
            Arc::new(MemoryDropStore::new()),
            DropConfig::new(REALM, admission),
            clock.clone(),
        )
        .map_err(MailboxError::unavailable)?;
        Self::over(Arc::new(service), clock).await
    }

    /// The service behind it (to sweep, or to share with another client).
    pub fn service(&self) -> &Arc<DropService> {
        &self.service
    }
}

#[async_trait]
impl Mailbox for MemoryMailbox {
    fn limits(&self) -> MailboxLimits {
        self.inner.limits()
    }

    async fn create(
        &self,
        id: &BoxId,
        policy: &BoxPolicy,
        reader: &BoxKey,
        admission: &Admission,
    ) -> Result<(), MailboxError> {
        self.inner.create(id, policy, reader, admission).await
    }

    async fn put(
        &self,
        id: &BoxId,
        writer: &BoxKey,
        sealed: Bytes,
    ) -> Result<MessageId, MailboxError> {
        self.inner.put(id, writer, sealed).await
    }

    async fn take(
        &self,
        id: &BoxId,
        reader: &BoxKey,
        after: Option<MessageId>,
        limit: u32,
        wait: Duration,
    ) -> Result<Vec<Message>, MailboxError> {
        self.inner.take(id, reader, after, limit, wait).await
    }

    async fn ack(&self, id: &BoxId, reader: &BoxKey, up_to: MessageId) -> Result<(), MailboxError> {
        self.inner.ack(id, reader, up_to).await
    }

    async fn set_writers(
        &self,
        id: &BoxId,
        reader: &BoxKey,
        writers: &[PublicKey],
    ) -> Result<(), MailboxError> {
        self.inner.set_writers(id, reader, writers).await
    }

    async fn delete_box(&self, id: &BoxId, reader: &BoxKey) -> Result<(), MailboxError> {
        self.inner.delete_box(id, reader).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use baton_core::Timestamp;
    use baton_drop::admission::WorkParams;
    use baton_mailbox::testing::{Harness, mailbox};
    use zeroize::Zeroizing;

    use super::*;

    const TOKEN: &[u8] = b"memory-operator-token";

    struct H {
        now: Arc<AtomicI64>,
        admission: Admission,
    }

    impl Harness for H {
        fn admission(&self) -> Admission {
            self.admission.clone()
        }
        fn advance(&self, ms: u64) {
            self.now.fetch_add(ms as i64, Ordering::SeqCst);
        }
    }

    async fn run(config: AdmissionConfig, admission: Admission) {
        let now = Arc::new(AtomicI64::new(1_800_000_000_000));
        let n = now.clone();
        let clock: Clock = Arc::new(move || Timestamp(n.load(Ordering::SeqCst)));
        let mb = MemoryMailbox::new(config, clock).await.unwrap();
        mailbox(Arc::new(mb), Arc::new(H { now, admission })).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn conformance_with_token() {
        run(
            AdmissionConfig::closed().with_token(TOKEN).unwrap(),
            Admission::Token(Zeroizing::new(TOKEN.to_vec())),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn conformance_with_proof_of_work() {
        run(
            AdmissionConfig::closed()
                .with_work(WorkParams::generate(3, 64, 1).unwrap())
                .unwrap(),
            Admission::Work,
        )
        .await;
    }
}
