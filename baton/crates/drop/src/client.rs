//! [`DropMailbox`]: the drop client, a [`Mailbox`] over any [`Exchange`].

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use baton_identity::PublicKey;
use baton_mailbox::{
    Admission, BoxId, BoxKey, BoxPolicy, Mailbox, MailboxError, MailboxLimits, Message, MessageId,
};
use bytes::Bytes;

use crate::Clock;
use crate::service::{MAX_MESSAGE_CAP, max_reply};
use crate::wire::{self, Body, Reply, ServiceInfo, WireAdmission};

/// Carries raw drop requests to a service and its replies back: in process, over HTTP, ...
#[async_trait]
pub trait Exchange: Send + Sync {
    /// The service's encoded [`ServiceInfo`].
    async fn info(&self) -> Result<Vec<u8>, MailboxError>;

    /// Sends one encoded request and returns the encoded reply. `wait` is how long the service
    /// may hold the request (a long poll), so a transport can set its timeout above it.
    async fn exchange(&self, request: Vec<u8>, wait: Duration) -> Result<Vec<u8>, MailboxError>;
}

/// A [`Mailbox`] backed by a drop service. Every request is stamped by the client's clock, carries
/// a fresh random nonce and is signed by the box key under the configured realm; every reply is
/// size-checked and validated (order, sizes, kind) before it is believed.
pub struct DropMailbox {
    exchange: Arc<dyn Exchange>,
    realm: String,
    info: ServiceInfo,
    clock: Clock,
    last_version: Mutex<u64>,
}

impl DropMailbox {
    /// Fetches the service's info through `exchange` and checks it: the realm must be `realm` (the
    /// client's own configuration, never taken from the service) and every limit within the caps
    /// a client accepts.
    pub async fn connect(
        exchange: Arc<dyn Exchange>,
        realm: impl Into<String>,
        clock: Clock,
    ) -> Result<Self, MailboxError> {
        let realm = realm.into();
        let info = wire::decode_info(&exchange.info().await?)
            .map_err(|_| MailboxError::unavailable("malformed service info"))?;
        let sane = info.realm == realm
            && (1..=MAX_MESSAGE_CAP).contains(&info.max_message)
            && info.max_take >= 1
            && info.max_take <= 65_536
            && info.max_take_bytes >= info.max_message
            && info.max_take_bytes <= 64 * 1024 * 1024
            && info.max_wait_ms <= 300_000
            && info.work.as_ref().is_none_or(|w| w.within_caps());
        if !sane {
            return Err(MailboxError::Rejected(
                "service info outside what the client accepts",
            ));
        }
        Ok(Self {
            exchange,
            realm,
            info,
            clock,
            last_version: Mutex::new(0),
        })
    }

    /// The service's info, as checked at connect.
    pub fn info(&self) -> &ServiceInfo {
        &self.info
    }

    async fn call(
        &self,
        key: &BoxKey,
        id: &BoxId,
        body: Body,
        wait: Duration,
    ) -> Result<Reply, MailboxError> {
        let raw = wire::seal(&self.realm, key, id, &body, (self.clock)(), wire::nonce());
        let reply = self.exchange.exchange(raw, wait).await?;
        match wire::decode_reply(&reply, max_reply(&self.info)) {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(MailboxError::unavailable("malformed reply")),
        }
    }

    async fn done(&self, key: &BoxKey, id: &BoxId, body: Body) -> Result<(), MailboxError> {
        match self.call(key, id, body, Duration::ZERO).await? {
            Reply::Done => Ok(()),
            _ => Err(unexpected()),
        }
    }

    fn next_version(&self) -> u64 {
        let now_us = ((self.clock)().0.max(0) as u64).saturating_mul(1000);
        let mut last = self.last_version.lock().expect("version lock");
        *last = now_us.max(last.saturating_add(1));
        *last
    }
}

fn unexpected() -> MailboxError {
    MailboxError::unavailable("unexpected reply")
}

#[async_trait]
impl Mailbox for DropMailbox {
    fn limits(&self) -> MailboxLimits {
        MailboxLimits {
            max_message: self.info.max_message as usize,
            max_wait: Duration::from_millis(u64::from(self.info.max_wait_ms)),
            max_take: self.info.max_take,
        }
    }

    async fn create(
        &self,
        id: &BoxId,
        policy: &BoxPolicy,
        reader: &BoxKey,
        admission: &Admission,
    ) -> Result<(), MailboxError> {
        let admission = match admission {
            Admission::None => WireAdmission::None,
            Admission::Token(t) if t.len() <= wire::MAX_TOKEN => wire::token(t),
            Admission::Token(_) => return Err(MailboxError::Admission),
            Admission::Work => {
                let work = self.info.work.clone().ok_or(MailboxError::Admission)?;
                let box_id = *id;
                let nonce = tokio::task::spawn_blocking(move || work.solve(&box_id))
                    .await
                    .map_err(MailboxError::unavailable)?
                    .ok_or(MailboxError::Admission)?;
                WireAdmission::Work(nonce)
            }
        };
        self.done(
            reader,
            id,
            Body::Create {
                policy: policy.clone(),
                admission,
            },
        )
        .await
    }

    async fn put(
        &self,
        id: &BoxId,
        writer: &BoxKey,
        sealed: Bytes,
    ) -> Result<MessageId, MailboxError> {
        if sealed.len() > self.info.max_message as usize {
            return Err(MailboxError::TooLarge);
        }
        match self
            .call(writer, id, Body::Put { bytes: sealed }, Duration::ZERO)
            .await?
        {
            Reply::Stored(n) => Ok(MessageId(n)),
            _ => Err(unexpected()),
        }
    }

    async fn take(
        &self,
        id: &BoxId,
        reader: &BoxKey,
        after: Option<MessageId>,
        limit: u32,
        wait: Duration,
    ) -> Result<Vec<Message>, MailboxError> {
        let limit = limit.clamp(1, self.info.max_take);
        let wait = wait.min(Duration::from_millis(u64::from(self.info.max_wait_ms)));
        let body = Body::Take {
            after: after.map(|a| a.0),
            limit,
            wait_ms: wait.as_millis() as u32,
        };
        let Reply::Messages(found) = self.call(reader, id, body, wait).await? else {
            return Err(unexpected());
        };
        let mut prev = after.map_or(0, |a| a.0);
        let mut first = after.is_none();
        if found.len() > limit as usize {
            return Err(unexpected());
        }
        let mut out = Vec::with_capacity(found.len());
        for m in found {
            if (!first && m.id <= prev) || m.bytes.len() > self.info.max_message as usize {
                return Err(unexpected());
            }
            first = false;
            prev = m.id;
            out.push(Message {
                id: MessageId(m.id),
                bytes: m.bytes,
                stored_at: m.at,
            });
        }
        Ok(out)
    }

    async fn ack(&self, id: &BoxId, reader: &BoxKey, up_to: MessageId) -> Result<(), MailboxError> {
        self.done(reader, id, Body::Ack { up_to: up_to.0 }).await
    }

    async fn set_writers(
        &self,
        id: &BoxId,
        reader: &BoxKey,
        writers: &[PublicKey],
    ) -> Result<(), MailboxError> {
        let body = Body::SetWriters {
            writers: writers.to_vec(),
            version: self.next_version(),
        };
        self.done(reader, id, body).await
    }

    async fn delete_box(&self, id: &BoxId, reader: &BoxKey) -> Result<(), MailboxError> {
        self.done(reader, id, Body::Delete).await
    }
}
