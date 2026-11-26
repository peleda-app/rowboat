use std::sync::Arc;
use std::time::Duration;

use baton_core::{GroupId, Timestamp};
use baton_group::{Entry, GroupError, GroupLog, HeadCheck};
use baton_link::{Duplex, Link, Protocol, PublicKey};
use tokio::time::{Instant, timeout};

use crate::PROTOCOL;
use crate::wire::{self, FrameError, Head, Refusal, Reply, Request};

/// Why a call to a group server failed. Carries no entry content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteError {
    /// The server cannot be reached or did not answer in time. The call may be retried.
    #[error("the group server is unavailable")]
    Unavailable,
    /// The server refused the request.
    #[error("the group server refused: {0:?}")]
    Refused(Refusal),
    /// The server answered something that does not fit the request.
    #[error("the group server answered out of protocol")]
    Protocol,
    /// An entry from the server failed verification against the log.
    #[error("an entry from the group server is invalid: {0}")]
    Invalid(GroupError),
    /// The server's head is behind the caller's log (a rollback or a stale copy).
    #[error("the group server is behind this log")]
    Rollback,
    /// The server's log and the caller's disagree at a position both have.
    #[error("the group server's log forked from this one")]
    Fork,
}

/// Limits and timings of a [`GroupClient`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// How long one call may take, opening a stream included.
    pub request_timeout: Duration,
    /// The largest reply body accepted.
    pub max_reply: usize,
    /// How far ahead of the caller's clock an entry's time may be.
    pub max_skew_ms: i64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            max_reply: wire::MAX_REPLY,
            max_skew_ms: crate::DEFAULT_SKEW_MS,
        }
    }
}

/// A connection to a [`GroupServer`](crate::GroupServer).
///
/// Guarantees: every call ends within [`ClientConfig::request_timeout`]; calls share one stream,
/// one at a time; a stream that failed or carried a malformed reply is dropped, and a call on a
/// reused stream that breaks is retried once on a new stream (every request is safe to repeat:
/// a repeated push of a held entry changes nothing); replies larger than
/// [`ClientConfig::max_reply`] are refused before they are read. Nothing from the server is
/// trusted: [`GroupClient::fetch`] returns only entries whose signature checks, of the group
/// asked, in sequence, and [`GroupClient::sync`] verifies each against the caller's log.
pub struct GroupClient {
    link: Arc<dyn Link>,
    server: PublicKey,
    protocol: Protocol,
    config: ClientConfig,
    max_fetch: u32,
    stream: tokio::sync::Mutex<Option<Box<dyn Duplex>>>,
}

enum Failure {
    Io,
    Protocol,
}

impl GroupClient {
    /// Connects to the server with key `server` over `link` and reads its limits.
    pub async fn connect(
        link: Arc<dyn Link>,
        server: PublicKey,
        config: ClientConfig,
    ) -> Result<Self, RemoteError> {
        let mut client = Self {
            link,
            server,
            protocol: Protocol::new(PROTOCOL).expect("valid protocol name"),
            config,
            max_fetch: 0,
            stream: tokio::sync::Mutex::new(None),
        };
        match client.call(&Request::Hello).await? {
            Reply::Hello { max_fetch, .. } if max_fetch > 0 => {
                client.max_fetch = max_fetch.min(wire::MAX_FETCH)
            }
            _ => return Err(RemoteError::Protocol),
        }
        Ok(client)
    }

    /// The server's key.
    pub fn server(&self) -> PublicKey {
        self.server
    }

    async fn exchange(&self, s: &mut Box<dyn Duplex>, body: &[u8]) -> Result<Reply, Failure> {
        let max = self.config.max_reply.min(wire::MAX_REPLY);
        let raw = async {
            wire::write_frame(s, body).await?;
            wire::read_frame(s, max).await
        };
        let raw = match timeout(self.config.request_timeout, raw).await {
            Ok(Ok(raw)) => raw,
            Ok(Err(FrameError::Length)) => return Err(Failure::Protocol),
            _ => return Err(Failure::Io),
        };
        wire::decode_reply(&raw, max).map_err(|_| Failure::Protocol)
    }

    async fn call(&self, request: &Request) -> Result<Reply, RemoteError> {
        let started = Instant::now();
        let body = wire::encode_request(request);
        let mut slot = self.stream.lock().await;
        let mut reply = None;
        if let Some(mut s) = slot.take() {
            match self.exchange(&mut s, &body).await {
                Ok(r) => {
                    *slot = Some(s);
                    reply = Some(r);
                }
                Err(Failure::Protocol) => return Err(RemoteError::Protocol),
                Err(Failure::Io) => {}
            }
        }
        let reply = match reply {
            Some(r) => r,
            None => {
                let left = self
                    .config
                    .request_timeout
                    .saturating_sub(started.elapsed());
                let mut s = match timeout(left, self.link.open(&self.server, &self.protocol)).await
                {
                    Ok(Ok(s)) => s,
                    _ => return Err(RemoteError::Unavailable),
                };
                match self.exchange(&mut s, &body).await {
                    Ok(r) => {
                        *slot = Some(s);
                        r
                    }
                    Err(Failure::Protocol) => return Err(RemoteError::Protocol),
                    Err(Failure::Io) => return Err(RemoteError::Unavailable),
                }
            }
        };
        match reply {
            Reply::Refused(Refusal::Version) => {
                *slot = None;
                Err(RemoteError::Protocol)
            }
            Reply::Refused(Refusal::Busy) => Err(RemoteError::Unavailable),
            Reply::Refused(r) => Err(RemoteError::Refused(r)),
            r => Ok(r),
        }
    }

    /// The head of `group` on the server, `None` while it holds no entry.
    pub async fn head(&self, group: &GroupId) -> Result<Option<Head>, RemoteError> {
        match self
            .call(&Request::Head {
                group: group.clone(),
            })
            .await?
        {
            Reply::Head(h) => Ok(h),
            _ => Err(RemoteError::Protocol),
        }
    }

    /// Entries of `group` after `after` (from genesis when `None`), at most `limit` (capped by
    /// the server). Each entry's signature is checked, and the entries are of `group`, numbered
    /// from `after + 1` without a gap.
    pub async fn fetch(
        &self,
        group: &GroupId,
        after: Option<u64>,
        limit: u32,
    ) -> Result<Vec<Entry>, RemoteError> {
        let limit = limit.min(self.max_fetch);
        let raw = match self
            .call(&Request::Fetch {
                group: group.clone(),
                after,
                limit,
            })
            .await?
        {
            Reply::Entries(e) => e,
            _ => return Err(RemoteError::Protocol),
        };
        if raw.len() > limit as usize {
            return Err(RemoteError::Protocol);
        }
        let mut next = after.map_or(Some(0), |a| a.checked_add(1));
        let mut out = Vec::with_capacity(raw.len());
        for bytes in raw {
            let e = Entry::decode(&bytes).map_err(RemoteError::Invalid)?;
            if e.group() != group || Some(e.seq()) != next {
                return Err(RemoteError::Protocol);
            }
            next = e.seq().checked_add(1);
            out.push(e);
        }
        Ok(out)
    }

    /// Pushes `entry`; returns the server's head after it and whether this push added it.
    pub async fn push(&self, entry: &Entry) -> Result<(Head, bool), RemoteError> {
        match self
            .call(&Request::Push {
                entry: entry.encode(),
            })
            .await?
        {
            Reply::Accepted { head, new } if head.seq >= entry.seq() => Ok((head, new)),
            _ => Err(RemoteError::Protocol),
        }
    }

    /// Brings `log` (or a new log of `group` when `None`, whose genesis must hash to `genesis`)
    /// up to the server's head, verifying every entry with [`GroupLog::apply_fresh`] at `now`,
    /// then checks the server's head against the result: a server behind the caller's log fails
    /// with [`RemoteError::Rollback`], a different entry at a shared position with
    /// [`RemoteError::Fork`]. On failure the caller's log is unchanged.
    pub async fn sync(
        &self,
        group: &GroupId,
        genesis: [u8; 32],
        log: Option<&GroupLog>,
        now: Timestamp,
    ) -> Result<GroupLog, RemoteError> {
        let mut log = log.cloned();
        loop {
            let after = log.as_ref().map(|l| l.head_seq());
            let page = self.fetch(group, after, self.max_fetch).await?;
            if page.is_empty() {
                break;
            }
            for e in page {
                match log.as_mut() {
                    None => {
                        if e.hash() != genesis || e.at() > now.plus_ms(self.config.max_skew_ms) {
                            return Err(RemoteError::Fork);
                        }
                        log = Some(GroupLog::verify(vec![e]).map_err(RemoteError::Invalid)?);
                    }
                    Some(l) => {
                        l.apply_fresh(e, now, self.config.max_skew_ms)
                            .map_err(|e| match e {
                                GroupError::Chain => RemoteError::Fork,
                                e => RemoteError::Invalid(e),
                            })?
                    }
                }
            }
        }
        let head = self.head(group).await?;
        let Some(log) = log else {
            return match head {
                None => Err(RemoteError::Refused(Refusal::Chain(None))),
                Some(_) => Err(RemoteError::Protocol),
            };
        };
        if log.genesis_hash() != genesis {
            return Err(RemoteError::Fork);
        }
        match head.map(|h| log.check_head(h.seq, h.hash)) {
            Some(HeadCheck::Same) | Some(HeadCheck::Ahead) => Ok(log),
            Some(HeadCheck::Behind) | None => Err(RemoteError::Rollback),
            Some(HeadCheck::Fork) => Err(RemoteError::Fork),
        }
    }
}
