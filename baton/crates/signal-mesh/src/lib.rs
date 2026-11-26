//! `baton-signal`'s [`Signal`] spread over the mesh.
//!
//! [`MeshSignal`] wraps a local [`Signal`] (normally `baton-signal-local`, whose limits bound what
//! remote members can make this node hold) and adds fan-out: publishing, storing and deleting act
//! on the local backend at once and are then sent to every member the transport can reach right
//! now. Nothing is retried or caught up later; a node that was unreachable misses what happened
//! meanwhile, which the contract allows because signals are cheap to lose.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use baton_core::GroupId;
use baton_mesh::{MAX_PAYLOAD, Transport};
use baton_signal::{Signal, SignalError, check_name, check_payload};
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

/// The transport channel this crate uses.
pub const CHANNEL: &str = "baton/signal/1";

/// How long one send to one member may take before it is abandoned, so a stuck peer does not
/// delay the others.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(1);

/// The longest time-to-live a remote member can give a value here.
pub const MAX_REMOTE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Serialize, Deserialize)]
enum Msg {
    Publish {
        group: GroupId,
        topic: String,
        payload: Vec<u8>,
    },
    Put {
        group: GroupId,
        key: String,
        value: Vec<u8>,
        ttl_ms: u64,
    },
    Delete {
        group: GroupId,
        key: String,
    },
}

/// [`Signal`] for one mesh node of one group.
///
/// Guarantees beyond the contract:
///
/// - Local effects are immediate: a value stored here is readable here at once, and local
///   subscribers get local publishes before `publish` returns.
/// - Remote effects are best effort and reach only members reachable when the call is made. A
///   remote copy of a value expires after the time-to-live measured from its arrival (at most
///   [`MAX_REMOTE_TTL`]), so clock differences between nodes do not matter.
/// - Writes to the same key from different nodes have no order: each node keeps the last one it
///   received.
/// - Only roster members' messages are accepted (checked by the transport), only for this
///   node's group, and only within the names and sizes the contract allows; everything a remote
///   member sends lands in the local backend and is bounded by its limits.
/// - Calls for another group fail; counters are not shared across the mesh (`incr` returns
///   `None`).
pub struct MeshSignal {
    group: GroupId,
    local: Arc<dyn Signal>,
    transport: Arc<dyn Transport>,
    task: JoinHandle<()>,
}

fn backend(e: impl std::error::Error + Send + Sync + 'static) -> SignalError {
    SignalError::Backend(Box::new(e))
}

#[derive(Debug, thiserror::Error)]
#[error("this mesh signal serves another group")]
struct OtherGroup;

async fn apply(local: &dyn Signal, group: &GroupId, msg: Msg) {
    match msg {
        Msg::Publish {
            group: g,
            topic,
            payload,
        } if &g == group => {
            let _ = local.publish(group, &topic, Bytes::from(payload)).await;
        }
        Msg::Put {
            group: g,
            key,
            value,
            ttl_ms,
        } if &g == group => {
            let ttl = Duration::from_millis(ttl_ms).min(MAX_REMOTE_TTL);
            let _ = local.put(group, &key, Bytes::from(value), ttl).await;
        }
        Msg::Delete { group: g, key } if &g == group => {
            let _ = local.delete(group, &key).await;
        }
        _ => {}
    }
}

impl MeshSignal {
    /// Serves `group` on `transport`, keeping values and subscribers in `local`. Needs a Tokio
    /// runtime; incoming messages are handled by a task that stops when this value is dropped.
    pub async fn start(
        transport: Arc<dyn Transport>,
        group: GroupId,
        local: Arc<dyn Signal>,
    ) -> Result<Self, SignalError> {
        let mut incoming = transport.subscribe(CHANNEL).await.map_err(backend)?;
        let task_local = local.clone();
        let task_group = group.clone();
        let task = tokio::spawn(async move {
            while let Some(env) = incoming.next().await {
                if env.payload.len() > MAX_PAYLOAD {
                    continue;
                }
                if let Ok(msg) = postcard::from_bytes::<Msg>(&env.payload) {
                    apply(&*task_local, &task_group, msg).await;
                }
            }
        });
        Ok(Self {
            group,
            local,
            transport,
            task,
        })
    }

    fn check_group(&self, group: &GroupId) -> Result<(), SignalError> {
        if group == &self.group {
            Ok(())
        } else {
            Err(backend(OtherGroup))
        }
    }

    async fn spread(&self, msg: &Msg) -> Result<(), SignalError> {
        let bytes = Bytes::from(postcard::to_stdvec(msg).expect("a message always serializes"));
        if bytes.len() > MAX_PAYLOAD {
            return Err(SignalError::TooLarge);
        }
        let peers = self.transport.peers().await.map_err(backend)?;
        futures::future::join_all(peers.iter().map(|peer| {
            let b = bytes.clone();
            async move {
                let _ =
                    tokio::time::timeout(SEND_TIMEOUT, self.transport.send(peer, CHANNEL, b)).await;
            }
        }))
        .await;
        Ok(())
    }
}

impl Drop for MeshSignal {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[async_trait]
impl Signal for MeshSignal {
    async fn publish(
        &self,
        group: &GroupId,
        topic: &str,
        payload: Bytes,
    ) -> Result<(), SignalError> {
        self.check_group(group)?;
        check_name(topic)?;
        check_payload(&payload)?;
        let msg = Msg::Publish {
            group: group.clone(),
            topic: topic.to_owned(),
            payload: payload.to_vec(),
        };
        if postcard::to_stdvec(&msg).map_or(true, |b| b.len() > MAX_PAYLOAD) {
            return Err(SignalError::TooLarge);
        }
        self.local.publish(group, topic, payload).await?;
        self.spread(&msg).await
    }

    async fn subscribe(
        &self,
        group: &GroupId,
        topic: &str,
    ) -> Result<BoxStream<'static, Bytes>, SignalError> {
        self.check_group(group)?;
        self.local.subscribe(group, topic).await
    }

    async fn put(
        &self,
        group: &GroupId,
        key: &str,
        value: Bytes,
        ttl: Duration,
    ) -> Result<(), SignalError> {
        self.check_group(group)?;
        check_name(key)?;
        check_payload(&value)?;
        let msg = Msg::Put {
            group: group.clone(),
            key: key.to_owned(),
            value: value.to_vec(),
            ttl_ms: ttl.as_millis().min(u64::MAX as u128) as u64,
        };
        if postcard::to_stdvec(&msg).map_or(true, |b| b.len() > MAX_PAYLOAD) {
            return Err(SignalError::TooLarge);
        }
        self.local.put(group, key, value, ttl).await?;
        self.spread(&msg).await
    }

    async fn get(&self, group: &GroupId, key: &str) -> Result<Option<Bytes>, SignalError> {
        self.check_group(group)?;
        self.local.get(group, key).await
    }

    async fn delete(&self, group: &GroupId, key: &str) -> Result<(), SignalError> {
        self.check_group(group)?;
        check_name(key)?;
        self.local.delete(group, key).await?;
        self.spread(&Msg::Delete {
            group: group.clone(),
            key: key.to_owned(),
        })
        .await
    }
}

#[cfg(test)]
mod tests;
