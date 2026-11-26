//! An in-process [`Transport`](baton_mesh::Transport) for tests: nodes join a [`MemoryHub`], which can split them into
//! partitions to simulate network splits. Frames are sealed and opened exactly as on a real
//! network, so signature and membership checks run for real.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use baton_core::{NodeId, Timestamp};
use baton_identity::{Identity, PublicKey, RosterHandle};
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use tokio::sync::mpsc;

use baton_mesh::frame::{Opener, seal};
use baton_mesh::{Envelope, MAX_PAYLOAD, Transport, TransportError, check_channel};

struct Inbox {
    opener: Opener,
    subscribers: Mutex<HashMap<String, Vec<mpsc::Sender<Envelope>>>>,
    dropped: AtomicU64,
}

impl Inbox {
    fn deliver(&self, raw: &[u8], sender: Option<&PublicKey>) {
        let Ok(envelope) = self.opener.open(raw, sender) else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut subs = self.subscribers.lock().expect("subscribers lock");
        if let Some(list) = subs.get_mut(&envelope.channel) {
            list.retain(|tx| {
                !matches!(
                    tx.try_send(envelope.clone()),
                    Err(mpsc::error::TrySendError::Closed(_))
                )
            });
        }
    }
}

#[derive(Default)]
struct HubState {
    inboxes: HashMap<NodeId, Arc<Inbox>>,
    groups: HashMap<NodeId, usize>,
}

impl HubState {
    fn group(&self, node: &NodeId) -> usize {
        self.groups.get(node).copied().unwrap_or(0)
    }
}

/// The in-process network. Cloning shares it.
///
/// Guarantees: a frame reaches its destination, in send order, exactly when both nodes have
/// joined and sit in the same partition at send time; otherwise the send fails with
/// [`TransportError::Unreachable`] and nothing is delivered.
#[derive(Clone, Default)]
pub struct MemoryHub {
    state: Arc<Mutex<HubState>>,
}

impl MemoryHub {
    /// An empty network with every node in one partition.
    pub fn new() -> Self {
        Self::default()
    }

    /// Connects a node with `identity` that trusts `roster`. Joining again with the same identity
    /// replaces the earlier connection.
    pub fn join(&self, identity: Identity, roster: RosterHandle) -> MemoryTransport {
        let local = identity.node_id();
        let inbox = Arc::new(Inbox {
            opener: Opener::new(local.clone(), roster.clone()),
            subscribers: Mutex::new(HashMap::new()),
            dropped: AtomicU64::new(0),
        });
        self.state
            .lock()
            .expect("hub lock")
            .inboxes
            .insert(local.clone(), inbox.clone());
        MemoryTransport {
            hub: self.clone(),
            identity: Arc::new(identity),
            local,
            roster,
            inbox,
            seq: Arc::new(Mutex::new(Timestamp::now().0.max(0) as u64 * 1000)),
        }
    }

    /// Splits the network: nodes in the same group reach each other, nodes in different groups
    /// do not. Nodes in no group form one more partition together.
    pub fn partition(&self, groups: &[&[NodeId]]) {
        let mut state = self.state.lock().expect("hub lock");
        state.groups.clear();
        for (i, group) in groups.iter().enumerate() {
            for node in group.iter() {
                state.groups.insert(node.clone(), i + 1);
            }
        }
    }

    /// Joins every partition back together.
    pub fn heal(&self) {
        self.state.lock().expect("hub lock").groups.clear();
    }

    /// Hands raw bytes to `to` as if they came from the network, bypassing sealing. For tests of
    /// what a node drops.
    pub fn inject(&self, to: &NodeId, raw: &[u8]) {
        let inbox = self
            .state
            .lock()
            .expect("hub lock")
            .inboxes
            .get(to)
            .cloned();
        if let Some(inbox) = inbox {
            inbox.deliver(raw, None);
        }
    }

    fn route(&self, from: &NodeId, to: &NodeId) -> Option<Arc<Inbox>> {
        let state = self.state.lock().expect("hub lock");
        if state.group(from) != state.group(to) {
            return None;
        }
        state.inboxes.get(to).cloned()
    }

    fn reachable(&self, from: &NodeId) -> Vec<NodeId> {
        let state = self.state.lock().expect("hub lock");
        let g = state.group(from);
        state
            .inboxes
            .keys()
            .filter(|n| *n != from && state.group(n) == g)
            .cloned()
            .collect()
    }
}

/// One node's connection to a [`MemoryHub`]. Cloning shares it.
#[derive(Clone)]
pub struct MemoryTransport {
    hub: MemoryHub,
    identity: Arc<Identity>,
    local: NodeId,
    roster: RosterHandle,
    inbox: Arc<Inbox>,
    seq: Arc<Mutex<u64>>,
}

impl MemoryTransport {
    /// How many incoming frames this node dropped because they failed a check.
    pub fn dropped(&self) -> u64 {
        self.inbox.dropped.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Transport for MemoryTransport {
    fn local(&self) -> NodeId {
        self.local.clone()
    }

    async fn send(&self, to: &NodeId, channel: &str, payload: Bytes) -> Result<(), TransportError> {
        check_channel(channel)?;
        if payload.len() > MAX_PAYLOAD {
            return Err(TransportError::TooLarge);
        }
        if *to == self.local {
            return Err(TransportError::Unreachable);
        }
        let inbox = self
            .hub
            .route(&self.local, to)
            .ok_or(TransportError::Unreachable)?;
        let mut seq = self.seq.lock().expect("sequence lock");
        *seq += 1;
        inbox.deliver(
            &seal(&self.identity, to, channel, *seq, &payload),
            Some(&self.identity.public()),
        );
        Ok(())
    }

    async fn subscribe(
        &self,
        channel: &str,
    ) -> Result<BoxStream<'static, Envelope>, TransportError> {
        check_channel(channel)?;
        let (tx, rx) = mpsc::channel(baton_mesh::SUBSCRIBER_BUFFER);
        self.inbox
            .subscribers
            .lock()
            .expect("subscribers lock")
            .entry(channel.to_owned())
            .or_default()
            .push(tx);
        Ok(
            futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|e| (e, rx)) })
                .boxed(),
        )
    }

    async fn peers(&self) -> Result<Vec<NodeId>, TransportError> {
        let roster = self.roster.current();
        let mut peers: Vec<_> = self
            .hub
            .reachable(&self.local)
            .into_iter()
            .filter(|n| roster.contains_node(n))
            .collect();
        peers.sort();
        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use baton_core::GroupId;
    use baton_identity::Roster;
    use baton_mesh::frame::seal;

    struct Mesh {
        hub: MemoryHub,
        ids: Vec<Identity>,
        handles: Vec<RosterHandle>,
        nodes: Vec<MemoryTransport>,
    }

    fn mesh(n: usize) -> Mesh {
        let ids: Vec<_> = (0..n).map(|_| Identity::generate()).collect();
        let mut roster = Roster::genesis(&ids[0], GroupId::new("t").unwrap());
        for id in &ids[1..] {
            roster = roster.with_member(&ids[0], id.public()).unwrap();
        }
        let hub = MemoryHub::new();
        let handles: Vec<_> = ids
            .iter()
            .map(|_| RosterHandle::new(roster.clone()).unwrap())
            .collect();
        let nodes = ids
            .iter()
            .zip(&handles)
            .map(|(id, h)| hub.join(id.clone(), h.clone()))
            .collect();
        Mesh {
            hub,
            ids,
            handles,
            nodes,
        }
    }

    async fn next(s: &mut BoxStream<'static, Envelope>) -> Option<Envelope> {
        tokio::time::timeout(Duration::from_millis(200), s.next())
            .await
            .ok()
            .flatten()
    }

    struct Hub(MemoryHub);

    impl baton_mesh::testing::Harness for Hub {
        async fn join(&self, identity: Identity, roster: RosterHandle) -> Arc<dyn Transport> {
            Arc::new(self.0.join(identity, roster))
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn conformance() {
        baton_mesh::testing::transport(&Hub(MemoryHub::new())).await;
    }

    #[tokio::test]
    async fn delivers_in_order_to_the_right_channel() {
        let m = mesh(2);
        let mut sub = m.nodes[1].subscribe("chan/a").await.unwrap();
        let mut other = m.nodes[1].subscribe("chan/b").await.unwrap();
        let to = m.nodes[1].local();
        for i in 0..5u8 {
            m.nodes[0]
                .send(&to, "chan/a", Bytes::from(vec![i]))
                .await
                .unwrap();
        }
        for i in 0..5u8 {
            let env = next(&mut sub).await.unwrap();
            assert_eq!(env.from, m.nodes[0].local());
            assert_eq!(&env.payload[..], &[i]);
        }
        assert!(next(&mut other).await.is_none());
        assert_eq!(m.nodes[0].peers().await.unwrap(), vec![to]);
        assert!(
            m.nodes[0]
                .send(&m.nodes[0].local(), "chan/a", Bytes::new())
                .await
                .is_err()
        );
        assert!(
            m.nodes[0]
                .send(&m.nodes[1].local(), "Bad Name", Bytes::new())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn partitions_cut_and_heal() {
        let m = mesh(3);
        let ids: Vec<_> = m.nodes.iter().map(|n| n.local()).collect();
        m.hub.partition(&[&ids[..2], &ids[2..]]);
        assert_eq!(m.nodes[0].peers().await.unwrap(), vec![ids[1].clone()]);
        assert!(m.nodes[2].peers().await.unwrap().is_empty());
        assert!(matches!(
            m.nodes[0].send(&ids[2], "x", Bytes::new()).await,
            Err(TransportError::Unreachable)
        ));
        m.hub.heal();
        assert_eq!(m.nodes[2].peers().await.unwrap().len(), 2);
        m.nodes[0].send(&ids[2], "x", Bytes::new()).await.unwrap();
    }

    #[tokio::test]
    async fn drops_unsigned_outsider_and_revoked_traffic() {
        let m = mesh(3);
        let target = m.nodes[0].local();
        let mut sub = m.nodes[0].subscribe("x").await.unwrap();

        let outsider = Identity::generate();
        m.hub
            .inject(&target, &seal(&outsider, &target, "x", u64::MAX, b"no"));
        m.hub.inject(&target, b"unsigned bytes");
        let stranger = m.hub.join(outsider.clone(), m.handles[1].clone());
        assert!(
            !m.nodes[0]
                .peers()
                .await
                .unwrap()
                .contains(&outsider.node_id())
        );
        stranger
            .send(&target, "x", Bytes::from_static(b"no"))
            .await
            .unwrap();
        assert!(next(&mut sub).await.is_none());
        assert_eq!(m.nodes[0].dropped(), 3);

        let revoked = m.handles[0]
            .current()
            .without_member(&m.ids[0], &m.ids[2].public())
            .unwrap();
        m.handles[0].update(revoked).unwrap();
        m.nodes[2]
            .send(&target, "x", Bytes::from_static(b"no"))
            .await
            .unwrap();
        m.nodes[1]
            .send(&target, "x", Bytes::from_static(b"yes"))
            .await
            .unwrap();
        let env = next(&mut sub).await.unwrap();
        assert_eq!(&env.payload[..], b"yes");
        assert!(next(&mut sub).await.is_none());
        assert!(
            !m.nodes[0]
                .peers()
                .await
                .unwrap()
                .contains(&m.ids[2].node_id())
        );
    }
}
