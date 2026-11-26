//! Conformance suite for [`Transport`]. It expects a lossless environment (loopback, an
//! in-process hub), so it can assert that every message arrives. It drives transports only
//! through the trait, so it cannot inject raw frames: replays, frames addressed to another node
//! and frames relayed by another member must be tested by each implementation (both in this
//! repository do), and every implementation must pass the deliverer as `sender` to
//! [`frame::Opener::open`](crate::frame::Opener::open) where its carrier authenticates one.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use baton_core::GroupId;
use baton_identity::{Identity, Roster, RosterHandle};
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;

use crate::{Envelope, MAX_PAYLOAD, Transport, TransportError};

/// How the suite gets transports.
pub trait Harness: Send + Sync {
    /// A transport for `identity` that trusts what `roster` holds at any moment. Transports from
    /// one harness reach each other.
    fn join(
        &self,
        identity: Identity,
        roster: RosterHandle,
    ) -> impl Future<Output = Arc<dyn Transport>> + Send;
}

async fn next(s: &mut BoxStream<'static, Envelope>, wait: Duration) -> Option<Envelope> {
    tokio::time::timeout(wait, s.next()).await.ok().flatten()
}

async fn eventually_peers(t: &Arc<dyn Transport>, want: usize) -> Vec<baton_core::NodeId> {
    for _ in 0..50 {
        let p = t.peers().await.unwrap();
        if p.len() >= want {
            return p;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    t.peers().await.unwrap()
}

/// The [`Transport`] contract, with an outsider, a revocation and concurrent senders.
pub async fn transport<H: Harness>(h: &H) {
    let ids: Vec<_> = (0..4).map(|_| Identity::generate()).collect();
    let mut roster = Roster::genesis(&ids[0], GroupId::new("conf-mesh").unwrap());
    for id in &ids[1..] {
        roster = roster.with_member(&ids[0], id.public()).unwrap();
    }
    let handles: Vec<_> = ids
        .iter()
        .map(|_| RosterHandle::new(roster.clone()).unwrap())
        .collect();
    let mut nodes = Vec::new();
    for (id, handle) in ids.iter().zip(&handles) {
        nodes.push(h.join(id.clone(), handle.clone()).await);
    }
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let wait = Duration::from_secs(3);
    let quiet = Duration::from_millis(300);

    let peers = eventually_peers(a, 3).await;
    for n in &nodes[1..] {
        assert!(
            peers.contains(&n.local()),
            "reachable members are listed as peers"
        );
    }
    assert!(!peers.contains(&a.local()), "a node is not its own peer");

    let mut on_a = b.subscribe("chan/a").await.unwrap();
    let mut on_b = b.subscribe("chan/b").await.unwrap();
    let mut own = a.subscribe("chan/a").await.unwrap();
    for i in 0..20u8 {
        a.send(&b.local(), "chan/a", Bytes::from(vec![i]))
            .await
            .unwrap();
    }
    for i in 0..20u8 {
        let env = next(&mut on_a, wait).await.expect("delivered");
        assert_eq!(
            env.from,
            a.local(),
            "the sender is the authenticated member"
        );
        assert_eq!(env.channel, "chan/a");
        assert_eq!(&env.payload[..], &[i], "per-pair order is kept");
    }
    assert!(next(&mut on_b, quiet).await.is_none(), "channels never mix");
    assert!(
        next(&mut own, quiet).await.is_none(),
        "a node never receives its own messages"
    );

    a.send(&b.local(), "chan/a", Bytes::from(vec![9u8; MAX_PAYLOAD]))
        .await
        .unwrap();
    assert_eq!(
        next(&mut on_a, wait).await.unwrap().payload.len(),
        MAX_PAYLOAD
    );
    assert!(matches!(
        a.send(
            &b.local(),
            "chan/a",
            Bytes::from(vec![0u8; MAX_PAYLOAD + 1])
        )
        .await,
        Err(TransportError::TooLarge)
    ));
    for bad in ["", "Bad", "a b", &"x".repeat(65)] {
        assert!(matches!(
            a.send(&b.local(), bad, Bytes::new()).await,
            Err(TransportError::InvalidChannel)
        ));
        assert!(matches!(
            a.subscribe(bad).await,
            Err(TransportError::InvalidChannel)
        ));
    }
    assert!(
        a.send(&a.local(), "chan/a", Bytes::new()).await.is_err(),
        "sending to oneself fails"
    );

    let outsider = Identity::generate();
    let own_view = Roster::genesis(&outsider, GroupId::new("conf-mesh").unwrap())
        .with_member(&outsider, ids[1].public())
        .unwrap();
    let stranger = h
        .join(outsider.clone(), RosterHandle::new(own_view).unwrap())
        .await;
    let _ = stranger
        .send(&b.local(), "chan/a", Bytes::from_static(b"intruder"))
        .await;
    assert!(
        next(&mut on_a, quiet).await.is_none(),
        "an outsider's messages never arrive"
    );
    assert!(
        !b.peers().await.unwrap().contains(&outsider.node_id()),
        "an outsider is never a peer"
    );

    let mut tasks = Vec::new();
    for sender in [a.clone(), c.clone(), d.clone()] {
        let to = b.local();
        tasks.push(tokio::spawn(async move {
            for i in 0..50u8 {
                sender
                    .send(&to, "chan/a", Bytes::from(vec![i]))
                    .await
                    .unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let mut last = std::collections::HashMap::new();
    for _ in 0..150 {
        let env = next(&mut on_a, wait)
            .await
            .expect("all concurrent messages arrive");
        let prev = last.insert(env.from.clone(), env.payload[0]);
        if let Some(p) = prev {
            assert_eq!(
                env.payload[0],
                p + 1,
                "order per sender holds under concurrency"
            );
        } else {
            assert_eq!(env.payload[0], 0);
        }
    }

    let revoked = roster.without_member(&ids[0], &ids[2].public()).unwrap();
    for (i, handle) in handles.iter().enumerate() {
        if i != 2 {
            handle.update(revoked.clone()).unwrap();
        }
    }
    let _ = c
        .send(&b.local(), "chan/a", Bytes::from_static(b"revoked"))
        .await;
    a.send(&b.local(), "chan/a", Bytes::from_static(b"member"))
        .await
        .unwrap();
    let env = next(&mut on_a, wait).await.unwrap();
    assert_eq!(
        &env.payload[..],
        b"member",
        "a revoked member's messages are dropped"
    );
    assert!(next(&mut on_a, quiet).await.is_none());
    assert!(
        !b.peers().await.unwrap().contains(&c.local()),
        "a revoked member is not a peer"
    );
}
