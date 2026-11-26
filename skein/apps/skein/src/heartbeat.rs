use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use baton_core::{GroupId, NodeId, Timestamp};
use baton_lease::Liveness;
use baton_lease_cas::CasLiveness;
use baton_state::{Expect, RecordName, StateError, StateStore};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

const RECORD: &str = "skein/heartbeat";
const MAX_RECORD: usize = 256;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Agreed {
    v: u8,
    heartbeat_ms: u64,
}

fn encode(heartbeat_ms: u64) -> Bytes {
    Bytes::from(serde_json::to_vec(&Agreed { v: 1, heartbeat_ms }).expect("plain record"))
}

fn decode(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > MAX_RECORD {
        return None;
    }
    let a: Agreed = serde_json::from_slice(bytes).ok()?;
    (a.v == 1 && a.heartbeat_ms > 0).then_some(a.heartbeat_ms)
}

/// Makes sure every node heartbeating in `group` of `state` uses the same heartbeat interval, so
/// that no node judges another dead between its heartbeats.
///
/// The interval agreed on is kept in the record `skein/heartbeat` of `group`. When it is missing
/// or unreadable, this node's interval becomes the agreed one. When it differs from this node's,
/// the node watches heartbeats for three of the longer interval: if any other node heartbeats in
/// that time, it fails; otherwise this node's interval becomes the agreed one.
pub(crate) async fn agree(
    state: Arc<dyn StateStore>,
    group: &GroupId,
    node: &NodeId,
    heartbeat: Duration,
) -> anyhow::Result<()> {
    let own = (heartbeat.as_millis() as u64).max(1);
    let name = RecordName::new(RECORD).expect("constant");
    loop {
        let current = state
            .get(group, &name)
            .await
            .context("reading the agreed heartbeat interval")?;
        let expect = match current {
            None => Expect::Absent,
            Some((bytes, version)) => match decode(&bytes) {
                Some(agreed) if agreed == own => return Ok(()),
                Some(agreed) => {
                    let others = live_others(state.clone(), group, node, own.max(agreed)).await?;
                    if !others.is_empty() {
                        bail!(
                            "engine.heartbeat_secs differs between nodes sharing this store: \
                             {own} ms here, {agreed} ms on the running nodes {}; every node must \
                             use the same value (stop all nodes to change it)",
                            others.join(", ")
                        );
                    }
                    Expect::Version(version)
                }
                None => Expect::Version(version),
            },
        };
        match state.put(group, &name, encode(own), expect).await {
            Ok(_) => return Ok(()),
            Err(StateError::Conflict) => continue,
            Err(e) => return Err(e).context("recording the agreed heartbeat interval"),
        }
    }
}

async fn live_others(
    state: Arc<dyn StateStore>,
    group: &GroupId,
    node: &NodeId,
    interval_ms: u64,
) -> anyhow::Result<Vec<String>> {
    let window = interval_ms.saturating_mul(3);
    let probe = CasLiveness::new(state, window / 2);
    probe
        .alive(group, Timestamp::now())
        .await
        .context("watching heartbeats")?;
    tokio::time::sleep(Duration::from_millis(window)).await;
    let alive = probe
        .alive(group, Timestamp::now())
        .await
        .context("watching heartbeats")?;
    Ok(alive
        .into_iter()
        .filter(|p| &p.node != node)
        .map(|p| p.node.to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use baton_state_memory::MemoryState;

    use super::*;

    fn nodes() -> GroupId {
        GroupId::new(skein_engine::NODES_GROUP).unwrap()
    }

    fn id(s: &str) -> NodeId {
        NodeId::new(s).unwrap()
    }

    async fn agreed(state: &Arc<dyn StateStore>) -> Option<u64> {
        let name = RecordName::new(RECORD).unwrap();
        decode(&state.get(&nodes(), &name).await.unwrap()?.0)
    }

    #[tokio::test]
    async fn the_first_node_sets_the_interval_and_equal_nodes_agree() {
        let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
        agree(state.clone(), &nodes(), &id("a"), Duration::from_millis(30))
            .await
            .unwrap();
        assert_eq!(agreed(&state).await, Some(30));
        agree(state.clone(), &nodes(), &id("b"), Duration::from_millis(30))
            .await
            .unwrap();
        assert_eq!(agreed(&state).await, Some(30));
    }

    #[tokio::test]
    async fn a_node_with_another_interval_refuses_to_join_live_nodes() {
        let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
        agree(state.clone(), &nodes(), &id("a"), Duration::from_millis(30))
            .await
            .unwrap();
        let liveness = CasLiveness::new(state.clone(), 90);
        let profile = skein_engine::node_profile(id("a"), 1, true);
        let beating = tokio::spawn(async move {
            loop {
                liveness
                    .heartbeat(&nodes(), &profile, Timestamp::now())
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        });
        for mine in [5, 60] {
            let refused = agree(
                state.clone(),
                &nodes(),
                &id("b"),
                Duration::from_millis(mine),
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(refused.contains("heartbeat_secs"), "{refused}");
            assert!(refused.contains(" a"), "{refused}");
        }
        assert_eq!(agreed(&state).await, Some(30), "the agreed value stays");
        beating.abort();
    }

    #[tokio::test]
    async fn the_interval_changes_once_no_node_runs_the_old_one() {
        let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
        agree(state.clone(), &nodes(), &id("a"), Duration::from_millis(20))
            .await
            .unwrap();
        CasLiveness::new(state.clone(), 60)
            .heartbeat(
                &nodes(),
                &skein_engine::node_profile(id("a"), 1, true),
                Timestamp::now(),
            )
            .await
            .unwrap();
        CasLiveness::new(state.clone(), 60)
            .heartbeat(
                &nodes(),
                &skein_engine::node_profile(id("b"), 1, true),
                Timestamp::now(),
            )
            .await
            .unwrap();
        agree(state.clone(), &nodes(), &id("b"), Duration::from_millis(40))
            .await
            .unwrap();
        assert_eq!(agreed(&state).await, Some(40));
    }

    #[tokio::test]
    async fn a_forged_or_oversized_record_is_replaced() {
        let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
        let name = RecordName::new(RECORD).unwrap();
        for bad in [
            Bytes::from_static(b"{\"v\":1,\"heartbeat_ms\":0}"),
            Bytes::from_static(b"{\"v\":2,\"heartbeat_ms\":5}"),
            Bytes::from_static(b"not json"),
            Bytes::from(vec![b' '; MAX_RECORD + 1]),
        ] {
            state.put(&nodes(), &name, bad, Expect::Any).await.unwrap();
            agree(state.clone(), &nodes(), &id("a"), Duration::from_millis(25))
                .await
                .unwrap();
            assert_eq!(agreed(&state).await, Some(25));
        }
    }
}
