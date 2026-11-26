use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use baton_core::{GroupId, LeaseKey, NodeId};
use baton_identity::RosterHandle;
use baton_lease::record::LeaseRecord;
use baton_state::{Expect, RecordName, StateError, StateStore};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Ordered by round, then by proposer, so two proposers never share a ballot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Ballot {
    pub round: u64,
    pub proposer: NodeId,
}

/// The replicated value of one lease key: the lease record, if any.
pub(crate) type Register = Option<LeaseRecord>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Reply {
    Promise(Option<(Ballot, Register)>),
    Accepted,
    Nack(Ballot),
    Veto,
}

/// How far above the binding promise an acceptor lets a ballot jump; honest proposers climb one
/// round at a time, so a member cannot burn the ballot space in one message.
pub(crate) const MAX_JUMP: u64 = 1 << 20;

/// How many keys an acceptor keeps in memory before dropping idle ones (they reload from the
/// store).
const CACHE_MAX: usize = 10_000;

/// Decides whether a change from the last accepted register to a proposed one may happen.
pub(crate) type Allow<'a> = &'a (dyn Fn(&Register, &Register) -> bool + Send + Sync);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Slot {
    promised: Option<Ballot>,
    accepted: Option<(Ballot, Register)>,
}

/// The acceptor role for every key of one group. Every promise and acceptance is written to the
/// state store, and only after the store confirmed it durable does the acceptor answer, so a
/// restarted node never forgets a promise and two leaders can never come out of one key.
pub(crate) struct Acceptor {
    group: GroupId,
    state: Arc<dyn StateStore>,
    roster: RosterHandle,
    cache: Mutex<HashMap<LeaseKey, Arc<tokio::sync::Mutex<Option<Slot>>>>>,
}

fn name(key: &LeaseKey) -> RecordName {
    RecordName::new(format!("quorum/{key}")).expect("every lease key is a valid record segment")
}

impl Acceptor {
    pub fn new(group: GroupId, state: Arc<dyn StateStore>, roster: RosterHandle) -> Self {
        Self {
            group,
            state,
            roster,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn slot(&self, key: &LeaseKey) -> Arc<tokio::sync::Mutex<Option<Slot>>> {
        let mut cache = self.cache.lock().expect("acceptor cache");
        if cache.len() >= CACHE_MAX && !cache.contains_key(key) {
            cache.retain(|_, slot| Arc::strong_count(slot) > 1);
        }
        cache.entry(key.clone()).or_default().clone()
    }

    /// The promise that still binds: one made to a proposer that has left the roster no longer
    /// holds anyone back.
    fn binding(&self, s: &Slot) -> Option<Ballot> {
        let roster = self.roster.current();
        s.promised
            .clone()
            .filter(|p| roster.contains_node(&p.proposer))
    }

    fn too_far(&self, s: &Slot, ballot: &Ballot) -> bool {
        let floor = self.binding(s).map_or(0, |p| p.round);
        ballot.round > floor.saturating_add(MAX_JUMP)
    }

    async fn load(&self, key: &LeaseKey, cached: &mut Option<Slot>) -> Result<Slot, StateError> {
        if let Some(s) = cached {
            return Ok(s.clone());
        }
        let s = match self.state.get(&self.group, &name(key)).await? {
            None => Slot::default(),
            Some((bytes, _)) => postcard::from_bytes(&bytes).map_err(StateError::backend)?,
        };
        *cached = Some(s.clone());
        Ok(s)
    }

    async fn store(
        &self,
        key: &LeaseKey,
        cached: &mut Option<Slot>,
        s: Slot,
    ) -> Result<(), StateError> {
        let bytes = Bytes::from(postcard::to_stdvec(&s).expect("a slot always serializes"));
        self.state
            .put(&self.group, &name(key), bytes, Expect::Any)
            .await?;
        *cached = Some(s);
        Ok(())
    }

    /// `None` when the state store failed or the ballot jumps too far: the acceptor then does not
    /// answer at all.
    pub async fn prepare(&self, key: &LeaseKey, ballot: &Ballot) -> Option<Reply> {
        let slot = self.slot(key);
        let mut cached = slot.lock().await;
        let mut s = self.load(key, &mut cached).await.ok()?;
        if self.too_far(&s, ballot) {
            return None;
        }
        match self.binding(&s) {
            Some(p) if &p >= ballot => Some(Reply::Nack(p)),
            _ => {
                s.promised = Some(ballot.clone());
                let accepted = s.accepted.clone();
                self.store(key, &mut cached, s).await.ok()?;
                Some(Reply::Promise(accepted))
            }
        }
    }

    /// `None` when the state store failed or the ballot jumps too far. `allow` sees the register
    /// this acceptor last accepted and the proposed one, under the key's lock, and may veto.
    pub async fn accept(
        &self,
        key: &LeaseKey,
        ballot: &Ballot,
        value: Register,
        allow: Allow<'_>,
    ) -> Option<Reply> {
        let slot = self.slot(key);
        let mut cached = slot.lock().await;
        let mut s = self.load(key, &mut cached).await.ok()?;
        if self.too_far(&s, ballot) {
            return None;
        }
        let previous = s.accepted.as_ref().and_then(|(_, v)| v.clone());
        match self.binding(&s) {
            Some(p) if &p > ballot => Some(Reply::Nack(p)),
            _ if !allow(&previous, &value) => Some(Reply::Veto),
            _ => {
                s.promised = Some(ballot.clone());
                s.accepted = Some((ballot.clone(), value));
                self.store(key, &mut cached, s).await.ok()?;
                Some(Reply::Accepted)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use baton_identity::{Identity, Roster};
    use baton_state_memory::MemoryState;

    use super::*;

    fn member(seed: u8) -> NodeId {
        Identity::from_secret_bytes(&[seed; 32]).node_id()
    }

    fn roster() -> RosterHandle {
        let a = Identity::from_secret_bytes(&[1; 32]);
        let mut r = Roster::genesis(&a, GroupId::new("g").unwrap());
        for seed in [2u8, 3] {
            r = r
                .with_member(&a, Identity::from_secret_bytes(&[seed; 32]).public())
                .unwrap();
        }
        RosterHandle::new(r).unwrap()
    }

    fn b(round: u64, seed: u8) -> Ballot {
        Ballot {
            round,
            proposer: member(seed),
        }
    }

    fn acceptor(state: Arc<dyn StateStore>) -> Acceptor {
        Acceptor::new(GroupId::new("g").unwrap(), state, roster())
    }

    const ALLOW: Allow<'static> = &|_, _| true;

    #[tokio::test]
    async fn promises_only_grow_and_survive_a_restart() {
        let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
        let k = LeaseKey::new("k").unwrap();
        let acc = acceptor(state.clone());
        assert!(matches!(
            acc.prepare(&k, &b(1, 1)).await,
            Some(Reply::Promise(None))
        ));
        assert!(matches!(
            acc.prepare(&k, &b(1, 1)).await,
            Some(Reply::Nack(_))
        ));
        let (x, y) = (b(1, 1), b(1, 2));
        let (lo, hi) = if x < y { (x, y) } else { (y, x) };
        let acc2 = acceptor(Arc::new(MemoryState::new()));
        assert!(matches!(
            acc2.prepare(&k, &lo).await,
            Some(Reply::Promise(None))
        ));
        assert!(matches!(
            acc2.prepare(&k, &hi).await,
            Some(Reply::Promise(None))
        ));
        assert!(matches!(
            acc2.accept(&k, &lo, None, ALLOW).await,
            Some(Reply::Nack(_))
        ));
        assert!(matches!(
            acc2.accept(&k, &hi, None, ALLOW).await,
            Some(Reply::Accepted)
        ));

        assert!(matches!(
            acc.accept(&k, &b(1, 1), None, ALLOW).await,
            Some(Reply::Accepted)
        ));
        let restarted = acceptor(state);
        assert!(
            matches!(restarted.prepare(&k, &b(1, 1)).await, Some(Reply::Nack(_))),
            "a restarted acceptor remembers its promise"
        );
        match restarted.prepare(&k, &b(2, 2)).await {
            Some(Reply::Promise(Some((ballot, None)))) => assert_eq!(ballot, b(1, 1)),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_ballot_cannot_jump_and_departed_proposers_do_not_bind() {
        let k = LeaseKey::new("k").unwrap();
        let acc = acceptor(Arc::new(MemoryState::new()));
        assert!(
            acc.prepare(&k, &b(u64::MAX, 1)).await.is_none(),
            "a maximal ballot gets no promise"
        );
        assert!(acc.prepare(&k, &b(MAX_JUMP + 1, 1)).await.is_none());
        assert!(matches!(
            acc.prepare(&k, &b(MAX_JUMP, 1)).await,
            Some(Reply::Promise(None))
        ));
        let k2 = LeaseKey::new("k2").unwrap();
        assert!(matches!(
            acc.prepare(&k2, &b(100, 9)).await,
            Some(Reply::Promise(None))
        ));
        assert!(
            matches!(acc.prepare(&k2, &b(1, 2)).await, Some(Reply::Promise(None))),
            "a promise to a proposer outside the roster does not bind"
        );
    }

    #[tokio::test]
    async fn an_acceptor_can_veto_a_change() {
        let k = LeaseKey::new("k").unwrap();
        let acc = acceptor(Arc::new(MemoryState::new()));
        assert!(matches!(
            acc.prepare(&k, &b(1, 1)).await,
            Some(Reply::Promise(None))
        ));
        let never: Allow<'static> = &|_, _| false;
        assert!(matches!(
            acc.accept(&k, &b(1, 1), None, never).await,
            Some(Reply::Veto)
        ));
    }

    struct Broken;

    #[async_trait::async_trait]
    impl StateStore for Broken {
        async fn get(
            &self,
            _: &GroupId,
            _: &RecordName,
        ) -> Result<Option<(Bytes, baton_state::Version)>, StateError> {
            Ok(None)
        }
        async fn put(
            &self,
            _: &GroupId,
            _: &RecordName,
            _: Bytes,
            _: Expect,
        ) -> Result<baton_state::Version, StateError> {
            Err(StateError::backend("disk full"))
        }
        async fn delete(&self, _: &GroupId, _: &RecordName, _: Expect) -> Result<(), StateError> {
            Ok(())
        }
        async fn list(
            &self,
            _: &GroupId,
            _: &RecordName,
            _: Option<&RecordName>,
            _: usize,
        ) -> Result<Vec<RecordName>, StateError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn an_acceptor_that_cannot_persist_does_not_answer() {
        let acc = acceptor(Arc::new(Broken));
        let k = LeaseKey::new("k").unwrap();
        assert!(acc.prepare(&k, &b(1, 1)).await.is_none());
        assert!(acc.accept(&k, &b(1, 1), None, ALLOW).await.is_none());
    }

    #[tokio::test]
    async fn corrupted_acceptor_state_answers_nothing() {
        let state = Arc::new(MemoryState::new());
        let k = LeaseKey::new("k").unwrap();
        state.tamper(
            &GroupId::new("g").unwrap(),
            &name(&k),
            Bytes::from_static(b"\xff\xff\xff"),
        );
        let acc = acceptor(state);
        assert!(acc.prepare(&k, &b(1, 1)).await.is_none());
    }
}
