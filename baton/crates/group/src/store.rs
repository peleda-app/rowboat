//! A group log kept in a `StateStore`: entry `seq` lives at `group/{seq}` (zero-padded), written
//! with `put_if_absent`, so two writers can never both append at one position; the store orders
//! them (on object storage with honest conditional writes, the store is the arbiter).

use std::sync::Arc;

use baton_state::{Expect, RecordName, StateError, StateStore};
use bytes::Bytes;

use crate::{Entry, GroupError, GroupLog};

fn name(seq: u64) -> RecordName {
    RecordName::new(format!("group/{seq:020}")).expect("a valid name")
}

fn backend(e: StateError) -> GroupError {
    GroupError::Backend(e.to_string())
}

/// Writes `entry` at its position. Fails with [`GroupError::Fork`] when another entry is already
/// there (someone appended first: reload, re-apply, retry).
pub async fn append(store: &Arc<dyn StateStore>, entry: &Entry) -> Result<(), GroupError> {
    match store
        .put(
            entry.group(),
            &name(entry.seq()),
            Bytes::from(entry.encode()),
            Expect::Absent,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(StateError::Conflict) => match store
            .get(entry.group(), &name(entry.seq()))
            .await
            .map_err(backend)?
        {
            Some((bytes, _)) if bytes[..] == entry.encode()[..] => Ok(()),
            _ => Err(GroupError::Fork),
        },
        Err(e) => Err(backend(e)),
    }
}

/// Writes every entry of `log` that the store does not have yet.
pub async fn save(store: &Arc<dyn StateStore>, log: &GroupLog) -> Result<(), GroupError> {
    for e in log.entries() {
        append(store, e).await?;
    }
    Ok(())
}

/// Reads and verifies the whole log of `group` from genesis. Paging continues until an empty
/// page; a gap in the sequence or any invalid entry fails the load.
pub async fn load(
    store: &Arc<dyn StateStore>,
    group: &baton_core::GroupId,
) -> Result<GroupLog, GroupError> {
    let prefix = RecordName::new("group").expect("constant");
    let mut names = Vec::new();
    let mut after: Option<RecordName> = None;
    loop {
        let page = store
            .list(group, &prefix, after.as_ref(), 1000)
            .await
            .map_err(backend)?;
        let Some(last) = page.last().cloned() else {
            break;
        };
        names.extend(page);
        after = Some(last);
    }
    let mut entries = Vec::with_capacity(names.len());
    for (i, n) in names.iter().enumerate() {
        if n != &name(i as u64) {
            return Err(GroupError::Chain);
        }
        let (bytes, _) = store
            .get(group, n)
            .await
            .map_err(backend)?
            .ok_or(GroupError::Chain)?;
        entries.push(Entry::decode(&bytes)?);
    }
    let log = GroupLog::verify(entries)?;
    if log.state().group() != group {
        return Err(GroupError::Chain);
    }
    Ok(log)
}

/// [`load`], refusing a log whose genesis is not `genesis_hash` (the fingerprint from the recovery
/// sheet), so a store cannot hand a fresh restore a forged group.
pub async fn load_expecting(
    store: &Arc<dyn StateStore>,
    group: &baton_core::GroupId,
    genesis_hash: [u8; 32],
) -> Result<GroupLog, GroupError> {
    let log = load(store, group).await?;
    if log.genesis_hash() != genesis_hash {
        return Err(GroupError::Fork);
    }
    Ok(log)
}
