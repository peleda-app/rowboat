use std::collections::{BTreeSet, HashMap};

use baton_mailbox::BoxId;

use crate::DropError;

/// Nonces seen within the freshness window, bounded in all and per box: when full of entries
/// that are still fresh it refuses new requests instead of forgetting one (forgetting would allow a
/// replay). The per-box share keeps one box's requests from making every other box busy.
pub(crate) struct ReplayCache {
    seen: HashMap<[u8; 32], (i64, BoxId)>,
    by_expiry: BTreeSet<(i64, [u8; 32])>,
    per_box: HashMap<BoxId, usize>,
    capacity: usize,
    box_capacity: usize,
}

impl ReplayCache {
    pub(crate) fn new(capacity: usize, box_capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            by_expiry: BTreeSet::new(),
            per_box: HashMap::new(),
            capacity,
            box_capacity,
        }
    }

    /// Records `key` for box `owner` until `expires_at`, unless it is already recorded, the cache
    /// is full or the box has used its share.
    pub(crate) fn insert(
        &mut self,
        key: [u8; 32],
        owner: BoxId,
        expires_at: i64,
        now: i64,
    ) -> Result<(), DropError> {
        while let Some(&(exp, k)) = self.by_expiry.first() {
            if exp >= now {
                break;
            }
            self.by_expiry.pop_first();
            if let Some((_, b)) = self.seen.remove(&k)
                && let Some(n) = self.per_box.get_mut(&b)
            {
                *n -= 1;
                if *n == 0 {
                    self.per_box.remove(&b);
                }
            }
        }
        if self.seen.contains_key(&key) {
            return Err(DropError::Replayed);
        }
        let used = self.per_box.get(&owner).copied().unwrap_or(0);
        if self.seen.len() >= self.capacity || used >= self.box_capacity {
            return Err(DropError::Busy);
        }
        self.seen.insert(key, (expires_at, owner));
        self.by_expiry.insert((expires_at, key));
        *self.per_box.entry(owner).or_insert(0) += 1;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: BoxId = BoxId([1; 32]);
    const B: BoxId = BoxId([2; 32]);

    #[test]
    fn refuses_repeats_until_expiry_and_never_evicts_fresh_entries() {
        let mut c = ReplayCache::new(2, 2);
        c.insert([1; 32], A, 100, 0).unwrap();
        assert_eq!(c.insert([1; 32], A, 100, 50), Err(DropError::Replayed));
        c.insert([2; 32], B, 200, 50).unwrap();
        assert_eq!(c.insert([3; 32], B, 300, 60), Err(DropError::Busy));
        assert_eq!(c.insert([1; 32], A, 100, 100), Err(DropError::Replayed));
        c.insert([3; 32], A, 300, 101).unwrap();
        assert_eq!(c.len(), 2);
        c.insert([1; 32], A, 400, 301).unwrap();
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn one_box_never_takes_more_than_its_share() {
        let mut c = ReplayCache::new(10, 3);
        for k in 0..3u8 {
            c.insert([k; 32], A, 100, 0).unwrap();
        }
        assert_eq!(c.insert([9; 32], A, 100, 0), Err(DropError::Busy));
        for k in 10..17u8 {
            c.insert([k; 32], B, 100, 0).unwrap_or(());
        }
        assert_eq!(
            c.insert([99; 32], A, 200, 101),
            Ok(()),
            "expiry frees the share"
        );
        assert_eq!(c.per_box.get(&A), Some(&1));
    }
}
