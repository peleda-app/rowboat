//! An in-process gate for one remote key, such as a mailbox at a provider: at most N requests
//! at a time, and a pause every holder respects once the server asks to wait.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, sleep_until};

/// Concurrent requests a new [`Throttle`] allows: Microsoft Graph's limit per app and mailbox.
pub const DEFAULT_LIMIT: usize = 4;

/// The longest pause a [`Throttle`] records, however long the server asked for.
pub const MAX_PAUSE: Duration = Duration::from_secs(600);

struct Inner {
    slots: Arc<Semaphore>,
    until: Mutex<Option<Instant>>,
    max_pause: Duration,
}

/// A gate for one key. Clones share the same slots and pause, so every provider handed a clone
/// waits for the others. Never fails and never times out on its own: a caller that needs a
/// deadline wraps [`Throttle::acquire`] in one.
#[derive(Clone)]
pub struct Throttle {
    inner: Arc<Inner>,
}

impl Default for Throttle {
    fn default() -> Self {
        Self::new(DEFAULT_LIMIT)
    }
}

impl std::fmt::Debug for Throttle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Throttle")
            .field("available", &self.inner.slots.available_permits())
            .field("paused_until", &self.paused_until())
            .finish()
    }
}

impl Throttle {
    /// A gate with `limit` slots (at least one) and pauses capped at [`MAX_PAUSE`].
    pub fn new(limit: usize) -> Self {
        Self::with_max_pause(limit, MAX_PAUSE)
    }

    /// A gate with `limit` slots (at least one) and pauses capped at `max_pause`.
    pub fn with_max_pause(limit: usize, max_pause: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                slots: Arc::new(Semaphore::new(limit.max(1))),
                until: Mutex::new(None),
                max_pause,
            }),
        }
    }

    /// Waits until no pause is in effect and a slot is free, then holds that slot until the
    /// [`Permit`] drops. A pause recorded while waiting for a slot is respected too: the permit
    /// is only handed out when no pause is in effect at that moment. Waiters are not ordered.
    pub async fn acquire(&self) -> Permit {
        loop {
            if let Some(until) = self.paused_until() {
                sleep_until(until).await;
                continue;
            }
            let slot = self
                .inner
                .slots
                .clone()
                .acquire_owned()
                .await
                .expect("the semaphore is never closed");
            if self.paused_until().is_none() {
                return Permit { _slot: slot };
            }
        }
    }

    /// Records that the server asked to wait `wait` from now. Pauses only ever extend: a shorter
    /// one than in effect changes nothing. Capped at the throttle's maximum pause.
    pub fn pause(&self, wait: Duration) {
        let now = Instant::now();
        self.extend(now + wait.min(self.inner.max_pause), now);
    }

    /// Records that the server asked to wait until `until`. Same rules as [`Throttle::pause`].
    pub fn pause_until(&self, until: Instant) {
        let now = Instant::now();
        self.extend(until.min(now + self.inner.max_pause), now);
    }

    fn extend(&self, until: Instant, now: Instant) {
        if until <= now {
            return;
        }
        let mut current = self.inner.until.lock().expect("never poisoned");
        if current.is_none_or(|c| c < until) {
            *current = Some(until);
        }
    }

    /// When the pause in effect ends; `None` when there is none.
    pub fn paused_until(&self) -> Option<Instant> {
        let until = *self.inner.until.lock().expect("never poisoned");
        until.filter(|u| *u > Instant::now())
    }

    /// Slots free right now.
    pub fn available(&self) -> usize {
        self.inner.slots.available_permits()
    }

    fn idle(&self) -> bool {
        Arc::strong_count(&self.inner) == 1 && self.paused_until().is_none()
    }

    /// Whether `other` is a clone of this throttle.
    pub fn same(&self, other: &Throttle) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

/// One slot of a [`Throttle`], held until dropped.
#[must_use = "the slot is released as soon as the permit drops"]
pub struct Permit {
    _slot: OwnedSemaphorePermit,
}

struct Registry {
    map: HashMap<String, Throttle>,
    prune_at: usize,
}

const PRUNE_FLOOR: usize = 64;

/// Throttles by key, shared by clones: the same key gives clones of the same [`Throttle`] for as
/// long as anyone holds one or a pause is in effect. Entries nobody holds and that are not
/// paused are dropped once the registry grows, so its size follows the keys in use.
#[derive(Clone)]
pub struct Throttles {
    registry: Arc<Mutex<Registry>>,
    limit: usize,
    max_pause: Duration,
}

impl Default for Throttles {
    fn default() -> Self {
        Self::new(DEFAULT_LIMIT)
    }
}

impl Throttles {
    /// A registry whose throttles have `limit` slots and pauses capped at [`MAX_PAUSE`].
    pub fn new(limit: usize) -> Self {
        Self::with_max_pause(limit, MAX_PAUSE)
    }

    /// A registry whose throttles have `limit` slots and pauses capped at `max_pause`.
    pub fn with_max_pause(limit: usize, max_pause: Duration) -> Self {
        Self {
            registry: Arc::new(Mutex::new(Registry {
                map: HashMap::new(),
                prune_at: PRUNE_FLOOR,
            })),
            limit,
            max_pause,
        }
    }

    /// The throttle for `key`, created on first use.
    pub fn get(&self, key: &str) -> Throttle {
        let mut registry = self.registry.lock().expect("never poisoned");
        if let Some(found) = registry.map.get(key) {
            return found.clone();
        }
        if registry.map.len() >= registry.prune_at {
            registry.map.retain(|_, t| !t.idle());
            registry.prune_at = (registry.map.len() * 2).max(PRUNE_FLOOR);
        }
        let throttle = Throttle::with_max_pause(self.limit, self.max_pause);
        registry.map.insert(key.to_owned(), throttle.clone());
        throttle
    }

    /// Keys currently kept, including idle ones not yet dropped.
    pub fn len(&self) -> usize {
        self.registry.lock().expect("never poisoned").map.len()
    }

    /// Whether no key is kept.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests;
