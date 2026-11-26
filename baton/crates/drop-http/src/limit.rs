//! Per-client rate and concurrency limits with bounded memory.

use std::collections::HashMap;
use std::net::IpAddr;

/// Per-client limits. A client is an IPv4 address or an IPv6 /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Requests per second a client may sustain (default 20).
    pub per_second: u32,
    /// Requests a client may make at once after being idle (default 100).
    pub burst: u32,
    /// Requests of one client in flight at once, long polls included (default 16).
    pub in_flight: u32,
    /// Long polls of one client waiting at once; its further takes return at once (default 4).
    pub polls: u32,
    /// Clients tracked at once; beyond this, idle entries are dropped, and if none is idle new
    /// clients share one overflow budget (default 65,536, a few MiB).
    pub max_tracked: usize,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            per_second: 20,
            burst: 100,
            in_flight: 16,
            polls: 4,
            max_tracked: 65_536,
        }
    }
}

/// The key a client is limited under.
pub(crate) fn client_key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => u128::from(v4.to_ipv6_mapped()),
            None => u128::from(v6) & !u128::from(u64::MAX),
        },
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    milli: u64,
    at: i64,
    in_flight: u32,
    polls: u32,
}

/// Where an admitted request was counted, to release it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Client(u128),
    Overflow,
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    Rate,
    InFlight,
}

/// Token buckets per client in milli-requests, plus in-flight counters.
pub(crate) struct Limiter {
    limit: RateLimit,
    table: HashMap<u128, Bucket>,
    overflow: Bucket,
    last_prune: i64,
}

impl Limiter {
    pub(crate) fn new(limit: RateLimit) -> Self {
        Self {
            table: HashMap::new(),
            overflow: Bucket {
                milli: Self::cap_of(&limit),
                at: i64::MIN,
                in_flight: 0,
                polls: 0,
            },
            last_prune: i64::MIN,
            limit,
        }
    }

    fn cap_of(limit: &RateLimit) -> u64 {
        u64::from(limit.burst).saturating_mul(1000)
    }

    fn refilled(&self, b: &Bucket, now: i64) -> u64 {
        if b.at == i64::MIN {
            return Self::cap_of(&self.limit);
        }
        let elapsed = now.saturating_sub(b.at).max(0) as u64;
        b.milli
            .saturating_add(elapsed.saturating_mul(u64::from(self.limit.per_second)))
            .min(Self::cap_of(&self.limit))
    }

    /// Counts one request of `key` at `now` (ms), or refuses it.
    pub(crate) fn acquire(&mut self, key: u128, now: i64) -> Result<Slot, Refused> {
        let cap = Self::cap_of(&self.limit);
        if !self.table.contains_key(&key) && self.table.len() >= self.limit.max_tracked {
            if now.saturating_sub(self.last_prune) >= 1000 {
                self.last_prune = now;
                let snapshot: Vec<(u128, Bucket)> =
                    self.table.iter().map(|(k, b)| (*k, *b)).collect();
                for (k, b) in snapshot {
                    if b.in_flight == 0 && self.refilled(&b, now) >= cap {
                        self.table.remove(&k);
                    }
                }
            }
            if self.table.len() >= self.limit.max_tracked {
                let mut b = self.overflow;
                let r = self.take(&mut b, now);
                self.overflow = b;
                return r.map(|()| Slot::Overflow);
            }
        }
        let mut b = self.table.get(&key).copied().unwrap_or(Bucket {
            milli: cap,
            at: i64::MIN,
            in_flight: 0,
            polls: 0,
        });
        let r = self.take(&mut b, now);
        self.table.insert(key, b);
        r.map(|()| Slot::Client(key))
    }

    fn take(&self, b: &mut Bucket, now: i64) -> Result<(), Refused> {
        b.milli = self.refilled(b, now);
        b.at = b.at.max(now);
        if b.in_flight >= self.limit.in_flight {
            return Err(Refused::InFlight);
        }
        if b.milli < 1000 {
            return Err(Refused::Rate);
        }
        b.milli -= 1000;
        b.in_flight += 1;
        Ok(())
    }

    /// Ends a request counted at `slot`.
    pub(crate) fn release(&mut self, slot: Slot) {
        match slot {
            Slot::Overflow => self.overflow.in_flight = self.overflow.in_flight.saturating_sub(1),
            Slot::Client(k) => {
                if let Some(b) = self.table.get_mut(&k) {
                    b.in_flight = b.in_flight.saturating_sub(1);
                }
            }
        }
    }

    fn bucket(&mut self, slot: Slot) -> Option<&mut Bucket> {
        match slot {
            Slot::Overflow => Some(&mut self.overflow),
            Slot::Client(k) => self.table.get_mut(&k),
        }
    }

    /// Lets the request counted at `slot` wait as a long poll, unless its client already has its
    /// share of waiting polls.
    pub(crate) fn start_poll(&mut self, slot: Slot) -> bool {
        let limit = self.limit.polls;
        match self.bucket(slot) {
            Some(b) if b.polls < limit => {
                b.polls += 1;
                true
            }
            _ => false,
        }
    }

    /// Ends a long poll started at `slot`.
    pub(crate) fn end_poll(&mut self, slot: Slot) {
        if let Some(b) = self.bucket(slot) {
            b.polls = b.polls.saturating_sub(1);
        }
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.table.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use proptest::prelude::*;

    use super::*;

    fn lim(per_second: u32, burst: u32, in_flight: u32, max_tracked: usize) -> Limiter {
        Limiter::new(RateLimit {
            per_second,
            burst,
            in_flight,
            polls: 2,
            max_tracked,
        })
    }

    fn ip(n: u32) -> u128 {
        client_key(IpAddr::V4(Ipv4Addr::from(n)))
    }

    #[test]
    fn burst_then_refill() {
        let mut l = lim(10, 5, 100, 10);
        for _ in 0..5 {
            let s = l.acquire(ip(1), 0).unwrap();
            l.release(s);
        }
        assert_eq!(l.acquire(ip(1), 0), Err(Refused::Rate));
        assert_eq!(l.acquire(ip(1), 99), Err(Refused::Rate));
        let s = l.acquire(ip(1), 100).unwrap();
        l.release(s);
        assert_eq!(l.acquire(ip(1), 100), Err(Refused::Rate));
        assert!(
            l.acquire(ip(2), 100).is_ok(),
            "other clients are not affected"
        );
    }

    #[test]
    fn a_clock_going_back_never_mints_tokens() {
        let mut l = lim(10, 1, 100, 10);
        let s = l.acquire(ip(1), 1_000_000).unwrap();
        l.release(s);
        assert_eq!(l.acquire(ip(1), 0), Err(Refused::Rate));
        assert_eq!(l.acquire(ip(1), 1_000_050), Err(Refused::Rate));
    }

    #[test]
    fn in_flight_is_capped_and_released() {
        let mut l = lim(1000, 1000, 2, 10);
        let a = l.acquire(ip(1), 0).unwrap();
        let _b = l.acquire(ip(1), 0).unwrap();
        assert_eq!(l.acquire(ip(1), 0), Err(Refused::InFlight));
        l.release(a);
        assert!(l.acquire(ip(1), 0).is_ok());
    }

    #[test]
    fn polls_are_capped_per_client_and_released() {
        let mut l = lim(1000, 1000, 100, 10);
        let a = l.acquire(ip(1), 0).unwrap();
        let b = l.acquire(ip(1), 0).unwrap();
        let c = l.acquire(ip(1), 0).unwrap();
        assert!(l.start_poll(a));
        assert!(l.start_poll(b));
        assert!(!l.start_poll(c), "a third poll of one client does not wait");
        let other = l.acquire(ip(2), 0).unwrap();
        assert!(l.start_poll(other), "other clients have their own share");
        l.end_poll(a);
        assert!(l.start_poll(c));
    }

    #[test]
    fn ipv6_clients_are_their_slash_64() {
        let a = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 9, 9, 9, 9);
        let c = Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1);
        assert_eq!(client_key(a.into()), client_key(b.into()));
        assert_ne!(client_key(a.into()), client_key(c.into()));
        let v4 = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(
            client_key(v4.into()),
            client_key(v4.to_ipv6_mapped().into())
        );
    }

    #[test]
    fn many_clients_stay_within_the_table_and_share_overflow() {
        let mut l = lim(1, 2, 1, 100);
        let mut held = Vec::new();
        for n in 0..100 {
            held.push(l.acquire(ip(n), 0).unwrap());
        }
        assert_eq!(l.tracked(), 100);
        let o = l.acquire(ip(1000), 0).unwrap();
        assert_eq!(o, Slot::Overflow);
        assert_eq!(l.acquire(ip(1001), 0), Err(Refused::InFlight));
        for n in 2000..12_000 {
            let _ = l.acquire(ip(n), 0);
        }
        assert_eq!(
            l.tracked(),
            100,
            "memory stays bounded under an address flood"
        );
        l.release(o);
        for s in held {
            l.release(s);
        }
        assert!(matches!(l.acquire(ip(50_000), 10_000), Ok(Slot::Client(_))));
        assert!(l.tracked() <= 100);
    }

    proptest! {
        #[test]
        fn never_more_than_burst_plus_rate(
            steps in proptest::collection::vec(0i64..50, 1..400),
        ) {
            let mut l = lim(20, 10, 1000, 4);
            let mut now = 0i64;
            let mut ok = 0u64;
            for d in steps {
                now += d;
                if let Ok(s) = l.acquire(ip(7), now) {
                    ok += 1;
                    l.release(s);
                }
            }
            prop_assert!(ok <= 10 + (now as u64 * 20) / 1000 + 1);
        }
    }
}
