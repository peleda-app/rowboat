//! The lease time-to-live batond told clients in earlier runs, so lowering it across a restart is
//! safe.

use std::path::Path;

use crate::BatondError;

/// The file inside the data directory.
pub const TTL_FILE: &str = "lease.ttl";

/// What the file keeps: the time-to-live advertised by the last run, and an older, larger one
/// some holder may still believe until `floor_until_ms` (wall clock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// The time-to-live the last run advertised.
    pub advertised: u64,
    /// The largest time-to-live the last run still honored.
    pub floor: u64,
    /// Until when (milliseconds since the epoch) a holder may believe `floor`.
    pub floor_until_ms: i64,
}

impl Record {
    fn encode(&self) -> String {
        format!(
            "{} {} {}\n",
            self.advertised, self.floor, self.floor_until_ms
        )
    }

    fn decode(raw: &str) -> Option<Self> {
        let mut parts = raw.split_whitespace();
        let r = Self {
            advertised: parts.next()?.parse().ok()?,
            floor: parts.next()?.parse().ok()?,
            floor_until_ms: parts.next()?.parse().ok()?,
        };
        parts.next().is_none().then_some(r)
    }
}

/// The time-to-live an earlier run may have told holders that still believe it at `now_ms`:
/// the last run's advertised one, or the older floor it honored while that has not run out.
pub fn previous(record: Option<Record>, now_ms: i64) -> u64 {
    record.map_or(0, |r| {
        let floor = if now_ms < r.floor_until_ms {
            r.floor
        } else {
            0
        };
        r.advertised.max(floor)
    })
}

/// Reads the record at `path`, returns the previous time-to-live for a run that advertises
/// `ttl_ms` from `now_ms`, and records that run (`0600`, written to a temporary file and renamed).
/// An unreadable or malformed record is refused, so a damaged file never lowers the floor.
pub fn advance(path: &Path, ttl_ms: u64, now_ms: i64) -> Result<u64, BatondError> {
    let record = match std::fs::read_to_string(path) {
        Ok(raw) => Some(Record::decode(&raw).ok_or_else(|| {
            BatondError::Config(format!(
                "{} is not a lease time-to-live record",
                path.display()
            ))
        })?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let previous = previous(record, now_ms);
    let next = Record {
        advertised: ttl_ms,
        floor: previous,
        floor_until_ms: now_ms.saturating_add(i64::try_from(previous).unwrap_or(i64::MAX)),
    };
    let tmp = path.with_extension("ttl.tmp");
    std::fs::write(&tmp, next.encode())?;
    crate::private_file(&tmp)?;
    std::fs::rename(&tmp, path)?;
    Ok(previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lowered_ttl_honors_the_old_one_until_no_holder_can_believe_it() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(TTL_FILE);
        assert_eq!(advance(&p, 15_000, 0).unwrap(), 0, "first run");
        assert_eq!(
            advance(&p, 5_000, 1_000).unwrap(),
            15_000,
            "lowered: the old one holds"
        );
        assert_eq!(
            advance(&p, 5_000, 2_000).unwrap(),
            15_000,
            "a quick second restart still honors it"
        );
        assert_eq!(
            advance(&p, 5_000, 2_000 + 15_000).unwrap(),
            5_000,
            "once nobody can believe 15 s, only the last advertised one counts"
        );
        assert_eq!(advance(&p, 20_000, 30_000).unwrap(), 5_000);
    }

    #[test]
    fn a_damaged_record_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(TTL_FILE);
        for bad in ["", "1 2", "1 2 3 4", "x 2 3", "-1 2 3"] {
            std::fs::write(&p, bad).unwrap();
            assert!(advance(&p, 5_000, 0).is_err(), "{bad:?}");
        }
    }

    proptest::proptest! {
        #[test]
        fn previous_never_forgets_a_ttl_a_holder_may_believe(
            advertised in 0u64..100_000,
            floor in 0u64..100_000,
            until in 0i64..1_000_000,
            now in 0i64..1_000_000,
        ) {
            let r = Record { advertised, floor, floor_until_ms: until };
            proptest::prop_assume!(Record::decode(&r.encode()) == Some(r));
            let p = previous(Some(r), now);
            proptest::prop_assert!(p >= advertised);
            if now < until {
                proptest::prop_assert!(p >= floor);
            }
        }
    }
}
