use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use skein_core::{AccountId, Event, FencingToken, Seq, TenantId};

use crate::StorageError;
use crate::log::{MAX_SEGMENT_EVENTS, SegmentHeader, decode_segment};

/// The BLAKE3 hash of a stored segment, over its bytes exactly as stored. Written as 64 lowercase
/// hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SegmentHash(pub [u8; 32]);

impl SegmentHash {
    /// The hash of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
}

impl fmt::Display for SegmentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(blake3::Hash::from_bytes(self.0).to_hex().as_str())
    }
}

impl fmt::Debug for SegmentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SegmentHash({self})")
    }
}

impl FromStr for SegmentHash {
    type Err = IntegrityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(IntegrityError::Malformed("segment hash".into()));
        }
        blake3::Hash::from_hex(s)
            .map(|h| Self(*h.as_bytes()))
            .map_err(|_| IntegrityError::Malformed("segment hash".into()))
    }
}

impl Serialize for SegmentHash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SegmentHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Names one stored segment and pins its bytes: the events `start..=end` written under `fence`,
/// whose stored bytes hash to `hash`. Any source can be asked for a segment by this reference, and
/// [`verify_segment`] accepts only the exact bytes it names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentRef {
    /// The first event in the segment.
    pub start: Seq,
    /// The last event in the segment.
    pub end: Seq,
    /// The fencing token the segment was written under.
    pub fence: FencingToken,
    /// The hash of the stored bytes.
    pub hash: SegmentHash,
}

impl SegmentRef {
    /// The segment's object name in [`crate::ObjectLog`]'s layout: `{start}-{end}-{fence}`, each
    /// 20 digits.
    pub fn name(&self) -> String {
        format!(
            "{:020}-{:020}-{:020}",
            self.start.0, self.end.0, self.fence.0
        )
    }

    fn well_formed(&self) -> bool {
        self.start.0 >= 1
            && self.start <= self.end
            && self.end.0 - self.start.0 < MAX_SEGMENT_EVENTS
    }
}

/// The committed state of one account's journal: how far it reaches, the highest fencing token
/// seen, and the segment holding its last event. Two heads of one account can be compared with
/// [`JournalHead::check_successor`], and a head pins every chained event before it through
/// [`Chain`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JournalHead {
    /// The tenant.
    pub tenant: TenantId,
    /// The account.
    pub account: AccountId,
    /// The number of the last committed event, `Seq(0)` for an empty journal.
    pub seq: Seq,
    /// The highest fencing token the journal has seen.
    pub fence: FencingToken,
    /// The segment ending at `seq`. `None` for an empty journal and for a head written before
    /// segments were chained; once a head has a tip, every later head has one.
    pub tip: Option<SegmentRef>,
}

const HEAD_CONTEXT: &str = "skein journal head v1";

impl JournalHead {
    /// The head of a journal that has never been written.
    pub fn empty(tenant: TenantId, account: AccountId) -> Self {
        Self {
            tenant,
            account,
            seq: Seq(0),
            fence: FencingToken(0),
            tip: None,
        }
    }

    /// A 32-byte digest of every field, domain-separated for this purpose. Equal digests mean
    /// equal heads; attestors sign this.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(HEAD_CONTEXT);
        for id in [self.tenant.as_str(), self.account.as_str()] {
            h.update(&(id.len() as u64).to_le_bytes());
            h.update(id.as_bytes());
        }
        h.update(&self.seq.0.to_le_bytes());
        h.update(&self.fence.0.to_le_bytes());
        match &self.tip {
            None => {
                h.update(&[0]);
            }
            Some(t) => {
                h.update(&[1]);
                h.update(&t.start.0.to_le_bytes());
                h.update(&t.end.0.to_le_bytes());
                h.update(&t.fence.0.to_le_bytes());
                h.update(&t.hash.0);
            }
        }
        *h.finalize().as_bytes()
    }

    /// Checks that the fields agree with each other: the tip ends at `seq`, was written under a
    /// token no higher than `fence`, and holds at most [`MAX_SEGMENT_EVENTS`] events.
    pub fn check(&self) -> Result<(), IntegrityError> {
        match &self.tip {
            Some(t) if t.end != self.seq || t.fence > self.fence || !t.well_formed() => {
                Err(IntegrityError::Malformed("journal head".into()))
            }
            _ => Ok(()),
        }
    }

    /// Checks that `newer` can follow this head without anything being lost: same account,
    /// neither `seq` nor `fence` lower ([`IntegrityError::Rollback`]: the source is behind or
    /// withholding events), the same tip at the same `seq`, and a tip whenever this head has one
    /// ([`IntegrityError::Fork`]). It reads nothing; [`verify_extends`] also walks the events in
    /// between.
    pub fn check_successor(&self, newer: &JournalHead) -> Result<(), IntegrityError> {
        if self.tenant != newer.tenant || self.account != newer.account {
            return Err(IntegrityError::Scope);
        }
        if newer.seq < self.seq || newer.fence < self.fence {
            return Err(IntegrityError::Rollback {
                trusted: self.seq.0,
                seen: newer.seq.0,
            });
        }
        if (newer.seq == self.seq && newer.tip != self.tip)
            || (self.tip.is_some() && newer.tip.is_none())
        {
            return Err(IntegrityError::Fork { seq: newer.seq.0 });
        }
        Ok(())
    }
}

/// A head with the attestation stored next to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHead {
    /// The head.
    pub head: JournalHead,
    /// What the [`HeadAttestor`] returned for it, if anything.
    pub attestation: Option<Bytes>,
}

/// Why journal data failed verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    /// Bytes do not match the hash that names them.
    #[error("segment {segment} does not match its hash")]
    HashMismatch {
        /// The segment's name.
        segment: String,
    },
    /// A segment's header or events do not match the name, account or range it was read as.
    #[error("segment {segment} is not what it is named: {reason}")]
    Mismatch {
        /// The segment's name.
        segment: String,
        /// What differs.
        reason: String,
    },
    /// A segment does not link to the segment before it.
    #[error("the segment starting at {seq} does not link to the one before it")]
    Link {
        /// Where the segment starts.
        seq: u64,
    },
    /// A segment the chain names is not available from the source: withheld, lost or compacted.
    #[error("segment {segment} is missing")]
    Missing {
        /// The segment's name.
        segment: String,
    },
    /// A head is behind a trusted one: events were rolled back or are being withheld.
    #[error("a head at {seen} is behind the trusted head at {trusted}")]
    Rollback {
        /// The trusted head's `seq`.
        trusted: u64,
        /// The other head's `seq`.
        seen: u64,
    },
    /// Two heads disagree about what the journal holds at or before `seq`.
    #[error("the journal forked at {seq}")]
    Fork {
        /// The position the heads disagree on.
        seq: u64,
    },
    /// The chain from a head does not reach `seq`: it is beyond the head, or before the first
    /// chained segment.
    #[error("event {seq} is not covered by the chain")]
    Unchained {
        /// The position asked for.
        seq: u64,
    },
    /// A head or segment of another tenant or account.
    #[error("data of another tenant or account")]
    Scope,
    /// The attestation of a head is missing or does not hold.
    #[error("head attestation refused: {0}")]
    Attestation(String),
    /// Stored verification data (a head, a hash) does not decode.
    #[error("malformed {0}")]
    Malformed(String),
}

/// Attests journal heads, so a head read from untrusted storage or a peer can be trusted.
///
/// [`crate::ObjectLog`] calls `attest` for every head it writes (each append and each claim) and
/// stores the result next to the head; it calls `verify` on every head it reads whose head or
/// attestation differs from the last one it verified, and fails the operation with the error
/// `verify` returned. Implementations sign [`JournalHead::digest`]; the head includes the fencing
/// token, so a signature can be bound to the holder of the lease.
///
/// Guarantees every implementation keeps (checked by [`crate::testing::head_attestor`]):
///
/// - `verify(head, attest(head))` succeeds.
/// - When `attest` returns `Some`, `verify` refuses that attestation for any other head, refuses
///   any other bytes for that head, and refuses `None`, with
///   [`StorageError::Integrity`]([`IntegrityError::Attestation`]).
/// - Backend failures (a key store that cannot be reached) are [`StorageError::Backend`].
///
/// To adopt an attestor on existing data, `verify` has to accept unattested heads until each
/// account has written once.
#[async_trait]
pub trait HeadAttestor: Send + Sync {
    /// The attestation to store with `head`, or `None` to store none.
    async fn attest(&self, head: &JournalHead) -> Result<Option<Bytes>, StorageError>;

    /// Succeeds when `attestation` vouches for `head`.
    async fn verify(
        &self,
        head: &JournalHead,
        attestation: Option<&[u8]>,
    ) -> Result<(), StorageError>;
}

/// The default [`HeadAttestor`]: attests nothing and accepts every head. Heads are then as
/// trustworthy as the storage holding them; the chain still detects tampered, reordered or
/// mixed-up segments below a head.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAttestor;

#[async_trait]
impl HeadAttestor for NoAttestor {
    async fn attest(&self, _: &JournalHead) -> Result<Option<Bytes>, StorageError> {
        Ok(None)
    }

    async fn verify(&self, _: &JournalHead, _: Option<&[u8]>) -> Result<(), StorageError> {
        Ok(())
    }
}

/// Checks a head read from anywhere: its fields agree ([`JournalHead::check`]) and `attestor`
/// accepts its attestation.
pub async fn verify_head(
    attestor: &dyn HeadAttestor,
    signed: &SignedHead,
) -> Result<(), StorageError> {
    signed.head.check()?;
    attestor
        .verify(&signed.head, signed.attestation.as_deref())
        .await
}

/// Anything that can hand out stored segments by reference: the journal itself, a cache, a replica.
/// It need not be trusted; callers verify what it returns with [`verify_segment`].
#[async_trait]
pub trait SegmentSource: Send + Sync {
    /// The stored bytes of `segment`, `None` when the source does not have it.
    async fn segment(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
    ) -> Result<Option<Bytes>, StorageError>;
}

/// A segment whose bytes matched its reference.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedSegment {
    /// The reference it was verified against.
    pub segment: SegmentRef,
    /// The segment before it, `None` for the first chained segment.
    pub prev: Option<SegmentRef>,
    /// Its events, numbered `segment.start..=segment.end`.
    pub events: Vec<Event>,
}

pub(crate) fn check_header(
    tenant: &TenantId,
    account: &AccountId,
    name: &str,
    start: Seq,
    end: Seq,
    fence: FencingToken,
    header: &SegmentHeader,
) -> Result<(), IntegrityError> {
    let mismatch = |reason: &str| IntegrityError::Mismatch {
        segment: name.to_owned(),
        reason: reason.to_owned(),
    };
    if &header.tenant != tenant || &header.account != account {
        return Err(mismatch("another tenant or account"));
    }
    if header.start != start || header.end != end || header.fence != fence {
        return Err(mismatch("another range or token"));
    }
    if let Some(prev) = &header.prev
        && (!prev.well_formed() || prev.end.0.checked_add(1) != Some(start.0) || prev.fence > fence)
    {
        return Err(IntegrityError::Link { seq: start.0 });
    }
    Ok(())
}

/// Verifies stored segment bytes from any source against the reference that names them: the
/// hash matches, the header names this tenant, account, range and token, the link to the
/// previous segment is consistent, and the events are this account's, numbered
/// `start..=end`. Reads nothing.
pub fn verify_segment(
    tenant: &TenantId,
    account: &AccountId,
    expected: &SegmentRef,
    bytes: &[u8],
) -> Result<VerifiedSegment, StorageError> {
    let name = expected.name();
    if SegmentHash::of(bytes) != expected.hash {
        return Err(IntegrityError::HashMismatch { segment: name }.into());
    }
    if !expected.well_formed() {
        return Err(IntegrityError::Malformed("segment reference".into()).into());
    }
    let decoded = decode_segment(bytes)?;
    let Some(header) = decoded.header else {
        return Err(IntegrityError::Mismatch {
            segment: name,
            reason: "not a chained segment".into(),
        }
        .into());
    };
    check_header(
        tenant,
        account,
        &name,
        expected.start,
        expected.end,
        expected.fence,
        &header,
    )?;
    check_events(
        account,
        &name,
        expected.start,
        expected.end,
        &decoded.events,
    )?;
    Ok(VerifiedSegment {
        segment: expected.clone(),
        prev: header.prev,
        events: decoded.events,
    })
}

pub(crate) fn check_events(
    account: &AccountId,
    name: &str,
    start: Seq,
    end: Seq,
    events: &[Event],
) -> Result<(), IntegrityError> {
    let ok = end.0.checked_sub(start.0).and_then(|n| n.checked_add(1)) == Some(events.len() as u64)
        && events
            .iter()
            .enumerate()
            .all(|(i, e)| e.seq.0 == start.0 + i as u64 && &e.account == account);
    if ok {
        Ok(())
    } else {
        Err(IntegrityError::Mismatch {
            segment: name.to_owned(),
            reason: "events out of order or of another account".into(),
        })
    }
}

/// Walks an account's journal backwards from a head, newest segment first, fetching each segment
/// from a [`SegmentSource`] and verifying it against the reference the segment after it (or the
/// head) holds. Every segment it yields is exactly the one the head committed to; it ends after
/// the first chained segment.
pub struct Chain<'a> {
    source: &'a dyn SegmentSource,
    tenant: TenantId,
    account: AccountId,
    next: Option<SegmentRef>,
}

impl<'a> Chain<'a> {
    /// A walk from `head`'s tip.
    pub fn new(source: &'a dyn SegmentSource, head: &JournalHead) -> Self {
        Self {
            source,
            tenant: head.tenant.clone(),
            account: head.account.clone(),
            next: head.tip.clone(),
        }
    }

    /// The next older segment, `None` after the first chained one. A segment the source does
    /// not have is [`IntegrityError::Missing`]; one that does not verify fails as
    /// [`verify_segment`] does.
    pub async fn next(&mut self) -> Result<Option<VerifiedSegment>, StorageError> {
        let Some(want) = self.next.take() else {
            return Ok(None);
        };
        let Some(bytes) = self
            .source
            .segment(&self.tenant, &self.account, &want)
            .await?
        else {
            return Err(IntegrityError::Missing {
                segment: want.name(),
            }
            .into());
        };
        let segment = verify_segment(&self.tenant, &self.account, &want, &bytes)?;
        self.next = segment.prev.clone();
        Ok(Some(segment))
    }
}

/// The verified segment holding event `seq`, found by walking back from `head`. Fails with
/// [`IntegrityError::Unchained`] when `seq` is beyond the head or before the first chained
/// segment. Costs one fetch per segment from the tip back to `seq`.
pub async fn locate(
    source: &dyn SegmentSource,
    head: &JournalHead,
    seq: Seq,
) -> Result<VerifiedSegment, StorageError> {
    if seq.0 == 0 || seq > head.seq {
        return Err(IntegrityError::Unchained { seq: seq.0 }.into());
    }
    let mut chain = Chain::new(source, head);
    while let Some(segment) = chain.next().await? {
        if segment.segment.start <= seq {
            return Ok(segment);
        }
    }
    Err(IntegrityError::Unchained { seq: seq.0 }.into())
}

/// Checks that `newer` extends `trusted`: [`JournalHead::check_successor`] holds, and walking
/// back from `newer` reaches exactly `trusted`'s tip, so every event `trusted` covered is still
/// there unchanged. A trusted head without a tip (written before chaining) pins only its `seq`
/// and `fence`. Costs one fetch per segment between the two heads.
pub async fn verify_extends(
    source: &dyn SegmentSource,
    trusted: &JournalHead,
    newer: &JournalHead,
) -> Result<(), StorageError> {
    trusted.check()?;
    newer.check()?;
    trusted.check_successor(newer)?;
    let Some(tip) = &trusted.tip else {
        return Ok(());
    };
    if newer.seq == trusted.seq {
        return Ok(());
    }
    let mut chain = Chain::new(source, newer);
    while let Some(segment) = chain.next().await? {
        if segment.segment.end == tip.end {
            return if &segment.segment == tip {
                Ok(())
            } else {
                Err(IntegrityError::Fork { seq: tip.end.0 }.into())
            };
        }
        if segment.segment.end < tip.end {
            break;
        }
    }
    Err(IntegrityError::Fork { seq: tip.end.0 }.into())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::log::{Head, SEGMENT_FORMAT, decode_head, encode_segment};

    fn tenant() -> TenantId {
        TenantId::new("t").unwrap()
    }

    fn account() -> AccountId {
        AccountId::new("a").unwrap()
    }

    fn event(n: u64) -> Event {
        Event {
            v: skein_core::SCHEMA_VERSION,
            seq: Seq(n),
            at: skein_core::Timestamp(n as i64),
            account: account(),
            key: format!("k{n}"),
            origin: None,
            trace: None,
            body: skein_core::EventBody::Unknown,
        }
    }

    fn reference() -> impl Strategy<Value = SegmentRef> {
        (
            1u64..1_000_000,
            0..MAX_SEGMENT_EVENTS,
            any::<u64>(),
            any::<[u8; 32]>(),
        )
            .prop_map(|(start, len, fence, hash)| SegmentRef {
                start: Seq(start),
                end: Seq(start + len),
                fence: FencingToken(fence),
                hash: SegmentHash(hash),
            })
    }

    fn head() -> impl Strategy<Value = JournalHead> {
        (prop::option::of(reference()), any::<u64>(), 0u64..5).prop_map(|(tip, fence, extra)| {
            let seq = tip.as_ref().map_or(Seq(0), |t| t.end);
            let fence = FencingToken(
                tip.as_ref()
                    .map_or(fence, |t| t.fence.0.saturating_add(extra)),
            );
            JournalHead {
                tenant: tenant(),
                account: account(),
                seq,
                fence,
                tip,
            }
        })
    }

    proptest! {
        #[test]
        fn hashes_round_trip_as_hex(bytes in any::<[u8; 32]>()) {
            let hash = SegmentHash(bytes);
            let text = hash.to_string();
            prop_assert_eq!(text.len(), 64);
            prop_assert_eq!(text.parse::<SegmentHash>().unwrap(), hash);
            prop_assert!(text.to_uppercase().parse::<SegmentHash>().is_err() || text.chars().all(|c| c.is_ascii_digit()));
        }

        #[test]
        fn stored_heads_round_trip(head in head(), attestation in prop::option::of(prop::collection::vec(any::<u8>(), 0..80))) {
            let stored = Head {
                seq: head.seq.0,
                fence: head.fence.0,
                tip: head.tip.clone(),
                attestation: attestation.map(Bytes::from),
            };
            let bytes = serde_json::to_vec(&stored).unwrap();
            prop_assert_eq!(decode_head(&bytes).unwrap(), stored);
            prop_assert!(head.check().is_ok());
        }

        #[test]
        fn the_digest_covers_every_field(head in head(), field in 0usize..6) {
            let mut other = head.clone();
            match field {
                0 => other.tenant = TenantId::new("u").unwrap(),
                1 => other.account = AccountId::new("b").unwrap(),
                2 => other.seq = Seq(head.seq.0 ^ 1),
                3 => other.fence = FencingToken(head.fence.0 ^ 1),
                4 => match &mut other.tip {
                    Some(t) => t.hash.0[5] ^= 1,
                    None => other.tip = Some(SegmentRef { start: Seq(1), end: Seq(1), fence: FencingToken(0), hash: SegmentHash([0; 32]) }),
                },
                _ => match &mut other.tip {
                    Some(t) => t.start = Seq(t.start.0 ^ 1),
                    None => other.seq = Seq(1),
                },
            }
            prop_assert_ne!(head.digest(), other.digest());
            prop_assert_eq!(head.digest(), head.clone().digest());
        }

        #[test]
        fn successors_never_go_back(a in head(), b in head()) {
            let ok = a.check_successor(&b).is_ok();
            if ok {
                prop_assert!(b.seq >= a.seq && b.fence >= a.fence);
                if a.tip.is_some() {
                    prop_assert!(b.tip.is_some());
                }
                if a.seq == b.seq {
                    prop_assert_eq!(&a.tip, &b.tip);
                }
            }
            prop_assert!(a.check_successor(&a).is_ok());
        }

        #[test]
        fn any_bytes_verify_only_as_named(bytes in prop::collection::vec(any::<u8>(), 0..400), r in reference()) {
            let result = verify_segment(&tenant(), &account(), &r, &bytes);
            if SegmentHash::of(&bytes) != r.hash {
                let is_mismatch = matches!(result, Err(StorageError::Integrity(IntegrityError::HashMismatch { .. })));
                prop_assert!(is_mismatch);
            }
        }
    }

    fn written(start: u64, end: u64, fence: u64, prev: Option<SegmentRef>) -> (SegmentRef, Bytes) {
        let header = SegmentHeader {
            skein_segment: SEGMENT_FORMAT,
            tenant: tenant(),
            account: account(),
            start: Seq(start),
            end: Seq(end),
            fence: FencingToken(fence),
            prev,
        };
        let events: Vec<_> = (start..=end).map(event).collect();
        let bytes = encode_segment(Some(&header), &events).unwrap();
        let r = SegmentRef {
            start: Seq(start),
            end: Seq(end),
            fence: FencingToken(fence),
            hash: SegmentHash::of(&bytes),
        };
        (r, bytes)
    }

    #[test]
    fn a_segment_verifies_against_its_reference_only() {
        let (r, bytes) = written(1, 3, 2, None);
        let v = verify_segment(&tenant(), &account(), &r, &bytes).unwrap();
        assert_eq!(v.events.len(), 3);
        assert_eq!(v.prev, None);
        let renamed = SegmentRef {
            fence: FencingToken(3),
            ..r.clone()
        };
        assert!(matches!(
            verify_segment(&tenant(), &account(), &renamed, &bytes),
            Err(StorageError::Integrity(IntegrityError::Mismatch { .. }))
        ));
        let other = AccountId::new("b").unwrap();
        assert!(matches!(
            verify_segment(&tenant(), &other, &r, &bytes),
            Err(StorageError::Integrity(IntegrityError::Mismatch { .. }))
        ));
        let legacy = encode_segment(None, &[]).unwrap();
        let named = SegmentRef {
            hash: SegmentHash::of(&legacy),
            ..r
        };
        assert!(matches!(
            verify_segment(&tenant(), &account(), &named, &legacy),
            Err(StorageError::Integrity(IntegrityError::Mismatch { .. }))
        ));
    }

    #[test]
    fn a_reference_ending_before_it_starts_is_refused() {
        let bytes = encode_segment(
            Some(&SegmentHeader {
                skein_segment: SEGMENT_FORMAT,
                tenant: tenant(),
                account: account(),
                start: Seq(5),
                end: Seq(2),
                fence: FencingToken(2),
                prev: None,
            }),
            &[],
        )
        .unwrap();
        for (start, end) in [(5, 2), (0, 0), (0, u64::MAX)] {
            let r = SegmentRef {
                start: Seq(start),
                end: Seq(end),
                fence: FencingToken(2),
                hash: SegmentHash::of(&bytes),
            };
            assert!(matches!(
                verify_segment(&tenant(), &account(), &r, &bytes),
                Err(StorageError::Integrity(IntegrityError::Malformed(_)))
            ));
        }
        assert!(check_events(&account(), "x", Seq(0), Seq(u64::MAX), &[]).is_err());
        assert!(check_events(&account(), "x", Seq(5), Seq(2), &[]).is_err());
    }

    #[test]
    fn a_link_must_end_right_before_and_not_above_the_token() {
        let (first, _) = written(1, 3, 2, None);
        for (start, fence) in [(5u64, 2u64), (3, 2), (4, 1)] {
            let (r, bytes) = written(start, start, fence, Some(first.clone()));
            assert!(matches!(
                verify_segment(&tenant(), &account(), &r, &bytes),
                Err(StorageError::Integrity(IntegrityError::Link { .. }))
            ));
        }
        let (r, bytes) = written(4, 4, 2, Some(first));
        verify_segment(&tenant(), &account(), &r, &bytes).unwrap();
    }

    #[test]
    fn a_link_ending_at_the_last_seq_is_refused_without_overflow() {
        let last = SegmentRef {
            start: Seq(u64::MAX),
            end: Seq(u64::MAX),
            fence: FencingToken(1),
            hash: SegmentHash([0; 32]),
        };
        let (r, bytes) = written(1, 1, 2, Some(last.clone()));
        assert!(matches!(
            verify_segment(&tenant(), &account(), &r, &bytes),
            Err(StorageError::Integrity(IntegrityError::Link { .. }))
        ));
        let header = SegmentHeader {
            skein_segment: SEGMENT_FORMAT,
            tenant: tenant(),
            account: account(),
            start: Seq(0),
            end: Seq(0),
            fence: FencingToken(2),
            prev: Some(last),
        };
        assert!(matches!(
            check_header(
                &tenant(),
                &account(),
                "x",
                Seq(0),
                Seq(0),
                FencingToken(2),
                &header
            ),
            Err(IntegrityError::Link { seq: 0 })
        ));
    }

    #[test]
    fn heads_written_before_chaining_still_read() {
        let head = decode_head(br#"{"seq":12,"fence":3}"#).unwrap();
        assert_eq!(
            (head.seq, head.fence, head.tip, head.attestation),
            (12, 3, None, None)
        );
        assert!(decode_head(br#"{"seq":1,"fence":1,"attestation":"!"}"#).is_err());
        assert!(
            decode_head(br#"{"seq":1,"fence":1,"tip":{"start":1,"end":1,"fence":1,"hash":"00"}}"#)
                .is_err()
        );
    }

    #[test]
    fn malformed_heads_are_refused() {
        let (r, _) = written(4, 6, 3, None);
        let mut head = JournalHead {
            tenant: tenant(),
            account: account(),
            seq: Seq(6),
            fence: FencingToken(3),
            tip: Some(r),
        };
        head.check().unwrap();
        head.seq = Seq(7);
        assert!(head.check().is_err());
        head.seq = Seq(6);
        head.fence = FencingToken(2);
        assert!(head.check().is_err());
    }

    #[tokio::test]
    async fn the_default_attestor_accepts_everything() {
        let head = JournalHead::empty(tenant(), account());
        assert_eq!(NoAttestor.attest(&head).await.unwrap(), None);
        NoAttestor.verify(&head, Some(b"anything")).await.unwrap();
        verify_head(
            &NoAttestor,
            &SignedHead {
                head,
                attestation: None,
            },
        )
        .await
        .unwrap();
    }
}
