//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

use bytes::Bytes;
use skein_core::{AccountId, FencingToken, Seq, TenantId};

use crate::log::{Decoded, decode_head, decode_segment, encode_segment};
use crate::{
    Chain, IntegrityError, JournalHead, SegmentHash, SegmentRef, SegmentSource, Snapshot,
    StorageError, verify_segment,
};

/// Reads `bytes` as a journal segment, both as stored (zstd) and as the NDJSON inside one, and
/// checks that segments this crate writes read back, header included.
pub fn segment(bytes: &[u8]) {
    let _ = decode_segment(bytes);
    let framed = zstd::bulk::compress(bytes, 1).expect("zstd compresses in memory");
    let Ok(decoded) = decode_segment(&framed) else {
        return;
    };
    let again = encode_segment(decoded.header.as_ref(), &decoded.events).expect("events encode");
    let back = decode_segment(&again).expect("a written segment reads");
    assert_eq!(back.header, decoded.header);
    assert_eq!(back.events, decoded.events);
    let mut state = Snapshot::empty(AccountId::new("a1").expect("a valid id"));
    for event in &decoded.events {
        state.apply(event);
    }
}

/// Reads `bytes` as a stored journal head: it either fails or reads back as written, and checking
/// it never panics.
pub fn head(bytes: &[u8]) {
    let Ok(head) = decode_head(bytes) else {
        return;
    };
    let written = serde_json::to_vec(&head).expect("a head serializes");
    assert_eq!(decode_head(&written).expect("a written head reads"), head);
    let journal = JournalHead {
        tenant: TenantId::new("t").expect("valid"),
        account: AccountId::new("a").expect("valid"),
        seq: Seq(head.seq),
        fence: FencingToken(head.fence),
        tip: head.tip,
    };
    let _ = (journal.check(), journal.digest());
}

fn ready<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(out) = f.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

struct One(Option<(SegmentRef, Bytes)>);

#[async_trait::async_trait]
impl SegmentSource for One {
    async fn segment(
        &self,
        _: &TenantId,
        _: &AccountId,
        segment: &SegmentRef,
    ) -> Result<Option<Bytes>, StorageError> {
        Ok(self
            .0
            .as_ref()
            .filter(|(r, _)| r == segment)
            .map(|(_, b)| b.clone()))
    }
}

/// Verifies `bytes` (as stored, and zstd-framed) as a segment named by its own header: the
/// verification never panics, accepts only what matches, refuses any other hash, and a walk from
/// a head naming it ends.
pub fn verify(bytes: &[u8]) {
    let framed = Bytes::from(zstd::bulk::compress(bytes, 1).expect("zstd compresses in memory"));
    for stored in [Bytes::copy_from_slice(bytes), framed] {
        let Ok(Decoded {
            header: Some(header),
            ..
        }) = decode_segment(&stored)
        else {
            continue;
        };
        let named = SegmentRef {
            start: header.start,
            end: header.end,
            fence: header.fence,
            hash: SegmentHash::of(&stored),
        };
        let verified = verify_segment(&header.tenant, &header.account, &named, &stored);
        if let Ok(v) = &verified {
            assert_eq!(v.events.len() as u64, header.end.0 - header.start.0 + 1);
            assert_eq!(v.prev, header.prev);
        }
        let mut wrong = named.clone();
        wrong.hash.0[0] ^= 1;
        assert!(matches!(
            verify_segment(&header.tenant, &header.account, &wrong, &stored),
            Err(StorageError::Integrity(IntegrityError::HashMismatch { .. }))
        ));
        let head = JournalHead {
            tenant: header.tenant.clone(),
            account: header.account.clone(),
            seq: header.end,
            fence: header.fence,
            tip: Some(named.clone()),
        };
        let source = One(Some((named, stored.clone())));
        ready(async {
            let mut chain = Chain::new(&source, &head);
            let first = chain.next().await;
            assert_eq!(first.is_ok(), verified.is_ok());
            if first.is_ok() {
                let rest = chain.next().await;
                assert!(header.prev.is_none() == matches!(rest, Ok(None)));
                assert!(chain.next().await.is_ok_and(|n| n.is_none()));
            }
        });
    }
}

/// Reads `bytes` as a stored snapshot and checks that it reads back as written.
pub fn snapshot(bytes: &[u8]) {
    let Ok(snapshot) = serde_json::from_slice::<Snapshot>(bytes) else {
        return;
    };
    let written = serde_json::to_vec(&snapshot).expect("a snapshot serializes");
    assert_eq!(
        serde_json::from_slice::<Snapshot>(&written).expect("a written snapshot reads"),
        snapshot
    );
    let _ = (snapshot.message_count(), snapshot.object_count());
}

/// The length of the header in front of every stored Baton state record.
pub const STATE_HEADER_LEN: usize = crate::state::HEADER_LEN;

/// Reads `bytes` as a stored Baton state record: it either fails or yields exactly the bytes after
/// the header, and a record this crate writes reads back.
pub fn state_record(bytes: &[u8]) {
    use crate::state::{HEADER_LEN, open, seal};
    if let Ok(value) = open(bytes::Bytes::copy_from_slice(bytes)) {
        assert_eq!(&value[..], &bytes[HEADER_LEN..]);
    }
    assert_eq!(
        &open(seal(bytes)).expect("a written record reads")[..],
        bytes
    );
}

/// The control path of a Baton state record.
pub fn state_path(name: &baton_state::RecordName) -> String {
    crate::state::path(name)
}

/// The record a control path holds, if it is the path of one.
pub fn state_name(path: &str) -> Option<baton_state::RecordName> {
    crate::state::name(path)
}
