//! Conformance suite for [`Signal`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use baton_core::GroupId;
use bytes::Bytes;
use futures::StreamExt;

use crate::{MAX_NAME, MAX_PAYLOAD, Signal, SignalError};

/// The [`Signal`] contract. Waits a little over `ttl` three times, so keep it short.
pub async fn signal(sig: Arc<dyn Signal>, ttl: Duration) {
    let g1 = GroupId::new("conf-sig-1").unwrap();
    let g2 = GroupId::new("conf-sig-2").unwrap();

    let mut sub1 = sig.subscribe(&g1, "hints/res").await.unwrap();
    let mut sub2 = sig.subscribe(&g2, "hints/res").await.unwrap();
    sig.publish(&g1, "hints/res", Bytes::from_static(b"1"))
        .await
        .unwrap();
    sig.publish(&g1, "hints/res", Bytes::from_static(b"2"))
        .await
        .unwrap();
    for want in [b"1", b"2"] {
        let got = tokio::time::timeout(Duration::from_secs(2), sub1.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got[..], want, "publish order is kept");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), sub2.next())
            .await
            .is_err(),
        "groups are isolated"
    );

    let _never_read = sig.subscribe(&g1, "slow").await.unwrap();
    let started = Instant::now();
    for i in 0..2_000u32 {
        sig.publish(&g1, "slow", Bytes::from(i.to_be_bytes().to_vec()))
            .await
            .unwrap();
    }
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "a subscriber that never reads does not block publishers"
    );

    sig.put(&g1, "token:res", Bytes::from_static(b"secret"), ttl)
        .await
        .unwrap();
    assert_eq!(
        sig.get(&g1, "token:res").await.unwrap().unwrap(),
        &b"secret"[..]
    );
    assert!(sig.get(&g2, "token:res").await.unwrap().is_none());
    tokio::time::sleep(ttl + Duration::from_millis(50)).await;
    assert!(
        sig.get(&g1, "token:res").await.unwrap().is_none(),
        "values expire"
    );

    sig.put(&g1, "k", Bytes::from_static(b"v"), Duration::from_secs(60))
        .await
        .unwrap();
    sig.delete(&g1, "k").await.unwrap();
    assert!(sig.get(&g1, "k").await.unwrap().is_none());

    if let Some(first) = sig.incr(&g1, "count", 2, ttl).await.unwrap() {
        assert_eq!(first, 2);
        let mut adds = Vec::new();
        for _ in 0..20 {
            let sig = sig.clone();
            let g1 = g1.clone();
            adds.push(tokio::spawn(async move {
                sig.incr(&g1, "count", 1, ttl).await.unwrap()
            }));
        }
        for add in adds {
            add.await.unwrap();
        }
        assert_eq!(
            sig.incr(&g1, "count", 0, ttl).await.unwrap(),
            Some(22),
            "concurrent adds are never lost"
        );
        assert_eq!(sig.incr(&g2, "count", 1, ttl).await.unwrap(), Some(1));
        assert!(
            sig.get(&g1, "count").await.unwrap().is_none(),
            "counters are not values"
        );
        assert_eq!(
            sig.incr(&g1, "count", u64::MAX, ttl).await.unwrap(),
            Some(u64::MAX),
            "counters saturate"
        );
        tokio::time::sleep(ttl + Duration::from_millis(50)).await;
        assert_eq!(
            sig.incr(&g1, "count", 1, ttl).await.unwrap(),
            Some(1),
            "counters expire"
        );

        sig.incr(&g1, "fixed", 1, ttl).await.unwrap();
        tokio::time::sleep(ttl / 2).await;
        assert_eq!(sig.incr(&g1, "fixed", 1, ttl).await.unwrap(), Some(2));
        tokio::time::sleep(ttl / 2 + Duration::from_millis(50)).await;
        assert_eq!(
            sig.incr(&g1, "fixed", 1, ttl).await.unwrap(),
            Some(1),
            "later adds do not extend a counter's time-to-live"
        );
    }

    let long = "x".repeat(MAX_NAME + 1);
    for bad in ["", "a b", "a\nb", "a\0b", "ä", long.as_str()] {
        assert!(matches!(
            sig.put(&g1, bad, Bytes::new(), ttl).await,
            Err(SignalError::InvalidName)
        ));
        assert!(matches!(
            sig.publish(&g1, bad, Bytes::new()).await,
            Err(SignalError::InvalidName)
        ));
        assert!(matches!(
            sig.subscribe(&g1, bad).await,
            Err(SignalError::InvalidName)
        ));
    }
    let big = Bytes::from(vec![0u8; MAX_PAYLOAD + 1]);
    assert!(matches!(
        sig.put(&g1, "big", big.clone(), ttl).await,
        Err(SignalError::TooLarge)
    ));
    assert!(
        sig.get(&g1, "big").await.unwrap().is_none(),
        "a refused value stores nothing"
    );
    let mut sub = sig.subscribe(&g1, "big").await.unwrap();
    assert!(matches!(
        sig.publish(&g1, "big", big).await,
        Err(SignalError::TooLarge)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), sub.next())
            .await
            .is_err(),
        "a refused payload is not delivered"
    );
    sig.put(&g1, "max", Bytes::from(vec![1u8; MAX_PAYLOAD]), ttl)
        .await
        .unwrap();
}
