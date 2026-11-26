//! Conformance suite for [`Wake`].

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::{MAX_WAKE, Wake, WakeError, WakeTarget};

/// The [`Wake`] contract. `receiver` must accept wakes from `sender` and not from `stranger`;
/// `invalid` is a target `sender` cannot address.
pub async fn wake(
    sender: Arc<dyn Wake>,
    receiver: Arc<dyn Wake>,
    stranger: Arc<dyn Wake>,
    invalid: WakeTarget,
) {
    let target = receiver.target();
    assert!(matches!(
        sender
            .wake(&target, Bytes::from(vec![0u8; MAX_WAKE + 1]))
            .await,
        Err(WakeError::TooLarge)
    ));
    assert!(matches!(
        sender.wake(&invalid, Bytes::from_static(b"x")).await,
        Err(WakeError::InvalidTarget)
    ));

    let full = Bytes::from(vec![9u8; MAX_WAKE]);
    sender.wake(&target, full.clone()).await.unwrap();
    let got = within(receiver.listen()).await.unwrap();
    assert_eq!(got.sealed, full, "a delivered wake arrives unchanged");

    let _ = stranger.wake(&target, Bytes::from_static(b"forged")).await;
    sender
        .wake(&target, Bytes::from_static(b"genuine"))
        .await
        .unwrap();
    let got = within(receiver.listen()).await.unwrap();
    assert_eq!(
        got.sealed,
        Bytes::from_static(b"genuine"),
        "a stranger's wake never arrives"
    );

    let waiting = {
        let receiver = receiver.clone();
        tokio::spawn(async move { receiver.listen().await })
    };
    tokio::task::yield_now().await;
    sender
        .wake(&target, Bytes::from_static(b"later"))
        .await
        .unwrap();
    let got = within(waiting).await.unwrap().unwrap();
    assert_eq!(got.sealed, Bytes::from_static(b"later"));
}

async fn within<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), f)
        .await
        .expect("the wake arrives")
}
