//! The conformance suite every [`Endpoints`] runs.
//!
//! ```ignore
//! #[tokio::test(flavor = "multi_thread")]
//! async fn conformance() {
//!     rowboat_endpoint::testing::endpoints(&MyEndpoints::new()).await;
//! }
//! ```

use std::sync::Arc;
use std::time::Duration;

use baton_identity::{Identity, PublicKey};
use baton_link::{LinkError, PinnedKeys, Protocol, Trust};
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Endpoint, Endpoints};

const PATIENCE: Duration = Duration::from_secs(20);

struct Everyone;

impl Trust for Everyone {
    fn allows(&self, _: &PublicKey) -> bool {
        true
    }
}

async fn within<T>(what: &str, f: impl Future<Output = T>) -> T {
    tokio::time::timeout(PATIENCE, f)
        .await
        .unwrap_or_else(|_| panic!("timed out: {what}"))
}

async fn echo_once(server: &Endpoint, protocol: &Protocol) -> tokio::task::JoinHandle<PublicKey> {
    let mut listener = server.link.listen(protocol).await.unwrap();
    tokio::spawn(async move {
        let mut inc = listener.next().await.expect("an incoming stream");
        let mut buf = [0u8; 5];
        inc.stream.read_exact(&mut buf).await.unwrap();
        inc.stream.write_all(&buf).await.unwrap();
        inc.stream.shutdown().await.unwrap();
        inc.peer
    })
}

async fn round_trip(client: &Endpoint, server: &Endpoint, protocol: &Protocol) {
    client
        .link
        .add_hint(&server.link.local(), server.hint.clone())
        .unwrap();
    let mut s = within("open", client.link.open(&server.link.local(), protocol))
        .await
        .unwrap();
    s.write_all(b"hello").await.unwrap();
    let mut back = [0u8; 5];
    within("echo", s.read_exact(&mut back)).await.unwrap();
    assert_eq!(&back, b"hello");
}

/// Runs the whole suite.
pub async fn endpoints(factory: &dyn Endpoints) {
    let protocol = Protocol::new("conformance").unwrap();
    let a_id = Identity::generate();
    let b_id = Identity::generate();
    let a_pins = Arc::new(PinnedKeys::new([b_id.public()]));
    let b_pins = Arc::new(PinnedKeys::new([a_id.public()]));
    let a = factory.bind(&a_id, a_pins.clone()).await.unwrap();
    let b = factory.bind(&b_id, b_pins).await.unwrap();
    assert_eq!(
        a.link.local(),
        a_id.public(),
        "local() is the identity's key"
    );
    assert_eq!(b.link.local(), b_id.public());

    let served = echo_once(&a, &protocol).await;
    round_trip(&b, &a, &protocol).await;
    assert_eq!(within("served", served).await.unwrap(), b_id.public());

    let open_id = Identity::generate();
    let open = factory.bind(&open_id, Arc::new(Everyone)).await.unwrap();
    let stranger_id = Identity::generate();
    let stranger = factory
        .bind(
            &stranger_id,
            Arc::new(PinnedKeys::new([open_id.public(), a_id.public()])),
        )
        .await
        .unwrap();
    let served = echo_once(&open, &protocol).await;
    round_trip(&stranger, &open, &protocol).await;
    assert_eq!(
        within("served", served).await.unwrap(),
        stranger_id.public()
    );

    let _listener = a
        .link
        .listen(&Protocol::new("other").unwrap())
        .await
        .unwrap();
    stranger
        .link
        .add_hint(&a.link.local(), a.hint.clone())
        .unwrap();
    let refused = within(
        "refusal",
        stranger
            .link
            .open(&a.link.local(), &Protocol::new("other").unwrap()),
    )
    .await;
    assert!(
        matches!(refused, Err(LinkError::Rejected)),
        "an endpoint refuses a peer its trust does not allow"
    );

    open.link.close().await;
    let served = echo_once(&a, &protocol).await;
    round_trip(&b, &a, &protocol).await;
    assert_eq!(
        within("served after another endpoint closed", served)
            .await
            .unwrap(),
        b_id.public()
    );

    for e in [a, b, stranger] {
        e.link.close().await;
    }
}
