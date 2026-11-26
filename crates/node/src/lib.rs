//! Peleda's node: the builder that composes Skein's engine, the `skein-view` mail database,
//! Baton's lease, liveness and signal implementations, the content pipeline the app hands in and
//! the spam and category hooks, behind [`rowboat_api::NodeApi`].
//!
//! ```ignore
//! let node = Node::builder()
//!     .profile(Profile::Desktop)
//!     .data_dir(app_data_dir.join("node"))
//!     .keystore(keystore)     // the app's vault adapter
//!     .content(content)       // the app's sandboxed rinse workers
//!     .build()
//!     .await?;
//! let api = node.api();
//! node.start().await;
//! // ...
//! node.shutdown().await;
//! ```
//!
//! The node never parses message bytes: `skein-view` gets its parser through the content
//! pipeline, and every render is checked with `rinse_mail::verify_rendered`. Secrets live only in
//! the keystore (the node's identity and master key) and, sealed under keys derived from the
//! master key, in the objects directory (account passwords). Logs carry ids, counts and kinds.

mod api;
mod boot;
mod clock;
mod discovery;
mod errors;
mod events;
mod notify;
mod overlay;
mod parser;
mod probe;
mod providers;
mod random;
pub mod records;
mod run;
#[cfg(feature = "testing")]
pub mod testing;

pub use boot::{BuildError, KEY_NAMES, Node, NodeBuilder, Profile, TestTiming};
pub use clock::{Clock, ManualClock, SystemClock};
pub use probe::ServerProber;
pub use providers::{ImapSmtp, Providers};
