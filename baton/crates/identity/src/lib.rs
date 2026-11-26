//! Who belongs to a person's mesh.
//!
//! Every node has an Ed25519 [`Identity`]; its [`NodeId`](baton_core::NodeId) is derived from the
//! public key, so a node id names exactly one key. The group's members are listed in a signed
//! [`Roster`] whose epoch only grows: pairing a device or revoking one produces the next roster,
//! signed by a current member. A [`RosterHandle`] holds the roster a node currently trusts and
//! accepts only valid successors. New devices join through a one-time [`Invite`].
//!
//! Secrets never appear in `Debug` output, and nothing here logs.

mod error;
mod key;
mod pairing;
mod roster;

pub use error::IdentityError;
pub use key::{Identity, PublicKey, Signature};
pub use pairing::{Invite, Inviter, JoinRequest};
pub use roster::{Roster, RosterHandle};
