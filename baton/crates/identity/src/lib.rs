//! Who belongs to a person's mesh.
//!
//! Every node has an Ed25519 [`Identity`]; its [`NodeId`](baton_core::NodeId) is derived from the
//! public key, so a node id names exactly one key. The group's members are listed in a signed
//! [`Roster`] whose epoch only grows: pairing a device or revoking one produces the next roster,
//! signed by a current member. A [`RosterHandle`] holds the roster a node currently trusts and
//! accepts only valid successors. New devices pair over a [`Pake`] (CPace): a key exchange over a
//! short invite secret that resists offline guessing.
//!
//! Secrets never appear in `Debug` output, and nothing here logs.

mod error;
mod key;
mod pake;
mod roster;

pub use error::IdentityError;
pub use key::{Identity, PublicKey, Signature};
pub use pake::{PAKE_MESSAGE_LEN, PAKE_TAG_LEN, Pake, PakeRole, PakeSession};
pub use roster::{Roster, RosterHandle};
