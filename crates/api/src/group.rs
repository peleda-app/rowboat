//! The group surface: pairing, the list of nodes and revocation (GROUP.md).

use serde::{Deserialize, Serialize};

use crate::NodeError;
use crate::ids::AccountId;

/// The longest pairing code or address the node accepts, in characters.
pub const MAX_PAIRING_TEXT: usize = 2048;
/// The longest name a node may be given, in characters.
pub const MAX_NODE_LABEL: usize = 64;
/// Most accounts one call grants to a server.
pub const MAX_GRANTS: usize = 1_000;

/// A device invite just made: what the app shows as a QR code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingInvite {
    /// The invite's id, for [`crate::NodeApi::confirm_pairing`] and
    /// [`crate::NodeApi::cancel_invite`]: 16 characters of `[0-9a-f]`.
    pub invite: String,
    /// The QR payload (`peleda-pair:` and base32). It is a secret until it expires: show it, never
    /// send it anywhere.
    pub qr: String,
    /// The short code a person may type instead (`XX-XXXX-XXXX`), when the invite has one; a
    /// secret like `qr`. Device invites have none yet: a typed code needs a rendezvous.
    pub short_code: Option<String>,
    /// The pairing address typed with `short_code` (`peleda-addr:...`); holds no secret.
    pub address: Option<String>,
    /// When the invite expires, milliseconds since the epoch.
    pub expires_at: i64,
}

/// How a pairing this node took part in ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingResult {
    /// The other node: the device that certified this one, or the server this node adopted.
    pub node_id: String,
    /// The group this node is in after the pairing.
    pub group_id: String,
    /// This node joined another group: the app must shut the node down and build it again over
    /// the same directory and keystore before using it.
    pub restart_required: bool,
}

/// One node of the group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSummary {
    /// Its node id.
    pub node_id: String,
    /// `server`, `desktop`, `phone` or `blind`.
    pub class: String,
    /// The label it gave when it paired with this node: display only, never trusted.
    pub label: Option<String>,
    /// Whether it is this node.
    pub this_node: bool,
    /// Whether it counts now: certified, not revoked, not expired.
    pub counts: bool,
    /// Whether it was revoked.
    pub revoked: bool,
    /// When its certificate expires, milliseconds since the epoch.
    pub expires_at: i64,
    /// When this node last heard from it since this node started, milliseconds since the epoch;
    /// now for this node itself, `None` when not since the start.
    pub last_seen: Option<i64>,
    /// Accounts it may lead under the group log (`lead` on the account's resource).
    pub may_lead: Vec<AccountId>,
}

/// What kind of node an invite pairs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteKind {
    /// A device invite: this node joins the inviter's group.
    Device,
    /// A server's first-run invite: this node adopts the server into its group.
    Server,
}

/// What a pairing code says before anything is dialed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteInfo {
    /// Device or server.
    pub kind: InviteKind,
    /// When it expires, milliseconds since the epoch; a typed short code does not say.
    pub expires_at: Option<i64>,
}

/// Whether the group's server answers this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    /// The group has no server.
    None,
    /// The server answers; it leads the accounts it holds.
    Answering,
    /// The server has been silent for the takeover delay or announced leaving: devices lead.
    Silent,
}

/// Which node leads one account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountLeader {
    /// The account.
    pub account: AccountId,
    /// The leaseholder's node id, `None` when nobody holds the lease or the arbiter does not
    /// answer.
    pub node: Option<String>,
}

/// Who leads what, as this node sees it now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupStatus {
    /// The server, as this node sees it.
    pub server: ServerState,
    /// Every account this node reads, by account id.
    pub leaders: Vec<AccountLeader>,
}

/// What a revocation left for the person to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoked {
    /// Accounts the revoked node could lead: it may have kept their passwords or tokens, so they
    /// must be changed (or the OAuth grant revoked).
    pub secrets_rotation_required: Vec<AccountId>,
}

/// Whether `text` is a plausible pairing code or address: one line, 1 to [`MAX_PAIRING_TEXT`]
/// characters.
pub fn pairing_text(text: &str) -> Result<(), NodeError> {
    if !text.trim().is_empty() && crate::check::one_line(text, MAX_PAIRING_TEXT) {
        Ok(())
    } else {
        Err(NodeError::InvalidInput)
    }
}

/// Whether `label` is a node name: one line of 1 to [`MAX_NODE_LABEL`] characters, not blank.
pub fn node_label(label: &str) -> Result<(), NodeError> {
    if !label.trim().is_empty() && crate::check::one_line(label, MAX_NODE_LABEL) {
        Ok(())
    } else {
        Err(NodeError::InvalidInput)
    }
}

/// Whether `id` is an invite id: 16 characters of `[0-9a-f]`.
pub fn invite_id(id: &str) -> Result<(), NodeError> {
    if id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(NodeError::InvalidInput)
    }
}

/// Whether `id` is a node id: 52 characters of `[a-z2-7]` (an Ed25519 key in base32).
pub fn node_id(id: &str) -> Result<(), NodeError> {
    if id.len() == 52
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        Ok(())
    } else {
        Err(NodeError::InvalidInput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks() {
        assert!(pairing_text("peleda-pair:AAAA").is_ok());
        for bad in ["", "   ", "a\nb", &"a".repeat(MAX_PAIRING_TEXT + 1)] {
            assert_eq!(pairing_text(bad), Err(NodeError::InvalidInput));
        }
        assert!(invite_id("0123456789abcdef").is_ok());
        for bad in ["0123456789ABCDEF", "0123", "0123456789abcdeg"] {
            assert!(invite_id(bad).is_err());
        }
        assert!(node_id(&"a".repeat(52)).is_ok());
        for bad in ["a".repeat(51), "1".repeat(52), "A".repeat(52)] {
            assert!(node_id(&bad).is_err());
        }
        assert!(node_label("Ada's laptop").is_ok());
        assert!(node_label(&"é".repeat(MAX_NODE_LABEL)).is_ok());
        for bad in ["", "  ", "a\nb", "a\u{7}b", &"a".repeat(MAX_NODE_LABEL + 1)] {
            assert_eq!(node_label(bad), Err(NodeError::InvalidInput), "{bad:?}");
        }
    }
}
