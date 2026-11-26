use std::fmt;

use serde::{Deserialize, Serialize};

use crate::NodeError;

macro_rules! text_id {
    ($(#[$doc:meta])* $name:ident, $check:expr) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Checks and wraps `value`; [`NodeError::InvalidInput`] when it breaks the rules.
            pub fn new(value: impl Into<String>) -> Result<Self, NodeError> {
                let value = value.into();
                let check: fn(&str) -> bool = $check;
                if check(&value) {
                    Ok(Self(value))
                } else {
                    Err(NodeError::InvalidInput)
                }
            }

            /// The id as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = NodeError;
            fn try_from(value: String) -> Result<Self, NodeError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

fn base32_id(prefix: u8) -> impl Fn(&str) -> bool {
    move |s: &str| {
        s.len() == 27
            && s.as_bytes()[0] == prefix
            && s.bytes()
                .skip(1)
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    }
}

/// Whether `s` is a canonical ULID: 26 characters of Crockford base32 in upper case, the first
/// at most `7`.
pub fn is_ulid(s: &str) -> bool {
    s.len() == 26
        && s.as_bytes()[0] <= b'7'
        && s.bytes().all(|b| {
            b.is_ascii_digit()
                || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U'))
        })
}

text_id!(
    /// An account of the node: `a` and 26 characters of lowercase base32 (`[a-z2-7]`).
    AccountId,
    |s| base32_id(b'a')(s)
);
text_id!(
    /// A mailbox: the provider's id (IMAP: the decoded path), 1 to 1024 bytes, no control
    /// characters.
    MailboxId,
    |s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)
);
text_id!(
    /// A message: the BLAKE3 hash of its original bytes, 64 lowercase hex characters.
    MessageId,
    |s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
);
text_id!(
    /// A queued command: a canonical ULID.
    CommandId,
    is_ulid
);
text_id!(
    /// A local draft: a canonical ULID.
    DraftId,
    is_ulid
);
text_id!(
    /// A tag the node attached (`spam.junk`, `category.person.direct`): 1 to 64 characters of
    /// `[a-z0-9._-]`.
    Tag,
    |s| !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
);

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({})", self.0)
    }
}
impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", self.0)
    }
}
impl fmt::Debug for CommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommandId({})", self.0)
    }
}
impl fmt::Debug for DraftId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DraftId({})", self.0)
    }
}
impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag({})", self.0)
    }
}
impl fmt::Debug for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MailboxId({} bytes)", self.0.len())
    }
}

/// A thread of an account, positive. A thread may vanish when threads merge: reading it then
/// gives [`NodeError::NotFound`] and the app reloads its list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct ThreadId(i64);

impl ThreadId {
    /// Checks and wraps `id`.
    pub fn new(id: i64) -> Result<Self, NodeError> {
        if id > 0 {
            Ok(Self(id))
        } else {
            Err(NodeError::InvalidInput)
        }
    }

    /// The id.
    pub fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for ThreadId {
    type Error = NodeError;
    fn try_from(value: i64) -> Result<Self, NodeError> {
        Self::new(value)
    }
}

impl From<ThreadId> for i64 {
    fn from(value: ThreadId) -> i64 {
        value.0
    }
}

/// Most bytes of an address.
pub const MAX_ADDRESS: usize = 320;

/// Whether `address` is a bare address safe in a header or an SMTP command: one `@` with text
/// on both sides, at most [`MAX_ADDRESS`] bytes, no whitespace, control characters, angle
/// brackets, commas, semicolons, quotes, parentheses or backslashes.
pub fn plausible_address(address: &str) -> bool {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !local.contains('@')
        && address.len() <= MAX_ADDRESS
        && !address.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '<' | '>' | ',' | ';' | '"' | '(' | ')' | '\\' | '[' | ']' | ':'
                )
        })
}

text_id!(
    /// An email address checked with [`plausible_address`]; the domain is kept as given.
    EmailAddress,
    plausible_address
);

impl fmt::Debug for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmailAddress({} bytes)", self.0.len())
    }
}

impl EmailAddress {
    /// The part after the `@`.
    pub fn domain(&self) -> &str {
        self.0.rsplit_once('@').map(|(_, d)| d).unwrap_or_default()
    }

    /// The part before the `@`.
    pub fn local_part(&self) -> &str {
        self.0.rsplit_once('@').map(|(l, _)| l).unwrap_or_default()
    }
}
