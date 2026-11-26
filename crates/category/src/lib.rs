//! The node's category hook: one category for a message as rinse rendered it.
//!
//! Synchronous and CPU-bound: a categorizer never sees raw bytes, never reaches the network and
//! never panics on a hostile [`Rendered`]. Implementations run [`testing::categorizer`].

use std::fmt;

use rinse_mail::Rendered;

#[cfg(feature = "testing")]
pub mod testing;

/// What a categorizer sees of one message.
#[derive(Debug, Clone, Copy)]
pub struct CategoryInput<'a> {
    /// The message as rinse rendered and the node verified it.
    pub rendered: &'a Rendered,
    /// The account id.
    pub account: &'a str,
}

/// A category id: 1 to 55 characters of `[a-z0-9._-]`, so that its tag `category.<id>` is a
/// valid view tag.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Category(String);

impl Category {
    /// Checks and wraps `id`; `None` when it breaks the rules.
    pub fn new(id: &str) -> Option<Self> {
        let ok = !id.is_empty()
            && id.len() <= 55
            && id.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        ok.then(|| Self(id.to_owned()))
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The tag the node stores: `category.<id>`.
    pub fn tag(&self) -> String {
        format!("category.{}", self.0)
    }
}

impl fmt::Debug for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Category({})", self.0)
    }
}

/// Puts one message into a category.
///
/// Guarantees: equal input gives an equal answer; never panics, never blocks on I/O; `None` when
/// unsure; a change that may change any answer changes [`Categorizer::version`].
pub trait Categorizer: Send + Sync {
    /// The category of `input`, `None` when unsure.
    fn category(&self, input: &CategoryInput<'_>) -> Option<Category>;

    /// The categorizer's version: 1 to 64 characters of `[a-z0-9._-]`.
    fn version(&self) -> String;
}

/// Whether `version` has the shape every hook version must have.
pub fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_fit_a_tag() {
        let c = Category::new("person.direct").unwrap();
        assert_eq!(c.tag(), "category.person.direct");
        assert!(Category::new(&"a".repeat(55)).is_some());
        assert!(Category::new(&"a".repeat(56)).is_none());
        for bad in ["", "Person", "a b", "a/b", "é"] {
            assert!(Category::new(bad).is_none(), "{bad}");
        }
        assert!(valid_version("bento-1"));
        assert!(!valid_version("x y"));
    }
}
