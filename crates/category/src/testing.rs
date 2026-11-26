//! The conformance suite every [`Categorizer`] runs, over messages the implementation's tests
//! render (rinse's hostile corpus through `rinse-mail-direct`, for example).

use rinse_mail::Rendered;

use crate::{Categorizer, CategoryInput, valid_version};

/// Categorizes every message twice and checks: equal answers, no panic, a well-formed version,
/// every category usable as a tag.
pub fn categorizer(categorizer: &dyn Categorizer, rendered: &[Rendered]) {
    assert!(valid_version(&categorizer.version()));
    for r in rendered {
        let input = CategoryInput {
            rendered: r,
            account: "a0000000000000000000000000",
        };
        let first = categorizer.category(&input);
        assert_eq!(
            first,
            categorizer.category(&input),
            "answer not deterministic"
        );
        if let Some(c) = first {
            assert!(c.tag().len() <= 64);
        }
    }
}
