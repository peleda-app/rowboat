//! The conformance suite every [`SpamFilter`] runs, over messages the implementation's tests
//! render (rinse's hostile corpus through `rinse-mail-direct`, for example).

use rinse_mail::Rendered;

use crate::{SpamFilter, SpamInput, SpamVerdict, valid_version};

/// Judges every message twice, in and out of a junk mailbox, and checks: equal verdicts both
/// times, no panic, a well-formed version, and a message in a junk mailbox never judged
/// `Clean` when the filter honours placement (`honours_junk`).
pub fn filter(filter: &dyn SpamFilter, rendered: &[Rendered], honours_junk: bool) {
    assert!(valid_version(&filter.version()));
    for r in rendered {
        for in_junk in [false, true] {
            let input = SpamInput {
                rendered: r,
                account: "a0000000000000000000000000",
                in_junk,
                receivers: &[],
            };
            let first = filter.verdict(&input);
            assert_eq!(first, filter.verdict(&input), "verdict not deterministic");
            if in_junk && honours_junk {
                assert_eq!(first, SpamVerdict::Junk);
            }
        }
    }
    assert_eq!(filter.version(), filter.version());
}
