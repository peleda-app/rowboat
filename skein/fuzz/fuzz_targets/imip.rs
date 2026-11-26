#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use skein_core::{Timestamp, plausible_address};
use skein_itip::imip::{self, Outgoing};

#[derive(Arbitrary, Debug)]
enum Input<'a> {
    Message(&'a [u8]),
    Compose {
        from: String,
        to: Vec<String>,
        calendar: String,
        subject: String,
        text: String,
        token: String,
        in_reply_to: Option<String>,
        references: Vec<String>,
    },
}

fuzz_target!(|input: Input<'_>| match input {
    Input::Message(bytes) => {
        let _ = imip::may_carry_calendar(bytes);
        let _ = imip::find(bytes);
        let _ = imip::read(bytes);
    }
    Input::Compose {
        from,
        to,
        calendar,
        subject,
        text,
        token,
        in_reply_to,
        references,
    } => {
        let Ok(summary) = skein_itip::summary(calendar.as_bytes()) else {
            return;
        };
        let message = imip::compose(&Outgoing {
            from: &from,
            to: &to,
            calendar: calendar.as_bytes(),
            method: &summary.method,
            subject: &subject,
            text: &text,
            token: &token,
            at: Timestamp(1_767_225_600_000),
            in_reply_to: in_reply_to.as_deref(),
            references: &references,
        });
        if !plausible_address(&from) || !to.iter().all(|a| plausible_address(a)) {
            return;
        }
        let found = imip::find(&message).expect("a composed message carries its calendar");
        assert_eq!(found.calendar.as_ref(), calendar.as_bytes());
    }
});
