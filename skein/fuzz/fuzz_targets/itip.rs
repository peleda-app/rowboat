#![no_main]

use libfuzzer_sys::fuzz_target;
use skein_core::{PartStat, Timestamp};
use skein_itip as itip;

const AT: Timestamp = Timestamp(1_767_225_600_000);

fuzz_target!(|data: &[u8]| {
    let _ = itip::summary(data);
    let (previous, next) = match data.iter().position(|b| *b == 0) {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, data),
    };
    let _ = itip::plan(Some(previous), Some(next));
    let _ = itip::plan(None, Some(next));
    let _ = itip::plan(Some(previous), None);
    let Ok(facts) = itip::facts(data) else {
        return;
    };
    let _ = facts.organized_by(&[]);
    let _ = itip::imip::describe("REQUEST", data, "ada@example.com", None);

    if let Ok(request) = itip::request(data, AT) {
        let summary = itip::summary(&request).expect("a built REQUEST reads");
        assert_eq!(summary.method, "REQUEST");
        let again = itip::request(&request, AT).expect("a built REQUEST builds again");
        assert_eq!(again, request, "building a REQUEST is idempotent");
    }
    if let Ok(cancel) = itip::cancel(data, None, None, AT) {
        assert_eq!(
            itip::summary(&cancel).expect("a built CANCEL reads").method,
            "CANCEL"
        );
    }
    let Some(attendee) = facts.attendees.first().map(|a| a.address.clone()) else {
        return;
    };
    if let Ok(reply) = itip::reply(data, &attendee, PartStat::Accepted, Some("Yes"), AT) {
        let summary = itip::summary(&reply).expect("a built REPLY reads");
        assert_eq!(summary.method, "REPLY");
        assert!(summary.attendees.iter().all(|a| a.address == attendee));
    }
    if let Ok(answered) = itip::set_partstat(data, &attendee, PartStat::Tentative, None) {
        let again = itip::set_partstat(&answered, &attendee, PartStat::Tentative, None)
            .expect("an answered copy can be answered again");
        assert_eq!(again, answered, "answering is idempotent");
        let own = itip::facts(&answered).expect("an answered copy reads");
        let me = own
            .own_attendee(&[attendee.clone()])
            .expect("still invited");
        assert_eq!(me.partstat.as_deref(), Some("TENTATIVE"));
    }
});
