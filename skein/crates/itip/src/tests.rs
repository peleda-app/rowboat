use proptest::prelude::*;

use super::*;
use crate::imip::{Outgoing, compose, describe, find, may_carry_calendar, read};

const REQUEST: &[u8] = include_bytes!("../tests/fixtures/request.ics");
const MAIL: &[u8] = include_bytes!("../tests/fixtures/invitation.eml");
const AT: Timestamp = Timestamp(1_795_262_400_000);

const OWN: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\nBEGIN:VEVENT\r\n\
UID:review@example.com\r\nDTSTAMP:20261101T000000Z\r\nSEQUENCE:1\r\n\
DTSTART:20261130T090000Z\r\nDTEND:20261130T100000Z\r\nSUMMARY:Review\r\n\
ORGANIZER;SCHEDULE-STATUS=1.1:mailto:ada@example.com\r\n\
ATTENDEE;PARTSTAT=ACCEPTED:mailto:ada@example.com\r\n\
ATTENDEE;PARTSTAT=NEEDS-ACTION;SCHEDULE-STATUS=1.1:mailto:bob@example.org\r\n\
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carol@example.org\r\n\
ATTENDEE;SCHEDULE-AGENT=NONE:mailto:room@example.com\r\n\
BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nDESCRIPTION:Soon\r\nEND:VALARM\r\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";

fn text(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).unwrap()
}

fn unfold(b: &[u8]) -> String {
    text(b).replace("\r\n ", "")
}

#[test]
fn summarizes_an_invitation() {
    let s = summary(REQUEST).unwrap();
    assert_eq!(s.method, "REQUEST");
    assert_eq!(s.component, "VEVENT");
    assert_eq!(s.uid, "planning-7f3a@example.org");
    assert_eq!(s.sequence, 2);
    assert_eq!(s.recurrence_id, None);
    assert_eq!(s.organizer.as_deref(), Some("bob@example.org"));
    assert_eq!(s.attendees.len(), 3);
    assert_eq!(s.attendees[0].address, "ada@example.com");
    assert_eq!(s.attendees[0].partstat.as_deref(), Some("NEEDS-ACTION"));
    assert!(s.attendees[0].rsvp);
    assert!(!s.more_attendees);
    assert_eq!(summary(OWN.as_bytes()), Err(ItipError::WrongMethod));
}

#[test]
fn facts_join_series_and_instances() {
    let f = facts(REQUEST).unwrap();
    assert_eq!(f.summary.as_deref(), Some("Planning, weekly"));
    assert_eq!(f.attendees.len(), 3);
    assert_eq!(f.attendees[2].agent, Agent::Client);
    assert_eq!(
        f.own_attendee(&["MAILTO:ADA@example.com".into()])
            .map(|a| a.address.as_str()),
        Some("ada@example.com")
    );
    assert!(!f.organized_by(&["ada@example.com".into()]));
    assert!(f.organized_by(&[]));
}

#[test]
fn a_reply_covers_every_component_the_attendee_is_on() {
    let r = reply(
        REQUEST,
        "ada@example.com",
        PartStat::Accepted,
        Some("See you; bring notes"),
        AT,
    )
    .unwrap();
    let s = unfold(&r);
    assert!(s.contains("METHOD:REPLY\r\n"));
    assert!(s.contains("BEGIN:VTIMEZONE\r\n"));
    assert_eq!(s.matches("BEGIN:VEVENT").count(), 2);
    assert_eq!(s.matches("ATTENDEE").count(), 2);
    assert!(s.contains("PARTSTAT=ACCEPTED"));
    assert!(!s.contains("RSVP"));
    assert!(!s.contains("carol@"));
    assert!(!s.contains("VALARM"));
    assert!(!s.contains("DESCRIPTION"));
    assert!(s.contains("RECURRENCE-ID;TZID=Europe/Berlin:20261201T100000"));
    assert!(s.contains("DTSTAMP:20261121T120000Z"));
    assert!(s.contains("COMMENT:See you\\; bring notes"));
    assert!(s.contains("SEQUENCE:2"));
    let back = summary(&r).unwrap();
    assert_eq!(back.method, "REPLY");
    assert_eq!(back.attendees.len(), 1);
    assert_eq!(back.attendees[0].partstat.as_deref(), Some("ACCEPTED"));
    assert_eq!(
        reply(REQUEST, "eve@example.net", PartStat::Declined, None, AT),
        Err(ItipError::AttendeeNotFound)
    );
    let cancel_msg = cancel(OWN.as_bytes(), None, None, AT).unwrap();
    assert_eq!(
        reply(&cancel_msg, "bob@example.org", PartStat::Accepted, None, AT),
        Err(ItipError::WrongMethod)
    );
}

#[test]
fn a_reply_is_the_same_for_the_same_input() {
    let a = reply(REQUEST, "carol@example.org", PartStat::Tentative, None, AT).unwrap();
    let b = reply(REQUEST, "carol@example.org", PartStat::Tentative, None, AT).unwrap();
    assert_eq!(a, b);
}

#[test]
fn set_partstat_changes_only_the_answer() {
    let out = set_partstat(REQUEST, "ADA@example.com", PartStat::Declined, None).unwrap();
    let s = unfold(&out);
    assert_eq!(s.matches("PARTSTAT=DECLINED").count(), 2);
    assert!(s.contains("mailto:carol@example.org"));
    assert!(s.contains("BEGIN:VALARM"));
    assert!(s.contains("X-EXAMPLE-FLAG;X-PARAM=\"a:b;c\":kept"));
    assert!(s.contains("DESCRIPTION:A long description that is folded because it goes on for more than seventy-five octets on one line."));
    assert_eq!(
        set_partstat(REQUEST, "eve@example.net", PartStat::Accepted, None),
        Err(ItipError::AttendeeNotFound)
    );
    for line in text(&out).split("\r\n") {
        assert!(line.len() <= 75, "{line}");
    }
}

#[test]
fn a_request_drops_alarms_and_server_parameters() {
    let r = request(OWN.as_bytes(), AT).unwrap();
    let s = unfold(&r);
    assert!(s.contains("METHOD:REQUEST"));
    assert!(!s.contains("VALARM"));
    assert!(!s.contains("SCHEDULE-STATUS"));
    assert!(s.contains("DTSTAMP:20261121T120000Z"));
    assert_eq!(s.matches("DTSTAMP").count(), 1);
    assert_eq!(summary(&r).unwrap().attendees.len(), 4);
}

#[test]
fn a_cancel_names_whom_it_concerns_and_raises_the_sequence() {
    let all = cancel(OWN.as_bytes(), None, None, AT).unwrap();
    let s = summary(&all).unwrap();
    assert_eq!(s.method, "CANCEL");
    assert_eq!(s.sequence, 2);
    assert_eq!(s.attendees.len(), 4);
    assert!(unfold(&all).contains("STATUS:CANCELLED"));
    let some = cancel(
        OWN.as_bytes(),
        Some(&["mailto:Carol@example.org".into()]),
        Some(1),
        AT,
    )
    .unwrap();
    let s = summary(&some).unwrap();
    assert_eq!(s.sequence, 1);
    assert_eq!(s.attendees.len(), 1);
    assert_eq!(s.attendees[0].address, "carol@example.org");
    assert_eq!(
        cancel(OWN.as_bytes(), Some(&["eve@example.net".into()]), None, AT),
        Err(ItipError::AttendeeNotFound)
    );
}

#[test]
fn plans_follow_rfc_6638() {
    let p = plan(None, Some(OWN.as_bytes())).unwrap().unwrap();
    assert_eq!(p.organizer, "ada@example.com");
    assert_eq!(p.request, vec!["bob@example.org", "carol@example.org"]);
    assert!(p.cancel.is_empty());
    let without_carol = OWN.replace(
        "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carol@example.org\r\n",
        "",
    );
    let p = plan(Some(OWN.as_bytes()), Some(without_carol.as_bytes()))
        .unwrap()
        .unwrap();
    assert_eq!(p.request, vec!["bob@example.org"]);
    assert_eq!(p.cancel, vec!["carol@example.org"]);
    let p = plan(Some(OWN.as_bytes()), None).unwrap().unwrap();
    assert!(p.request.is_empty());
    assert_eq!(p.cancel, vec!["bob@example.org", "carol@example.org"]);
    let quiet = OWN.replace("ORGANIZER;", "ORGANIZER;SCHEDULE-AGENT=CLIENT;");
    assert!(
        plan(None, Some(quiet.as_bytes()))
            .unwrap()
            .unwrap()
            .is_empty()
    );
    let alone = OWN.replace(
        "ORGANIZER;SCHEDULE-STATUS=1.1:mailto:ada@example.com\r\n",
        "",
    );
    assert_eq!(plan(None, Some(alone.as_bytes())).unwrap(), None);
    assert_eq!(plan(None, None).unwrap(), None);
}

#[test]
fn finds_the_invitation_in_mail() {
    assert!(may_carry_calendar(MAIL));
    assert!(!may_carry_calendar(b"Subject: hi\r\n\r\nplain text"));
    let inv = find(MAIL).unwrap();
    assert_eq!(
        summary(&inv.calendar).unwrap().uid,
        "planning-7f3a@example.org"
    );
    assert_eq!(inv.recipients, vec!["ada@example.com", "carol@example.org"]);
    assert_eq!(inv.message_id.as_deref(), Some("inv-1@example.org"));
    assert_eq!(inv.references, vec!["thread-0@example.org"]);
    assert_eq!(read(MAIL).unwrap(), inv);
    let bare = read(REQUEST).unwrap();
    assert!(bare.recipients.is_empty());
    assert_eq!(
        read(b"Subject: x\r\n\r\nnothing"),
        Err(ItipError::NoCalendarPart)
    );
    assert!(read(b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n").is_err());
}

#[test]
fn composes_rfc_6047_mail() {
    let r = reply(REQUEST, "ada@example.com", PartStat::Accepted, None, AT).unwrap();
    let (subject, body) = describe("REPLY", &r, "ada@example.com", Some(PartStat::Accepted));
    assert_eq!(subject, "Accepted: Planning, weekly");
    let to = vec!["bob@example.org".to_owned()];
    let refs = vec!["thread-0@example.org".to_owned()];
    let out = Outgoing {
        from: "ada@example.com",
        to: &to,
        calendar: &r,
        method: "REPLY",
        subject: "Zusage: Planung für Übermorgen\r\nBcc: eve@example.net",
        text: &body,
        token: "01JD000000000000000000000Z",
        at: AT,
        in_reply_to: Some("<inv-1@example.org>"),
        references: &refs,
    };
    let mail = compose(&out);
    assert_eq!(compose(&out), mail);
    let s = text(&mail);
    assert!(s.contains("Message-ID: <01JD000000000000000000000Z.itip@example.com>\r\n"));
    assert!(s.contains("In-Reply-To: <inv-1@example.org>\r\n"));
    assert!(s.contains("References: <thread-0@example.org>\r\n <inv-1@example.org>\r\n"));
    assert!(s.contains("Date: Sat, 21 Nov 2026 12:00:00 +0000\r\n"));
    assert!(!s.contains("\r\nBcc:"));
    assert!(s.split("\r\n").all(|l| l.len() <= 998));
    assert!(!s.replace("\r\n", "").contains('\n'));
    let found = find(&mail).unwrap();
    assert_eq!(found.calendar, r);
    assert_eq!(found.recipients, to);
    let parsed = mail_parser::MessageParser::new().parse(&mail[..]).unwrap();
    assert_eq!(
        parsed.root().headers().subject(),
        Some("Zusage: Planung für ÜbermorgenBcc: eve@example.net")
    );
}

#[test]
fn rejects_broken_calendars() {
    for bad in [
        &b""[..],
        b"BEGIN:VEVENT\r\nEND:VEVENT\r\n",
        b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nEND:VCALENDAR\r\n",
        b"BEGIN:VCALENDAR\r\nnonsense\r\nEND:VCALENDAR\r\n",
        b" folded\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
        b"BEGIN:VCALENDAR\r\nX;P=\"open:END:VCALENDAR\r\n",
    ] {
        assert!(facts(bad).is_err(), "{:?}", text(bad));
    }
    let deep = format!(
        "BEGIN:VCALENDAR\r\n{}{}END:VCALENDAR\r\n",
        "BEGIN:X\r\n".repeat(20),
        "END:X\r\n".repeat(20)
    );
    assert!(facts(deep.as_bytes()).is_err());
    assert_eq!(
        facts(&vec![b'a'; MAX_CALENDAR + 1]),
        Err(ItipError::TooLarge)
    );
}

#[test]
fn addresses_with_multibyte_text_near_the_scheme_are_read() {
    assert_eq!(
        address("mailto\u{e9}x@example.com"),
        "mailto\u{e9}x@example.com"
    );
    assert_eq!(address(" MAILTO:Ada@Example.com "), "ada@example.com");
    assert_eq!(address("mailto:mailto: bob@example.org"), "bob@example.org");
    let calendar = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:u1\r\n\
ORGANIZER:mailto:ada@example.com\r\nATTENDEE:mail:\u{fffd}x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    assert_eq!(summary(calendar.as_bytes()).unwrap().attendees.len(), 1);
}

#[test]
fn built_messages_give_instances_the_series_uid() {
    let calendar = b"BEGIN:VCALENDAR\nMETHOD:REQUEST\nBEGIN:VEVENT\nUID:u1@example.org\n\
DTSTART:20261124T100000Z\nRRULE:FREQ=WEEKLY\nORGANIZER:mailto:ada@example.com\nEND:VEVENT\n\
BEGIN:VEVENT\nRECURRENCE-ID:20261201T100000Z\nORGANIZER:mailto:ada@example.com\n\
ATTENDEE:mailto:dave@example.org\nEND:VEVENT\nEND:VCALENDAR\n";
    let answer = reply(calendar, "dave@example.org", PartStat::Accepted, None, AT).unwrap();
    assert_eq!(summary(&answer).unwrap().uid, "u1@example.org");
    let request = request(calendar, AT).unwrap();
    assert_eq!(unfold(&request).matches("UID:u1@example.org").count(), 2);
    let without = b"BEGIN:VCALENDAR\nBEGIN:VEVENT\nORGANIZER:mailto:ada@example.com\n\
ATTENDEE:mailto:dave@example.org\nEND:VEVENT\nEND:VCALENDAR\n";
    assert_eq!(
        super::request(without, AT),
        Err(ItipError::Invalid("no UID"))
    );
    assert_eq!(
        cancel(without, None, None, AT),
        Err(ItipError::Invalid("no UID"))
    );
}

#[test]
fn control_characters_in_values_are_not_part_of_the_address() {
    let calendar = b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:u1\r\n\
ORGANIZER:mailto:ada@example.com\r\nATTENDEE;PARTSTAT=DECLINED:mailto:dave@example.org\r\0\0\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";
    let who = &facts(calendar).unwrap().attendees[0].address;
    assert_eq!(who, "dave@example.org");
    let answered = set_partstat(calendar, who, PartStat::Accepted, None).unwrap();
    let again = set_partstat(&answered, who, PartStat::Accepted, None).unwrap();
    assert_eq!(again, answered);
}

proptest! {
    #[test]
    fn parsing_never_panics(input in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = facts(&input);
        let _ = summary(&input);
        let _ = find(&input);
    }

    #[test]
    fn written_text_survives_a_round_trip(comment in "\\PC{0,200}") {
        let out = set_partstat(REQUEST, "ada@example.com", PartStat::Accepted, Some(&comment)).unwrap();
        let root = ical::parse(&out).unwrap();
        let ev = root.children.iter().find(|c| c.name == "VEVENT").unwrap();
        let expected: String = comment.chars().filter(|c| !c.is_control() || *c == '\n').collect();
        prop_assert_eq!(ical::unescape(&ev.prop("COMMENT").unwrap().value), expected);
        for line in String::from_utf8(out.to_vec()).unwrap().split("\r\n") {
            prop_assert!(line.len() <= 75);
        }
    }
}

const ONE_INSTANCE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\nMETHOD:REQUEST\r\n\
BEGIN:VTIMEZONE\r\nTZID:America/New_York\r\nBEGIN:STANDARD\r\nDTSTART:19701101T020000\r\n\
RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU\r\nTZOFFSETFROM:-0400\r\nTZOFFSETTO:-0500\r\nEND:STANDARD\r\n\
END:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:standup@example.org\r\nDTSTAMP:20261120T090000Z\r\nSEQUENCE:4\r\n\
RECURRENCE-ID;TZID=America/New_York:20261203T090000\r\n\
DTSTART;TZID=America/New_York:20261203T110000\r\nDURATION:PT15M\r\nSUMMARY:Standup (moved)\r\n\
ORGANIZER:mailto:bob@example.org\r\nATTENDEE;RSVP=TRUE:mailto:ada@example.com\r\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";

#[test]
fn a_reply_to_one_instance_keeps_its_recurrence_id_and_time_zone() {
    let s = summary(ONE_INSTANCE.as_bytes()).unwrap();
    assert_eq!(s.recurrence_id.as_deref(), Some("20261203T090000"));
    let r = reply(
        ONE_INSTANCE.as_bytes(),
        "ada@example.com",
        PartStat::Declined,
        None,
        AT,
    )
    .unwrap();
    let t = unfold(&r);
    assert!(t.contains("TZID:America/New_York"));
    assert!(t.contains("RECURRENCE-ID;TZID=America/New_York:20261203T090000"));
    assert!(t.contains("DURATION:PT15M"));
    assert!(t.contains("SEQUENCE:4"));
    assert_eq!(t.matches("BEGIN:VEVENT").count(), 1);
}

#[test]
fn exceptions_and_floating_times_survive_untouched() {
    let floating = OWN
        .replace(
            "DTSTART:20261130T090000Z",
            "DTSTART:20261130T090000\r\nRRULE:FREQ=DAILY;COUNT=5\r\nEXDATE:20261202T090000",
        )
        .replace("DTEND:20261130T100000Z", "DTEND:20261130T100000");
    let out = set_partstat(
        floating.as_bytes(),
        "bob@example.org",
        PartStat::Accepted,
        None,
    )
    .unwrap();
    let t = unfold(&out);
    assert!(t.contains("DTSTART:20261130T090000\r\n"));
    assert!(t.contains("RRULE:FREQ=DAILY;COUNT=5\r\n"));
    assert!(t.contains("EXDATE:20261202T090000\r\n"));
    let req = unfold(&request(floating.as_bytes(), AT).unwrap());
    assert!(req.contains("EXDATE:20261202T090000\r\n"));
    let cancel = unfold(&cancel(floating.as_bytes(), None, None, AT).unwrap());
    assert!(cancel.contains("DTSTART:20261130T090000\r\n"));
}
