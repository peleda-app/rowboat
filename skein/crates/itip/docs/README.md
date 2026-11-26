# skein-itip

Reading and building iTIP messages (RFC 5546) and the mail that carries them (iMIP, RFC 6047).
Pure functions over bytes: no I/O, no state. What is not touched is kept as written (unknown
properties and parameters, time zones), lines are written with CRLF and folded at 75 octets, and
the same input always gives the same bytes. Control characters other than tab are not part of a
value (RFC 5545 `VALUE-CHAR`): they are dropped when reading, so an address read from an object
is the address a message built from it carries, and building from a built message gives the same
bytes. Every component of a built message names the series' `UID` (an instance without one gets
it); an object whose series has no `UID` cannot be built from.

The engine uses it to journal `itip_received`, to answer invitations and to mail organizer
changes where the calendar server does not schedule. Consumers may use it to read what the
journal holds; Skein never decides whether to trust or apply an incoming message.

## API

| Item | Guarantees |
| --- | --- |
| `summary(calendar)` | the facts of an iTIP message (`METHOD` required): method, component, `UID`, `SEQUENCE`, `RECURRENCE-ID`, organizer, up to 100 attendees with `PARTSTAT` and `RSVP` (`skein_core::ItipSummary`) |
| `facts(object)` | the facts of a stored object or a message: `UID`, highest `SEQUENCE`, organizer and its `SCHEDULE-AGENT`, every attendee of the series and its instances once, `SUMMARY` as text; `Facts::own_attendee`, `Facts::organized_by` |
| `set_partstat(object, attendee, answer, comment)` | the attendee's `PARTSTAT` on the series and every instance they are on, `RSVP` and `SCHEDULE-STATUS` dropped, `COMMENT` set; everything else kept (what an attendee's client writes, RFC 6638 section 3.2.2.1) |
| `reply(source, attendee, answer, comment, at)` | a `REPLY` from a `REQUEST`, `ADD`, `PUBLISH` or a stored copy without `METHOD`: one component per series or instance the attendee is on, with `UID`, `SEQUENCE`, `RECURRENCE-ID`, `ORGANIZER`, times, `SUMMARY`, `LOCATION`, the one attendee and `DTSTAMP` = `at`; time zones copied |
| `request(object, at)` | a `REQUEST`: the object with `METHOD:REQUEST`, alarms and server-written scheduling parameters removed, `DTSTAMP` = `at` |
| `cancel(object, only, sequence, at)` | a `CANCEL` naming every attendee, or only `only` (removed attendees); `SEQUENCE` given, or one more than the object's |
| `plan(previous, next)` | whom an organizer's create, update or delete must tell when the writer schedules: `REQUEST` to every attendee of `next`, `CANCEL` to attendees only in `previous` (all of them for a delete); `SCHEDULE-AGENT=CLIENT` or `NONE` attendees and the organizer itself left out; `None` without an organizer |
| `imip::may_carry_calendar(message)` | a byte scan: false means the message certainly has no calendar part |
| `imip::find(message)` | the first `text/calendar` or `application/ics` part with a `METHOD` (forwarded messages not looked at), with `To`/`Cc`, `Message-ID` and `References` |
| `imip::read(bytes)` | the same from a whole message or a bare iCalendar object |
| `imip::compose(&Outgoing)` | an RFC 6047 message: `multipart/alternative` with base64 text and `text/calendar; method=...` parts, `Message-ID` from a token, `In-Reply-To` and `References`, RFC 2047 subject; header values lose control characters |
| `imip::describe(method, calendar, sender, answer)` | plain English subject and text such as `Accepted: Planning` |
| `ItipError` | `Invalid`, `TooLarge` (over 4 MiB), `NoComponent`, `WrongMethod`, `NoOrganizer`, `AttendeeNotFound`, `NoCalendarPart`; `reason()` gives a short code; messages never carry content or addresses |
| `address(value)` | an address without `mailto:` (stripped however often it repeats), trimmed, lower case; applying it twice gives the same address |

## Limits

Objects over 4 MiB are refused, components nest at most 8 deep, and parsing never panics
(checked with property tests). Addresses passed to `compose` are written as given, so callers
check them with `skein_core::plausible_address` first.
