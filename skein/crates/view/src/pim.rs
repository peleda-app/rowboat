use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Largest object parsed; larger ones keep only their metadata.
pub const OBJECT_CAP: usize = skein_itip::MAX_CALENDAR;
/// Most attendees, addresses or phone numbers kept per object.
pub const LIST_CAP: usize = 100;
/// Most characters kept of a summary, name or organization.
pub const TEXT_CHARS: usize = 1000;
const DAY_MS: i64 = 86_400_000;
const MAX_LINES: usize = 100_000;
const MAX_DEPTH: usize = 8;

/// How an object's bytes are written, from its media type as the connector set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// `text/calendar`.
    Icalendar,
    /// `text/vcard`.
    Vcard,
    /// `application/jscalendar+json` (JMAP).
    Jscalendar,
    /// `application/jscontact+json` (JMAP).
    Jscontact,
    /// `application/json; profile=google-calendar-event`.
    GoogleEvent,
    /// `application/json; profile=google-people-person`.
    GooglePerson,
    /// `application/json; profile=graph-event`.
    GraphEvent,
    /// `application/json; profile=graph-contact`.
    GraphContact,
    /// Anything else: stored, served raw, not parsed.
    Other,
}

impl Format {
    /// The format of a media type; parameters other than `profile` are ignored.
    pub fn of(content_type: &str) -> Self {
        let lower = content_type.to_ascii_lowercase();
        let mut parts = lower.split(';').map(str::trim);
        let essence = parts.next().unwrap_or_default();
        let profile = parts
            .filter_map(|p| p.strip_prefix("profile="))
            .map(|p| p.trim_matches('"'))
            .next();
        match (essence, profile) {
            ("text/calendar", _) => Self::Icalendar,
            ("text/vcard" | "text/x-vcard", _) => Self::Vcard,
            ("application/jscalendar+json", _) => Self::Jscalendar,
            ("application/jscontact+json", _) => Self::Jscontact,
            ("application/json", Some("google-calendar-event")) => Self::GoogleEvent,
            ("application/json", Some("google-people-person")) => Self::GooglePerson,
            ("application/json", Some("graph-event")) => Self::GraphEvent,
            ("application/json", Some("graph-contact")) => Self::GraphContact,
            _ => Self::Other,
        }
    }

    /// What objects in this format usually are: `contact`, `event` or `other`. iCalendar
    /// objects are refined to `task` when parsed.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Vcard | Self::Jscontact | Self::GooglePerson | Self::GraphContact => "contact",
            Self::Other => "other",
            _ => "event",
        }
    }

    /// The name stored and returned, such as `icalendar`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Icalendar => "icalendar",
            Self::Vcard => "vcard",
            Self::Jscalendar => "jscalendar",
            Self::Jscontact => "jscontact",
            Self::GoogleEvent => "google_event",
            Self::GooglePerson => "google_person",
            Self::GraphEvent => "graph_event",
            Self::GraphContact => "graph_contact",
            Self::Other => "other",
        }
    }
}

/// What the view keeps of an event, task or contact. Derived from the original bytes, never
/// authoritative; every field may be missing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectFields {
    /// `event`, `task`, `contact` or `other`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The `UID` of the event or contact.
    pub uid: Option<String>,
    /// The event or task title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Start in milliseconds since the epoch, UTC (see the docs for how zones are read).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<i64>,
    /// End, exclusive, in milliseconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    /// Whether the event lasts whole days.
    pub all_day: bool,
    /// The time zone the start is written in, as the object names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tzid: Option<String>,
    /// Whether the object carries a recurrence rule or extra dates; instances are not expanded.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recurring: bool,
    /// The status in upper case, such as `CONFIRMED` or `CANCELLED`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The organizer's address, lower case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organizer: Option<String>,
    /// Attendee addresses, lower case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attendees: Vec<String>,
    /// The contact's display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// Contact addresses, lower case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Phone numbers, as written.
    pub phones: Vec<String>,
    /// The organization's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// An object as the view stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedObject {
    pub format: Format,
    /// False when the bytes could not be read from Skein, or could not be parsed.
    pub available: bool,
    pub fields: ObjectFields,
}

/// Parses an object's bytes by its media type. Never fails: missing or unreadable bytes give
/// an object that is not available, and unknown formats keep only their metadata.
pub fn parse_object(content_type: &str, bytes: Option<&[u8]>) -> ParsedObject {
    let format = Format::of(content_type);
    let fallback = |available| ParsedObject {
        format,
        available,
        fields: ObjectFields {
            kind: format.kind().into(),
            ..ObjectFields::default()
        },
    };
    let Some(bytes) = bytes.filter(|b| b.len() <= OBJECT_CAP) else {
        return fallback(false);
    };
    let fields = match format {
        Format::Icalendar => icalendar(bytes),
        Format::Vcard => vcard(bytes),
        Format::Other => return fallback(true),
        json_format => serde_json::from_slice::<Value>(bytes)
            .ok()
            .filter(Value::is_object)
            .map(|v| match json_format {
                Format::GoogleEvent => google_event(&v),
                Format::GooglePerson => google_person(&v),
                Format::GraphEvent => graph_event(&v),
                Format::GraphContact => graph_contact(&v),
                Format::Jscalendar => jscalendar(&v),
                _ => jscontact(&v),
            }),
    };
    match fields {
        Some(mut fields) => {
            tidy(&mut fields);
            ParsedObject {
                format,
                available: true,
                fields,
            }
        }
        None => fallback(false),
    }
}

fn cap(text: &str) -> Option<String> {
    let t = text.trim();
    (!t.is_empty()).then(|| t.chars().take(TEXT_CHARS).collect())
}

fn tidy(f: &mut ObjectFields) {
    for list in [&mut f.attendees, &mut f.emails] {
        for a in list.iter_mut() {
            *a = skein_itip::address(a);
        }
    }
    for list in [&mut f.attendees, &mut f.emails, &mut f.phones] {
        list.retain(|a| !a.is_empty());
        let mut seen = Vec::new();
        list.retain(|a| {
            let new = !seen.contains(a);
            seen.push(a.clone());
            new
        });
        list.truncate(LIST_CAP);
        for a in list.iter_mut() {
            *a = a.chars().take(TEXT_CHARS).collect();
        }
    }
    f.organizer = f.organizer.as_deref().map(skein_itip::address);
    f.organizer = f.organizer.take().filter(|o| !o.is_empty());
    for s in [
        &mut f.uid,
        &mut f.summary,
        &mut f.full_name,
        &mut f.org,
        &mut f.tzid,
        &mut f.status,
    ] {
        *s = s.as_deref().and_then(cap);
    }
    f.status = f.status.take().map(|s| s.to_ascii_uppercase());
    if let (Some(s), Some(e)) = (f.start, f.end)
        && e < s
    {
        f.end = Some(s);
    }
}

#[derive(Debug, Default)]
struct Line {
    name: String,
    params: Vec<(String, String)>,
    value: String,
}

impl Line {
    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Default)]
struct Comp {
    name: String,
    props: Vec<Line>,
    children: Vec<Comp>,
}

impl Comp {
    fn prop(&self, name: &str) -> Option<&Line> {
        self.props.iter().find(|p| p.name == name)
    }

    fn props<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Line> {
        self.props.iter().filter(move |p| p.name == name)
    }

    fn text(&self, name: &str) -> Option<String> {
        self.prop(name).map(|p| unescape(&p.value))
    }
}

fn content_line(raw: &str) -> Option<Line> {
    let mut quoted = false;
    let mut split = None;
    for (i, c) in raw.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ':' if !quoted => {
                split = Some(i);
                break;
            }
            _ => {}
        }
    }
    let split = split?;
    let (head, value) = (&raw[..split], &raw[split + 1..]);
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (i, c) in head.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                parts.push(&head[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&head[start..]);
    let mut parts = parts.into_iter();
    let name = parts.next()?.trim();
    let name = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
    if name.is_empty() {
        return None;
    }
    let params = parts
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k.trim().to_ascii_uppercase(), v.replace('"', "")))
        })
        .collect();
    Some(Line {
        name,
        params,
        value: value.to_owned(),
    })
}

fn components(bytes: &[u8]) -> Option<Comp> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = raw.strip_prefix([' ', '\t']) {
            if let Some(last) = lines.last_mut() {
                last.push_str(rest);
            }
        } else if !raw.trim().is_empty() {
            if lines.len() >= MAX_LINES {
                return None;
            }
            lines.push(raw.to_owned());
        }
    }
    let mut stack: Vec<Comp> = Vec::new();
    for raw in lines {
        let Some(line) = content_line(&raw) else {
            continue;
        };
        match line.name.as_str() {
            "BEGIN" => {
                if stack.len() >= MAX_DEPTH {
                    return None;
                }
                stack.push(Comp {
                    name: line.value.trim().to_ascii_uppercase(),
                    ..Comp::default()
                });
            }
            "END" => {
                let done = stack.pop()?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(done),
                    None => return Some(done),
                }
            }
            _ => stack.last_mut()?.props.push(line),
        }
    }
    None
}

fn components_of(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('n' | 'N') => cur.push('\n'),
                Some(other) => cur.push(other),
                None => {}
            },
            ';' => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => out.push('\n'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// Milliseconds since the epoch of a civil date and time, proleptic Gregorian, UTC.
fn civil_ms(year: i64, month: u32, day: u32, h: u32, m: u32, s: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || h > 23 || m > 59 || s > 60 {
        return None;
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * DAY_MS + i64::from(h * 3600 + m * 60 + s.min(59)) * 1000)
}

fn digits(s: &str) -> Option<u32> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// A local date-time read from either `20261121T093000` or `2026-11-21T09:30:00(.fff)`.
/// Returns (ms as if UTC, date only, the zone suffix: `Z`, `+01:00` or empty).
fn local_time(raw: &str) -> Option<(i64, bool, &str)> {
    let raw = raw.trim();
    let (date, rest) = match raw.split_once('T') {
        Some((d, r)) => (d, Some(r)),
        None => (raw, None),
    };
    let date_digits: String = date.chars().filter(|c| *c != '-').collect();
    if date_digits.len() != 8 {
        return None;
    }
    let y = i64::from(digits(&date_digits[..4])?);
    let mo = digits(&date_digits[4..6])?;
    let d = digits(&date_digits[6..8])?;
    let Some(rest) = rest else {
        return Some((civil_ms(y, mo, d, 0, 0, 0)?, true, ""));
    };
    let zone_at = rest.find(['Z', 'z', '+', '-']).unwrap_or(rest.len());
    let (time, zone) = rest.split_at(zone_at);
    let time = time.split('.').next().unwrap_or_default();
    let compact: String = time.chars().filter(|c| *c != ':').collect();
    if compact.len() < 4 {
        return None;
    }
    let h = digits(&compact[..2])?;
    let mi = digits(&compact[2..4])?;
    let s = if compact.len() >= 6 {
        digits(&compact[4..6])?
    } else {
        0
    };
    Some((civil_ms(y, mo, d, h, mi, s)?, false, zone))
}

/// `+0100`, `-05:30`, `+013000` as milliseconds east of UTC.
fn offset_ms(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    let sign = match raw.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let d: String = raw[1..].chars().filter(|c| *c != ':').collect();
    if d.len() < 4 {
        return None;
    }
    let h = i64::from(digits(&d[..2])?);
    let m = i64::from(digits(&d[2..4])?);
    let s = if d.len() >= 6 {
        i64::from(digits(&d[4..6])?)
    } else {
        0
    };
    Some(sign * ((h * 60 + m) * 60 + s) * 1000)
}

/// RFC 3339 or a zone-less local time taken as UTC.
fn json_time(raw: &str) -> Option<i64> {
    let (ms, _, zone) = local_time(raw)?;
    match zone {
        "" | "Z" | "z" => Some(ms),
        z => Some(ms - offset_ms(z)?),
    }
}

/// An iCalendar or ISO 8601 duration (`P1W`, `PT1H30M`, `-P1D`) in milliseconds.
fn duration_ms(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    let (sign, rest) = match raw.strip_prefix('-') {
        Some(r) => (-1, r),
        None => (1, raw.strip_prefix('+').unwrap_or(raw)),
    };
    let rest = rest.strip_prefix(['P', 'p'])?;
    let mut total = 0i64;
    let mut number = String::new();
    let mut in_time = false;
    for c in rest.chars() {
        match c.to_ascii_uppercase() {
            '0'..='9' => number.push(c),
            '.' | ',' => return None,
            'T' => in_time = true,
            unit => {
                let n: i64 = number.parse().ok()?;
                number.clear();
                total += n * match (unit, in_time) {
                    ('W', false) => 7 * DAY_MS,
                    ('D', false) => DAY_MS,
                    ('H', true) => 3_600_000,
                    ('M', true) => 60_000,
                    ('S', true) => 1000,
                    _ => return None,
                };
            }
        }
    }
    number.is_empty().then_some(sign * total)
}

fn zone_offset(root: &Comp, tzid: &str) -> Option<i64> {
    let zone = root.children.iter().find(|c| {
        c.name == "VTIMEZONE" && c.prop("TZID").is_some_and(|p| p.value.trim() == tzid)
    })?;
    let part = zone
        .children
        .iter()
        .find(|c| c.name == "STANDARD")
        .or_else(|| zone.children.first())?;
    offset_ms(&part.prop("TZOFFSETTO")?.value)
}

/// (UTC ms, all day, tzid) of a DTSTART-like property.
fn ical_time(root: &Comp, p: &Line) -> Option<(i64, bool, Option<String>)> {
    let (ms, date_only, zone) = local_time(&p.value)?;
    let all_day = date_only
        || p.param("VALUE")
            .is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
    if all_day || matches!(zone, "Z" | "z") {
        return Some((ms, all_day, None));
    }
    let tzid = p.param("TZID").map(|t| t.trim().to_owned());
    let offset = tzid
        .as_deref()
        .and_then(|t| zone_offset(root, t))
        .unwrap_or(0);
    Some((ms - offset, false, tzid))
}

fn icalendar(bytes: &[u8]) -> Option<ObjectFields> {
    let root = components(bytes).filter(|c| c.name == "VCALENDAR")?;
    let scheduling = |c: &&Comp| matches!(c.name.as_str(), "VEVENT" | "VTODO" | "VJOURNAL");
    let c = root
        .children
        .iter()
        .filter(scheduling)
        .find(|c| c.prop("RECURRENCE-ID").is_none())
        .or_else(|| root.children.iter().find(scheduling));
    let Some(c) = c else {
        return Some(ObjectFields {
            kind: "other".into(),
            ..ObjectFields::default()
        });
    };
    let task = c.name == "VTODO";
    let mut f = ObjectFields {
        kind: match c.name.as_str() {
            "VEVENT" => "event",
            "VTODO" => "task",
            _ => "other",
        }
        .into(),
        uid: c.text("UID"),
        summary: c.text("SUMMARY"),
        status: c.text("STATUS"),
        recurring: c.prop("RRULE").is_some() || c.prop("RDATE").is_some(),
        organizer: c.prop("ORGANIZER").map(|p| p.value.clone()),
        attendees: c.props("ATTENDEE").map(|p| p.value.clone()).collect(),
        ..ObjectFields::default()
    };
    if let Ok(facts) = skein_itip::facts(bytes) {
        f.uid = Some(facts.uid);
        f.summary = facts.summary.or(f.summary);
        f.organizer = facts.organizer.or(f.organizer);
        f.attendees = facts.attendees.into_iter().map(|a| a.address).collect();
    }
    let start = c.prop("DTSTART").and_then(|p| ical_time(&root, p));
    if let Some((ms, all_day, tzid)) = &start {
        f.start = Some(*ms);
        f.all_day = *all_day;
        f.tzid.clone_from(tzid);
    }
    let end_prop = if task { "DUE" } else { "DTEND" };
    f.end = c
        .prop(end_prop)
        .and_then(|p| ical_time(&root, p))
        .map(|(ms, _, _)| ms)
        .or_else(|| {
            let start = f.start?;
            match c.prop("DURATION").and_then(|p| duration_ms(&p.value)) {
                Some(d) => Some(start + d),
                None if task => None,
                None if f.all_day => Some(start + DAY_MS),
                None => Some(start),
            }
        });
    if task && f.start.is_none() {
        f.start = f.end;
    }
    Some(f)
}

fn vcard(bytes: &[u8]) -> Option<ObjectFields> {
    let c = components(bytes).filter(|c| c.name == "VCARD")?;
    let full_name = c.text("FN").or_else(|| {
        let n = c.prop("N")?;
        let parts = components_of(&n.value);
        let given = parts.get(1).map(String::as_str).unwrap_or_default();
        let family = parts.first().map(String::as_str).unwrap_or_default();
        cap(&format!("{given} {family}"))
    });
    let org = c
        .prop("ORG")
        .and_then(|p| components_of(&p.value).first().and_then(|o| cap(o)));
    Some(ObjectFields {
        kind: "contact".into(),
        uid: c.text("UID"),
        full_name,
        emails: c.props("EMAIL").map(|p| unescape(&p.value)).collect(),
        phones: c
            .props("TEL")
            .map(|p| {
                let v = unescape(&p.value);
                v.strip_prefix("tel:").map(str::to_owned).unwrap_or(v)
            })
            .collect(),
        org,
        ..ObjectFields::default()
    })
}

fn s(v: &Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str().map(str::to_owned)
}

fn each<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    let items: Vec<&Value> = match v.get(key) {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(Value::Object(m)) => m.values().collect(),
        _ => Vec::new(),
    };
    items.into_iter()
}

fn non_empty(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        Some(Value::Null) | None => false,
        Some(_) => true,
    }
}

fn google_time(v: &Value, key: &str) -> Option<(i64, bool, Option<String>)> {
    let t = v.get(key)?;
    let tz = s(t, &["timeZone"]);
    if let Some(dt) = s(t, &["dateTime"]) {
        return Some((json_time(&dt)?, false, tz));
    }
    let (ms, _, _) = local_time(&s(t, &["date"])?)?;
    Some((ms, true, None))
}

fn google_event(v: &Value) -> ObjectFields {
    let start = google_time(v, "start");
    let end = google_time(v, "end");
    ObjectFields {
        kind: "event".into(),
        uid: s(v, &["iCalUID"]).or_else(|| s(v, &["id"])),
        summary: s(v, &["summary"]),
        start: start.as_ref().map(|t| t.0),
        end: end.map(|t| t.0),
        all_day: start.as_ref().is_some_and(|t| t.1),
        tzid: start.and_then(|t| t.2),
        recurring: non_empty(v, "recurrence"),
        status: s(v, &["status"]),
        organizer: s(v, &["organizer", "email"]),
        attendees: each(v, "attendees")
            .filter_map(|a| s(a, &["email"]))
            .collect(),
        ..ObjectFields::default()
    }
}

fn google_person(v: &Value) -> ObjectFields {
    ObjectFields {
        kind: "contact".into(),
        uid: s(v, &["resourceName"]),
        full_name: each(v, "names").find_map(|n| s(n, &["displayName"])),
        emails: each(v, "emailAddresses")
            .filter_map(|e| s(e, &["value"]))
            .collect(),
        phones: each(v, "phoneNumbers")
            .filter_map(|e| s(e, &["value"]))
            .collect(),
        org: each(v, "organizations").find_map(|o| s(o, &["name"])),
        ..ObjectFields::default()
    }
}

fn graph_time(v: &Value, key: &str) -> Option<(i64, Option<String>)> {
    let t = v.get(key)?;
    Some((json_time(&s(t, &["dateTime"])?)?, s(t, &["timeZone"])))
}

fn graph_event(v: &Value) -> ObjectFields {
    let start = graph_time(v, "start");
    ObjectFields {
        kind: "event".into(),
        uid: s(v, &["iCalUId"]).or_else(|| s(v, &["id"])),
        summary: s(v, &["subject"]),
        start: start.as_ref().map(|t| t.0),
        end: graph_time(v, "end").map(|t| t.0),
        all_day: v.get("isAllDay").and_then(Value::as_bool) == Some(true),
        tzid: start.and_then(|t| t.1),
        recurring: non_empty(v, "recurrence"),
        status: (v.get("isCancelled").and_then(Value::as_bool) == Some(true))
            .then(|| "CANCELLED".to_owned()),
        organizer: s(v, &["organizer", "emailAddress", "address"]),
        attendees: each(v, "attendees")
            .filter_map(|a| s(a, &["emailAddress", "address"]))
            .collect(),
        ..ObjectFields::default()
    }
}

fn graph_contact(v: &Value) -> ObjectFields {
    let mut phones: Vec<String> = each(v, "businessPhones")
        .chain(each(v, "homePhones"))
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect();
    phones.extend(s(v, &["mobilePhone"]));
    ObjectFields {
        kind: "contact".into(),
        uid: s(v, &["id"]),
        full_name: s(v, &["displayName"]),
        emails: each(v, "emailAddresses")
            .filter_map(|e| s(e, &["address"]))
            .collect(),
        phones,
        org: s(v, &["companyName"]),
        ..ObjectFields::default()
    }
}

fn jscalendar(v: &Value) -> ObjectFields {
    let task = s(v, &["@type"]).is_some_and(|t| t.eq_ignore_ascii_case("task"));
    let tz = s(v, &["timeZone"]);
    let utc = tz
        .as_deref()
        .is_none_or(|z| matches!(z, "UTC" | "Etc/UTC" | "Z"));
    let at = |key: &str| s(v, &[key]).and_then(|t| json_time(&t));
    let start = at("start");
    let all_day = v.get("showWithoutTime").and_then(Value::as_bool) == Some(true);
    let end = if task {
        at("due")
    } else {
        start.map(|st| {
            st + s(v, &["duration"])
                .and_then(|d| duration_ms(&d))
                .unwrap_or(0)
        })
    };
    let mut organizer = s(v, &["replyTo", "imip"]);
    let mut attendees = Vec::new();
    for p in each(v, "participants") {
        let address = s(p, &["email"]).or_else(|| s(p, &["sendTo", "imip"]));
        let owner = p
            .get("roles")
            .and_then(|r| r.get("owner"))
            .and_then(Value::as_bool)
            == Some(true);
        if let Some(a) = address {
            if owner && organizer.is_none() {
                organizer = Some(a.clone());
            }
            attendees.push(a);
        }
    }
    ObjectFields {
        kind: if task { "task" } else { "event" }.into(),
        uid: s(v, &["uid"]),
        summary: s(v, &["title"]),
        start: start.or(end.filter(|_| task)),
        end,
        all_day,
        tzid: tz.filter(|_| !utc),
        recurring: non_empty(v, "recurrenceRules") || non_empty(v, "recurrenceOverrides"),
        status: s(v, &["status"]).or_else(|| s(v, &["progress"])),
        organizer,
        attendees,
        ..ObjectFields::default()
    }
}

fn jscontact(v: &Value) -> ObjectFields {
    let full_name = s(v, &["name", "full"]).or_else(|| {
        let parts: Vec<String> = each(v.get("name").unwrap_or(&Value::Null), "components")
            .filter_map(|c| s(c, &["value"]))
            .collect();
        cap(&parts.join(" "))
    });
    ObjectFields {
        kind: "contact".into(),
        uid: s(v, &["uid"]),
        full_name: full_name.or_else(|| s(v, &["fullName"])),
        emails: each(v, "emails")
            .filter_map(|e| s(e, &["address"]).or_else(|| s(e, &["email"])))
            .collect(),
        phones: each(v, "phones")
            .filter_map(|p| s(p, &["number"]).or_else(|| s(p, &["phone"])))
            .collect(),
        org: each(v, "organizations").find_map(|o| s(o, &["name"])),
        ..ObjectFields::default()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::parse::tests::fixture;

    fn ms(y: i64, mo: u32, d: u32, h: u32, mi: u32) -> i64 {
        civil_ms(y, mo, d, h, mi, 0).unwrap()
    }

    pub(crate) fn day(y: i64, mo: u32, d: u32) -> i64 {
        ms(y, mo, d, 0, 0)
    }

    #[test]
    fn civil_time_matches_known_instants() {
        assert_eq!(ms(1970, 1, 1, 0, 0), 0);
        assert_eq!(ms(2026, 11, 21, 0, 0), 1_795_219_200_000);
        assert_eq!(ms(2000, 2, 29, 12, 0), 951_825_600_000);
        assert_eq!(
            json_time("2026-11-21T10:00:00+02:00"),
            Some(ms(2026, 11, 21, 8, 0))
        );
        assert_eq!(
            json_time("2026-11-21T10:00:00.0000000"),
            Some(ms(2026, 11, 21, 10, 0))
        );
        assert_eq!(duration_ms("PT1H30M"), Some(5_400_000));
        assert_eq!(duration_ms("P1W"), Some(7 * DAY_MS));
        assert_eq!(duration_ms("-P1D"), Some(-DAY_MS));
        assert_eq!(duration_ms("P1Y"), None);
        assert_eq!(
            Format::of("Text/Calendar; charset=utf-8"),
            Format::Icalendar
        );
        assert_eq!(
            Format::of("application/json; profile=graph-event"),
            Format::GraphEvent
        );
        assert_eq!(Format::of("application/json"), Format::Other);
    }

    #[test]
    fn reads_an_event_with_its_zone() {
        let o = parse_object("text/calendar", Some(&fixture("event.ics")));
        assert!(o.available);
        let f = o.fields;
        assert_eq!(f.kind, "event");
        assert_eq!(f.uid.as_deref(), Some("plant-swap@example.com"));
        assert_eq!(f.summary.as_deref(), Some("Plant swap, garden shed"));
        assert_eq!(f.tzid.as_deref(), Some("Europe/Example"));
        assert_eq!(f.start, Some(ms(2026, 12, 5, 9, 0)), "10:00 at +0100");
        assert_eq!(f.end, Some(ms(2026, 12, 5, 10, 30)));
        assert!(f.recurring);
        assert_eq!(f.status.as_deref(), Some("CONFIRMED"));
        assert_eq!(f.organizer.as_deref(), Some("pat@example.com"));
        assert_eq!(f.attendees, vec!["sam@example.org", "lee@example.com"]);
    }

    #[test]
    fn reads_all_day_events_and_tasks() {
        let o = parse_object("text/calendar", Some(&fixture("allday.ics")));
        let f = o.fields;
        assert!(f.all_day);
        assert_eq!(f.start, Some(ms(2026, 12, 24, 0, 0)));
        assert_eq!(f.end, Some(ms(2026, 12, 25, 0, 0)));
        assert!(!f.recurring);
        let todo = b"BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:t1\r\nSUMMARY:Water the ferns\r\nDUE:20261201T170000Z\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        let f = parse_object("text/calendar", Some(todo)).fields;
        assert_eq!(f.kind, "task");
        assert_eq!(f.end, Some(ms(2026, 12, 1, 17, 0)));
        assert_eq!(f.start, f.end);
    }

    #[test]
    fn reads_a_vcard() {
        let f = parse_object("text/vcard", Some(&fixture("contact.vcf"))).fields;
        assert_eq!(f.kind, "contact");
        assert_eq!(f.full_name.as_deref(), Some("Jordan Example"));
        assert_eq!(
            f.emails,
            vec!["jordan@example.com", "j.example@example.org"]
        );
        assert_eq!(f.phones, vec!["+1-555-0100"]);
        assert_eq!(f.org.as_deref(), Some("Greenhouse; Inc."));
        assert_eq!(f.uid.as_deref(), Some("urn:uuid:contact-1"));
    }

    #[test]
    fn reads_provider_json() {
        let f = parse_object(
            "application/json; profile=google-calendar-event",
            Some(&fixture("google-event.json")),
        )
        .fields;
        assert_eq!(f.summary.as_deref(), Some("Seed exchange"));
        assert_eq!(f.start, Some(ms(2026, 12, 7, 17, 0)));
        assert_eq!(f.tzid.as_deref(), Some("America/Example"));
        assert!(f.recurring);
        assert_eq!(f.organizer.as_deref(), Some("pat@example.com"));
        assert_eq!(f.attendees, vec!["sam@example.org"]);
        assert_eq!(f.status.as_deref(), Some("CONFIRMED"));

        let f = parse_object(
            "application/json; profile=graph-event",
            Some(&fixture("graph-event.json")),
        )
        .fields;
        assert_eq!(f.summary.as_deref(), Some("Compost review"));
        assert_eq!(f.start, Some(ms(2026, 12, 8, 14, 0)));
        assert_eq!(f.end, Some(ms(2026, 12, 8, 15, 0)));
        assert_eq!(f.status.as_deref(), Some("CANCELLED"));

        let f = parse_object(
            "application/jscalendar+json",
            Some(&fixture("jscalendar.json")),
        )
        .fields;
        assert_eq!(f.summary.as_deref(), Some("Pruning class"));
        assert_eq!(f.end.zip(f.start).map(|(e, s)| e - s), Some(7_200_000));
        assert_eq!(f.organizer.as_deref(), Some("lee@example.com"));

        let f = parse_object(
            "application/jscontact+json",
            Some(&fixture("jscontact.json")),
        )
        .fields;
        assert_eq!(f.full_name.as_deref(), Some("Robin Sample"));
        assert_eq!(f.emails, vec!["robin@example.org"]);

        let f = parse_object(
            "application/json; profile=google-people-person",
            Some(br#"{"resourceName":"people/c1","names":[{"displayName":"Alex Demo"}],"emailAddresses":[{"value":"Alex@Example.com"}]}"#),
        )
        .fields;
        assert_eq!(f.full_name.as_deref(), Some("Alex Demo"));
        assert_eq!(f.emails, vec!["alex@example.com"]);

        let f = parse_object(
            "application/json; profile=graph-contact",
            Some(br#"{"id":"c2","displayName":"Casey Demo","emailAddresses":[{"address":"casey@example.org"}],"mobilePhone":"+1-555-0101","companyName":"Seeds Ltd"}"#),
        )
        .fields;
        assert_eq!(f.phones, vec!["+1-555-0101"]);
        assert_eq!(f.org.as_deref(), Some("Seeds Ltd"));
    }

    #[test]
    fn unreadable_or_unknown_objects_keep_metadata_only() {
        let o = parse_object("text/calendar", Some(b"not a calendar"));
        assert!(!o.available);
        assert_eq!(o.fields.kind, "event");
        let o = parse_object("application/octet-stream", Some(b"x"));
        assert!(o.available);
        assert_eq!(o.fields.kind, "other");
        let o = parse_object("text/vcard", None);
        assert!(!o.available);
        for junk in [
            &b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:9\r\n"[..],
            b"\xff\xfe",
            b"",
        ] {
            let _ = parse_object("text/calendar", Some(junk));
        }
    }
}
