use crate::ItipError;

/// The largest iCalendar object read.
pub const MAX_CALENDAR: usize = 4 << 20;
const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Param {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Property {
    pub name: String,
    pub params: Vec<Param>,
    pub value: String,
}

impl Property {
    pub fn new(name: &str, value: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            params: Vec::new(),
            value: value.into(),
        }
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
            .and_then(|p| p.values.first())
            .map(String::as_str)
    }

    pub fn set_param(&mut self, name: &str, value: &str) {
        self.remove_param(name);
        self.params.push(Param {
            name: name.to_owned(),
            values: vec![value.to_owned()],
        });
    }

    pub fn remove_param(&mut self, name: &str) {
        self.params.retain(|p| !p.name.eq_ignore_ascii_case(name));
    }

    pub fn address(&self) -> String {
        address(&self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Component {
    pub name: String,
    pub props: Vec<Property>,
    pub children: Vec<Component>,
}

impl Component {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            props: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn prop(&self, name: &str) -> Option<&Property> {
        self.props.iter().find(|p| p.name == name)
    }

    pub fn props_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Property> {
        self.props.iter().filter(move |p| p.name == name)
    }

    pub fn value(&self, name: &str) -> Option<&str> {
        self.prop(name).map(|p| p.value.trim())
    }

    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        match self.props.iter_mut().find(|p| p.name == name) {
            Some(p) => {
                p.params.clear();
                p.value = value;
            }
            None => self.props.push(Property::new(name, value)),
        }
        let mut first = true;
        self.props.retain(|p| {
            if p.name != name {
                return true;
            }
            std::mem::replace(&mut first, false)
        });
    }

    pub fn sequence(&self) -> u32 {
        self.value("SEQUENCE")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    pub fn is_scheduling(&self) -> bool {
        matches!(self.name.as_str(), "VEVENT" | "VTODO" | "VJOURNAL")
    }
}

/// An address without `mailto:` (however often it is repeated), trimmed and in lower case, so
/// `address(address(x)) == address(x)`.
pub fn address(value: &str) -> String {
    let mut v = value.trim();
    while let Some(scheme) = v.get(..7)
        && scheme.eq_ignore_ascii_case("mailto:")
    {
        v = v[7..].trim_start();
    }
    v.trim_end().to_ascii_lowercase()
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Component, ItipError> {
    if bytes.len() > MAX_CALENDAR {
        return Err(ItipError::TooLarge);
    }
    let text = String::from_utf8_lossy(bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = raw.strip_prefix([' ', '\t']) {
            match lines.last_mut() {
                Some(last) => last.push_str(rest),
                None => return Err(ItipError::Invalid("a folded line comes first")),
            }
        } else if !raw.trim().is_empty() {
            lines.push(raw.to_owned());
        }
    }
    let mut stack: Vec<Component> = Vec::new();
    let mut root: Option<Component> = None;
    for line in lines {
        if root.is_some() {
            return Err(ItipError::Invalid("content after the calendar"));
        }
        let prop = property(&line)?;
        match prop.name.as_str() {
            "BEGIN" => {
                if stack.len() >= MAX_DEPTH {
                    return Err(ItipError::Invalid("components nest too deep"));
                }
                let name = prop.value.trim().to_ascii_uppercase();
                if stack.is_empty() && name != "VCALENDAR" {
                    return Err(ItipError::Invalid("not a VCALENDAR"));
                }
                stack.push(Component::new(&name));
            }
            "END" => {
                let name = prop.value.trim().to_ascii_uppercase();
                let done = stack.pop().ok_or(ItipError::Invalid("END without BEGIN"))?;
                if done.name != name {
                    return Err(ItipError::Invalid("END does not match BEGIN"));
                }
                match stack.last_mut() {
                    Some(parent) => parent.children.push(done),
                    None => root = Some(done),
                }
            }
            _ => match stack.last_mut() {
                Some(current) => current.props.push(prop),
                None => return Err(ItipError::Invalid("a property outside the calendar")),
            },
        }
    }
    root.ok_or(ItipError::Invalid("the calendar does not end"))
}

fn property(line: &str) -> Result<Property, ItipError> {
    let bad = ItipError::Invalid("a line cannot be read");
    let end = line
        .find([';', ':'])
        .ok_or(ItipError::Invalid("a line has no value"))?;
    let name = line[..end].trim().to_ascii_uppercase();
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(bad);
    }
    let mut params = Vec::new();
    let bytes = line.as_bytes();
    let mut i = end;
    while bytes[i] == b';' {
        i += 1;
        let eq = line[i..]
            .find('=')
            .ok_or(ItipError::Invalid("a parameter has no value"))?
            + i;
        let pname = line[i..eq].trim().to_ascii_uppercase();
        i = eq + 1;
        let mut values = Vec::new();
        loop {
            if i < bytes.len() && bytes[i] == b'"' {
                let close = line[i + 1..]
                    .find('"')
                    .ok_or(ItipError::Invalid("a quoted parameter does not end"))?
                    + i
                    + 1;
                values.push(line[i + 1..close].to_owned());
                i = close + 1;
            } else {
                let stop = line[i..]
                    .find([',', ';', ':'])
                    .map(|p| p + i)
                    .ok_or(ItipError::Invalid("a parameter does not end"))?;
                values.push(line[i..stop].to_owned());
                i = stop;
            }
            if i >= bytes.len() {
                return Err(ItipError::Invalid("a line has no value"));
            }
            if bytes[i] == b',' {
                i += 1;
                continue;
            }
            break;
        }
        params.push(Param {
            name: pname,
            values: values.iter().map(|v| without_controls(v, false)).collect(),
        });
        if i >= bytes.len() {
            return Err(ItipError::Invalid("a line has no value"));
        }
    }
    if bytes[i] != b':' {
        return Err(bad);
    }
    Ok(Property {
        name,
        params,
        value: without_controls(&line[i + 1..], true),
    })
}

/// Control characters are not part of a value (RFC 5545 `VALUE-CHAR`, `SAFE-CHAR`): they are
/// dropped when reading, so what is read is what [`write`] writes back. Values keep tabs.
fn without_controls(text: &str, keep_tab: bool) -> String {
    text.chars()
        .filter(|c| !c.is_control() || (keep_tab && *c == '\t'))
        .collect()
}

pub(crate) fn write(root: &Component) -> Vec<u8> {
    let mut out = Vec::new();
    write_component(root, &mut out);
    out
}

fn write_component(c: &Component, out: &mut Vec<u8>) {
    fold(&format!("BEGIN:{}", c.name), out);
    for p in &c.props {
        let mut line = p.name.clone();
        for param in &p.params {
            line.push(';');
            line.push_str(&param.name);
            line.push('=');
            for (n, v) in param.values.iter().enumerate() {
                if n > 0 {
                    line.push(',');
                }
                let v: String = v.chars().filter(|c| *c != '"' && !c.is_control()).collect();
                if v.contains([':', ';', ',']) {
                    line.push('"');
                    line.push_str(&v);
                    line.push('"');
                } else {
                    line.push_str(&v);
                }
            }
        }
        line.push(':');
        line.push_str(&without_controls(&p.value, true));
        fold(&line, out);
    }
    for child in &c.children {
        write_component(child, out);
    }
    fold(&format!("END:{}", c.name), out);
}

fn fold(line: &str, out: &mut Vec<u8>) {
    let mut width = 0usize;
    let mut limit = 75usize;
    for ch in line.chars() {
        let len = ch.len_utf8();
        if width + len > limit {
            out.extend_from_slice(b"\r\n ");
            width = 0;
            limit = 74;
        }
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        width += len;
    }
    out.extend_from_slice(b"\r\n");
}

/// A TEXT value as written (RFC 5545 section 3.3.11) turned back into text.
pub(crate) fn unescape(value: &str) -> String {
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

/// Text written as a TEXT value.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}
