use data_encoding::BASE64;

const WORD_BYTES: usize = 45;

fn needs_encoding(text: &str) -> bool {
    !text.is_ascii() || text.len() > 70 || text.contains("=?")
}

fn encoded_words(text: &str) -> String {
    let mut words = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + WORD_BYTES).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        words.push(format!(
            "=?utf-8?B?{}?=",
            BASE64.encode(&text.as_bytes()[start..end])
        ));
        start = end;
    }
    words.join("\r\n ")
}

/// Header text (a subject, a display name outside quotes) as it goes into a header: unchanged
/// when it is short plain ASCII, else RFC 2047 encoded words of at most 45 bytes each, folded.
/// Control characters become spaces, so the result never ends a header.
pub fn encode_header_text(text: &str) -> String {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if needs_encoding(&clean) {
        encoded_words(&clean)
    } else {
        clean
    }
}

fn quoted(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    out.push('"');
    for c in name.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(if c.is_control() { ' ' } else { c });
    }
    out.push('"');
    out
}

pub(crate) fn mailbox(name: Option<&str>, address: &str) -> String {
    match name.map(str::trim).filter(|n| !n.is_empty()) {
        None => address.to_owned(),
        Some(n) if needs_encoding(n) => format!("{} <{address}>", encoded_words(n)),
        Some(n) => format!("{} <{address}>", quoted(n)),
    }
}

fn crlf_lines(text: &str) -> Vec<&str> {
    text.split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect()
}

fn qp_line(line: &str, out: &mut String) {
    let bytes = line.as_bytes();
    let mut col = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let last = i + 1 == bytes.len();
        let literal = (b == b' ' || b == b'\t') && !last || (b.is_ascii_graphic() && b != b'=');
        let piece = if literal {
            (b as char).to_string()
        } else {
            format!("={b:02X}")
        };
        if col + piece.len() > 75 {
            out.push_str("=\r\n");
            col = 0;
        }
        out.push_str(&piece);
        col += piece.len();
    }
    out.push_str("\r\n");
}

pub(crate) fn text_part(out: &mut String, text: &str, force_qp: bool) {
    let lines = crlf_lines(text);
    let seven_bit = !force_qp
        && text.is_ascii()
        && !text.contains('\0')
        && lines.iter().all(|l| l.len() <= 76 && !l.contains('\r'));
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    if seven_bit {
        out.push_str("Content-Transfer-Encoding: 7bit\r\n\r\n");
        for l in lines {
            out.push_str(l);
            out.push_str("\r\n");
        }
    } else {
        out.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
        for l in lines {
            qp_line(l, out);
        }
    }
}

const PARAM_SEGMENT: usize = 60;

fn percent_encoded(name: &str) -> Vec<String> {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~') {
                c.to_string()
            } else {
                let mut buf = [0; 4];
                c.encode_utf8(&mut buf)
                    .bytes()
                    .map(|b| format!("%{b:02X}"))
                    .collect()
            }
        })
        .collect()
}

fn rfc2231_param(key: &str, name: &str) -> String {
    let pieces = percent_encoded(name);
    let whole: String = pieces.concat();
    if whole.len() <= PARAM_SEGMENT {
        return format!("{key}*=utf-8''{whole}");
    }
    let mut segments = vec![String::from("utf-8''")];
    for piece in pieces {
        if segments
            .last()
            .is_some_and(|s| s.len() + piece.len() > PARAM_SEGMENT)
        {
            segments.push(String::new());
        }
        if let Some(last) = segments.last_mut() {
            last.push_str(&piece);
        }
    }
    segments
        .iter()
        .enumerate()
        .map(|(i, seg)| format!("{key}*{i}*={seg}"))
        .collect::<Vec<_>>()
        .join(";\r\n ")
}

/// The media type for a file name's extension; `application/octet-stream` for anything not in
/// the table.
pub fn media_type(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "ics" => "text/calendar",
        "vcf" => "text/vcard",
        "json" => "application/json",
        "zip" => "application/zip",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        _ => "application/octet-stream",
    }
}

pub(crate) fn attachment_part(out: &mut String, name: &str, bytes: &[u8]) {
    out.push_str(&format!(
        "Content-Type: {};\r\n {}\r\n",
        media_type(name),
        rfc2231_param("name", name)
    ));
    out.push_str(&format!(
        "Content-Disposition: attachment;\r\n {}\r\n",
        rfc2231_param("filename", name)
    ));
    out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    let b64 = BASE64.encode(bytes);
    for chunk in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str("\r\n");
    }
}
