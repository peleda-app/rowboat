use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use skein_core::tls::testing::TestCa;
use skein_core::{BlobHash, CommandBody, Credentials, Flags, ItemRef, MailboxRole, Timestamp};
use skein_mail::testing::{ServerControl, conformance};
use skein_mail::{MailChange, MailError, MailProvider, WriteOutcome};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::*;

#[derive(Clone)]
struct Msg {
    uid: u32,
    flags: Vec<String>,
    labels: Vec<String>,
    modseq: u64,
    msgid: u64,
    raw: Vec<u8>,
    date: Option<String>,
}

struct Folder {
    raw: String,
    path: String,
    attributes: &'static str,
    validity: u32,
    uid_next: u32,
    messages: Vec<Msg>,
}

#[derive(Default)]
struct State {
    folders: Vec<Folder>,
    modseq: u64,
    next_msgid: u64,
    commands: Vec<String>,
    drop_on: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct Caps {
    condstore: bool,
    uidplus: bool,
    moves: bool,
    gmail: bool,
    keywords: bool,
}

const BARE: Caps = Caps {
    condstore: false,
    uidplus: false,
    moves: false,
    gmail: false,
    keywords: false,
};
const FULL: Caps = Caps {
    condstore: true,
    uidplus: true,
    moves: true,
    gmail: false,
    keywords: true,
};
const GMAIL: Caps = Caps {
    condstore: true,
    uidplus: true,
    moves: true,
    gmail: true,
    keywords: true,
};

#[derive(Clone)]
enum Transport {
    Plain,
    Tls(TlsAcceptor),
    Starttls(TlsAcceptor),
}

#[derive(Clone)]
struct Fake {
    state: Arc<Mutex<State>>,
    caps: Caps,
    port: u16,
    roots: Option<skein_core::TlsRoots>,
    security: Security,
}

impl Fake {
    async fn start(caps: Caps) -> Self {
        Self::start_with(caps, Transport::Plain, None).await
    }

    async fn start_with(caps: Caps, transport: Transport, ca: Option<&TestCa>) -> Self {
        let folder = |raw: &str, path: &str, attributes, validity| Folder {
            raw: raw.into(),
            path: path.into(),
            attributes,
            validity,
            uid_next: 1,
            messages: Vec::new(),
        };
        let folders = if caps.gmail {
            vec![
                folder("INBOX", "INBOX", "\\HasNoChildren", 1),
                folder("[Gmail]", "[Gmail]", "\\HasChildren \\Noselect", 2),
                folder("[Gmail]/All Mail", "[Gmail]/All Mail", "\\All", 3),
                folder("[Gmail]/Trash", "[Gmail]/Trash", "\\Trash", 4),
                folder("[Gmail]/Spam", "[Gmail]/Spam", "\\Junk", 5),
                folder(
                    "Projects/&BBIEMAQ2BD0EPgQ1-",
                    "Projects/Важное",
                    "\\HasNoChildren",
                    6,
                ),
            ]
        } else {
            vec![
                folder("INBOX", "INBOX", "\\HasChildren", 1),
                folder(
                    "INBOX.Archive",
                    "INBOX/Archive",
                    "\\HasNoChildren \\Archive",
                    2,
                ),
                folder(
                    "INBOX.&BB4EQgQ,BEAEMAQyBDsENQQ9BD0ESwQ1-",
                    "INBOX/Отправленные",
                    "\\HasNoChildren \\Sent",
                    3,
                ),
                folder("Shared", "Shared", "\\Noselect \\HasChildren", 4),
                folder("Junk", "Junk", "\\HasNoChildren", 5),
                folder("Bin", "Bin", "\\HasNoChildren \\Trash", 6),
            ]
        };
        let state = Arc::new(Mutex::new(State {
            folders,
            modseq: 10,
            next_msgid: 1_800_000_000_000_000_000,
            ..State::default()
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = state.clone();
        let security = match transport {
            Transport::Plain => Security::Plain,
            Transport::Tls(_) => Security::Tls,
            Transport::Starttls(_) => Security::Starttls,
        };
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let state = shared.clone();
                let transport = transport.clone();
                tokio::spawn(async move {
                    match transport {
                        Transport::Plain => session(socket, state, caps, true).await,
                        Transport::Tls(acceptor) => {
                            if let Ok(tls) = acceptor.accept(socket).await {
                                session(tls, state, caps, true).await;
                            }
                        }
                        Transport::Starttls(acceptor) => {
                            if let Some(socket) = starttls(socket).await
                                && let Ok(tls) = acceptor.accept(socket).await
                            {
                                session(tls, state, caps, false).await;
                            }
                        }
                    }
                });
            }
        });
        Self {
            state,
            caps,
            port,
            roots: ca.map(TestCa::roots),
            security,
        }
    }

    fn settings(&self) -> ImapSettings {
        let host = if self.security == Security::Plain {
            "127.0.0.1"
        } else {
            "localhost"
        };
        let mut settings = ImapSettings::new(host, "ada@example.com");
        settings.port = Some(self.port);
        settings.security = self.security;
        if let Some(roots) = &self.roots {
            settings.roots = roots.clone();
        }
        settings
    }

    fn provider_with(&self, credentials: Credentials) -> ImapProvider {
        ImapProvider::new(self.settings(), credentials)
            .unwrap()
            .with_timeout(Duration::from_secs(5))
    }

    fn provider(&self) -> ImapProvider {
        self.provider_with(Credentials::Password {
            secret: "secret".into(),
        })
    }

    fn commands(&self) -> Vec<String> {
        self.state.lock().unwrap().commands.clone()
    }

    fn with_folder<T>(&self, path: &str, f: impl FnOnce(&mut Folder, u64) -> T) -> T {
        let mut state = self.state.lock().unwrap();
        state.modseq += 1;
        let modseq = state.modseq;
        let folder = state.folders.iter_mut().find(|f| f.path == path).unwrap();
        f(folder, modseq)
    }

    fn set_labels(&self, path: &str, uid: u32, labels: &[&str]) {
        self.with_folder(path, |folder, modseq| {
            let m = folder.messages.iter_mut().find(|m| m.uid == uid).unwrap();
            m.labels = labels.iter().map(|l| (*l).to_owned()).collect();
            m.modseq = modseq;
        });
    }

    fn messages(&self, path: &str) -> Vec<Msg> {
        let state = self.state.lock().unwrap();
        state
            .folders
            .iter()
            .find(|f| f.path == path)
            .unwrap()
            .messages
            .clone()
    }
}

#[async_trait]
impl ServerControl for Fake {
    async fn create_mailbox(&self, mailbox: &str) {
        let mut state = self.state.lock().unwrap();
        if state.folders.iter().any(|f| f.path == mailbox) {
            return;
        }
        let delimiter = if self.caps.gmail { "/" } else { "." };
        let validity = state.folders.len() as u32 + 100;
        state.folders.push(Folder {
            raw: utf7::encode(mailbox).replace('/', delimiter),
            path: mailbox.into(),
            attributes: "\\HasNoChildren",
            validity,
            uid_next: 1,
            messages: Vec::new(),
        });
    }

    async fn add(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        let msgid = {
            let mut state = self.state.lock().unwrap();
            state.next_msgid += 7;
            state.next_msgid
        };
        self.with_folder(mailbox, |folder, modseq| {
            let uid = folder.uid_next;
            folder.uid_next += 1;
            folder.messages.push(Msg {
                uid,
                flags: flags.iter().map(str::to_owned).collect(),
                labels: Vec::new(),
                modseq,
                msgid,
                raw: bytes.to_vec(),
                date: None,
            });
        });
    }

    async fn remove(&self, mailbox: &str, bytes: &[u8]) {
        self.with_folder(mailbox, |folder, _| {
            folder.messages.retain(|m| m.raw != bytes);
        });
    }

    async fn set_flags(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        self.with_folder(mailbox, |folder, modseq| {
            if let Some(m) = folder.messages.iter_mut().find(|m| m.raw == bytes) {
                m.flags = flags.iter().map(str::to_owned).collect();
                m.modseq = modseq;
            }
        });
    }

    async fn invalidate(&self, mailbox: &str) {
        self.with_folder(mailbox, |folder, _| {
            folder.validity += 1000;
            folder.uid_next = 1;
            for m in &mut folder.messages {
                m.uid = folder.uid_next;
                folder.uid_next += 1;
            }
        });
    }

    async fn flags_of(&self, mailbox: &str, bytes: &[u8]) -> Option<Flags> {
        self.messages(mailbox)
            .into_iter()
            .find(|m| m.raw == bytes)
            .map(|m| Flags::new(m.flags))
    }
}

/// Answers the plain greeting and one `STARTTLS`, returning the socket ready for the handshake.
async fn starttls(mut socket: TcpStream) -> Option<TcpStream> {
    socket
        .write_all(b"* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
        .await
        .ok()?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\n") {
        socket.read_exact(&mut byte).await.ok()?;
        line.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&line);
    let (tag, rest) = line.trim_end().split_once(' ')?;
    if !rest.eq_ignore_ascii_case("STARTTLS") {
        return None;
    }
    socket
        .write_all(format!("{tag} OK begin TLS\r\n").as_bytes())
        .await
        .ok()?;
    Some(socket)
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Atom(String),
    Str(String),
    List(Vec<Tok>),
}

impl Tok {
    fn text(&self) -> String {
        match self {
            Tok::Atom(s) | Tok::Str(s) => s.clone(),
            Tok::List(_) => panic!("a list where text was expected: {self:?}"),
        }
    }

    fn list(&self) -> Vec<Tok> {
        match self {
            Tok::List(items) => items.clone(),
            other => panic!("not a list: {other:?}"),
        }
    }
}

fn tokens(line: &str) -> Vec<Tok> {
    fn parse(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Vec<Tok> {
        let mut out = Vec::new();
        while let Some(&c) = chars.peek() {
            match c {
                ' ' => {
                    chars.next();
                }
                '(' => {
                    chars.next();
                    out.push(Tok::List(parse(chars)));
                }
                ')' => {
                    chars.next();
                    return out;
                }
                '"' => {
                    chars.next();
                    let mut s = String::new();
                    while let Some(c) = chars.next() {
                        match c {
                            '\\' => s.extend(chars.next()),
                            '"' => break,
                            c => s.push(c),
                        }
                    }
                    out.push(Tok::Str(s));
                }
                _ => {
                    let mut s = String::new();
                    while let Some(&c) = chars.peek() {
                        if c == ' ' || c == '(' || c == ')' {
                            break;
                        }
                        s.push(c);
                        chars.next();
                    }
                    out.push(Tok::Atom(s));
                }
            }
        }
        out
    }
    parse(&mut line.chars().peekable())
}

/// A sequence set where `*` is the largest UID in the folder, as RFC 3501 says.
fn in_set(set: &str, uid: u32, max: u32) -> bool {
    let num = |s: &str| if s == "*" { max } else { s.parse().unwrap() };
    set.split(',').any(|part| match part.split_once(':') {
        Some((a, b)) => {
            let (a, b) = (num(a), num(b));
            (a.min(b)..=a.max(b)).contains(&uid)
        }
        None => num(part) == uid,
    })
}

fn has(flags: &[String], flag: &str) -> bool {
    flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
}

async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    state: Arc<Mutex<State>>,
    caps: Caps,
    greet: bool,
) {
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    if greet {
        write
            .write_all(b"* OK [CAPABILITY IMAP4rev1] fake server ready\r\n")
            .await
            .unwrap();
    }
    let mut selected: Option<(usize, bool)> = None;
    let mut enabled = false;
    loop {
        let mut bytes = Vec::new();
        if !matches!(reader.read_until(b'\n', &mut bytes).await, Ok(n) if n > 0) {
            return;
        }
        let line = String::from_utf8_lossy(&bytes).trim_end().to_owned();
        let (tag, rest) = line.split_once(' ').unwrap_or((&line, ""));
        let tag = tag.to_owned();
        let upper = rest.to_ascii_uppercase();
        let args = tokens(rest);
        let command = args
            .first()
            .map(Tok::text)
            .unwrap_or_default()
            .to_ascii_uppercase();
        let verb = if command == "UID" {
            format!("UID {}", args[1].text().to_ascii_uppercase())
        } else {
            command.clone()
        };
        let drop_now = {
            let mut st = state.lock().unwrap();
            st.commands.push(rest.to_owned());
            st.drop_on == Some(verb.as_str())
        };
        if drop_now {
            return;
        }
        let mut out = String::new();
        match verb.as_str() {
            "CAPABILITY" => {
                let mut extra = String::from(" ENABLE");
                for (on, name) in [
                    (caps.condstore, " CONDSTORE"),
                    (caps.uidplus, " UIDPLUS"),
                    (caps.moves, " MOVE"),
                    (caps.gmail, " X-GM-EXT-1"),
                ] {
                    if on {
                        extra.push_str(name);
                    }
                }
                out = format!("* CAPABILITY IMAP4rev1{extra}\r\n{tag} OK done\r\n");
            }
            "LOGIN" => {
                out = match args[2].text().as_str() {
                    "secret" if args[1].text() == "ada@example.com" => {
                        format!("{tag} OK LOGIN completed\r\n")
                    }
                    "busy" => {
                        format!("{tag} NO [UNAVAILABLE] Too many simultaneous connections\r\n")
                    }
                    _ => format!("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n"),
                }
            }
            "AUTHENTICATE" => {
                let _ = write.write_all(b"+ \r\n").await;
                let mut answer = String::new();
                if reader.read_line(&mut answer).await.unwrap_or(0) == 0 {
                    return;
                }
                let decoded = STANDARD.decode(answer.trim()).unwrap_or_default();
                if decoded == b"user=ada@example.com\x01auth=Bearer good-token\x01\x01" {
                    out = format!("{tag} OK AUTHENTICATE completed\r\n");
                } else {
                    let error = STANDARD.encode(r#"{"status":"400","schemes":"Bearer"}"#);
                    let _ = write.write_all(format!("+ {error}\r\n").as_bytes()).await;
                    let mut empty = String::new();
                    if reader.read_line(&mut empty).await.unwrap_or(0) == 0 {
                        return;
                    }
                    assert!(
                        empty.trim().is_empty(),
                        "the error challenge was not answered empty"
                    );
                    out = format!("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n");
                }
            }
            "ENABLE" => {
                assert!(caps.condstore, "ENABLE CONDSTORE without CONDSTORE");
                enabled = true;
                out = format!("* ENABLED CONDSTORE\r\n{tag} OK done\r\n");
            }
            "NOOP" => out = format!("{tag} OK done\r\n"),
            "LIST" if args[2].text().is_empty() => {
                let delimiter = if caps.gmail { "/" } else { "." };
                out = format!(
                    "* LIST (\\Noselect) \"{delimiter}\" \"\"\r\n{tag} OK LIST completed\r\n"
                );
            }
            "CREATE" | "RENAME" | "DELETE" => {
                let delimiter = if caps.gmail { "/" } else { "." };
                let name = args[1].text();
                let mut state = state.lock().unwrap();
                let index = state.folders.iter().position(|f| f.raw == name);
                let target = args.get(2).map(Tok::text);
                let taken = |raw: &str| state.folders.iter().any(|f| f.raw == raw);
                out = match (verb.as_str(), index) {
                    (_, _) if name.eq_ignore_ascii_case("INBOX") && verb != "CREATE" => {
                        format!("{tag} NO cannot change INBOX\r\n")
                    }
                    ("CREATE", _) if taken(&name) || name.eq_ignore_ascii_case("INBOX") => {
                        format!("{tag} NO [ALREADYEXISTS] mailbox exists\r\n")
                    }
                    ("CREATE", _) => {
                        let validity = state.folders.len() as u32 + 200;
                        state.folders.push(Folder {
                            path: utf7::decode(&name).replace(delimiter, "/"),
                            raw: name,
                            attributes: "\\HasNoChildren",
                            validity,
                            uid_next: 1,
                            messages: Vec::new(),
                        });
                        format!("{tag} OK CREATE completed\r\n")
                    }
                    (_, None) => format!("{tag} NO [NONEXISTENT] no such mailbox\r\n"),
                    ("RENAME", Some(_)) if taken(target.as_deref().unwrap()) => {
                        format!("{tag} NO [ALREADYEXISTS] mailbox exists\r\n")
                    }
                    ("RENAME", Some(index)) => {
                        let new = target.unwrap();
                        let folder = &mut state.folders[index];
                        folder.path = utf7::decode(&new).replace(delimiter, "/");
                        folder.raw = new;
                        folder.validity += 1000;
                        format!("{tag} OK RENAME completed\r\n")
                    }
                    (_, Some(index)) => {
                        state.folders.remove(index);
                        format!("{tag} OK DELETE completed\r\n")
                    }
                };
            }
            "LIST" => {
                let delimiter = if caps.gmail { "/" } else { "." };
                for folder in &state.lock().unwrap().folders {
                    out.push_str(&format!(
                        "* LIST ({}) \"{delimiter}\" \"{}\"\r\n",
                        folder.attributes, folder.raw
                    ));
                }
                out.push_str(&format!("{tag} OK LIST completed\r\n"));
            }
            "EXAMINE" | "SELECT" => {
                let name = args[1].text();
                let state = state.lock().unwrap();
                match state
                    .folders
                    .iter()
                    .position(|f| f.raw == name && !f.attributes.contains("Noselect"))
                {
                    Some(index) => {
                        let read_only = command == "EXAMINE";
                        selected = Some((index, read_only));
                        let folder = &state.folders[index];
                        out.push_str(&format!(
                            "* {} EXISTS\r\n* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n\
                             * OK [UIDVALIDITY {}] ok\r\n* OK [UIDNEXT {}] ok\r\n",
                            folder.messages.len(),
                            folder.validity,
                            folder.uid_next
                        ));
                        if enabled {
                            out.push_str(&format!("* OK [HIGHESTMODSEQ {}] ok\r\n", state.modseq));
                        }
                        let permanent = match (read_only, caps.keywords) {
                            (true, _) => "",
                            (false, false) => "\\Seen \\Answered \\Flagged \\Deleted \\Draft",
                            (false, true) => "\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*",
                        };
                        out.push_str(&format!("* OK [PERMANENTFLAGS ({permanent})] ok\r\n"));
                        let mode = if read_only { "READ-ONLY" } else { "READ-WRITE" };
                        out.push_str(&format!("{tag} OK [{mode}] done\r\n"));
                    }
                    None => {
                        selected = None;
                        out = format!("{tag} NO [NONEXISTENT] no such mailbox\r\n");
                    }
                }
            }
            "UID SEARCH" => {
                let state = state.lock().unwrap();
                let folder = &state.folders[selected.unwrap().0];
                let max = folder.messages.iter().map(|m| m.uid).max().unwrap_or(0);
                let mut found: Vec<u32> = folder.messages.iter().map(|m| m.uid).collect();
                let mut keys = args[2..].iter();
                while let Some(key) = keys.next() {
                    match key.text().to_ascii_uppercase().as_str() {
                        "ALL" => {}
                        "UID" => {
                            let set = keys.next().unwrap().text();
                            found.retain(|uid| in_set(&set, *uid, max));
                        }
                        "DELETED" => found.retain(|uid| {
                            let m = folder.messages.iter().find(|m| m.uid == *uid).unwrap();
                            has(&m.flags, "\\Deleted")
                        }),
                        other => panic!("search key {other}"),
                    }
                }
                let list: Vec<String> = found.iter().map(u32::to_string).collect();
                out = format!("* SEARCH {}\r\n{tag} OK done\r\n", list.join(" "))
                    .replace("SEARCH \r\n", "SEARCH\r\n");
            }
            "UID FETCH" => {
                let items = upper.split_once(' ').unwrap().1.split_once(' ').unwrap().1;
                let items = items.split_once(' ').map_or("", |(_, i)| i);
                assert!(
                    !items.replace("BODY.PEEK[]", "").contains("BODY[")
                        && !items.replace("RFC822.SIZE", "").contains("RFC822"),
                    "fetch must not mark mail as read: {line}"
                );
                assert!(
                    caps.gmail || !items.contains("X-GM-"),
                    "Gmail items asked of another server"
                );
                let set = args[2].text();
                let since: Option<u64> = args.get(4).map(|t| {
                    let condition = t.list();
                    assert_eq!(condition[0].text().to_ascii_uppercase(), "CHANGEDSINCE");
                    condition[1].text().parse().unwrap()
                });
                assert!(
                    since.is_none() || enabled,
                    "CHANGEDSINCE before CONDSTORE was enabled"
                );
                let state = state.lock().unwrap();
                let folder = &state.folders[selected.unwrap().0];
                let max = folder.messages.iter().map(|m| m.uid).max().unwrap_or(0);
                for (seq, m) in folder.messages.iter().enumerate() {
                    if !in_set(&set, m.uid, max) || since.is_some_and(|s| m.modseq <= s) {
                        continue;
                    }
                    let mut parts = format!("UID {}", m.uid);
                    if items.contains("FLAGS") {
                        parts.push_str(&format!(" FLAGS ({})", m.flags.join(" ")));
                    }
                    if items.contains("INTERNALDATE") {
                        let date = m.date.as_deref().unwrap_or("14-Mar-2025 09:30:00 +0100");
                        parts.push_str(&format!(" INTERNALDATE \"{date}\""));
                    }
                    if items.contains("RFC822.SIZE") {
                        parts.push_str(&format!(" RFC822.SIZE {}", m.raw.len()));
                    }
                    if items.contains("X-GM-MSGID") {
                        parts.push_str(&format!(" X-GM-MSGID {}", m.msgid));
                    }
                    if items.contains("X-GM-LABELS") {
                        parts.push_str(&format!(" X-GM-LABELS ({})", m.labels.join(" ")));
                    }
                    if since.is_some() {
                        parts.push_str(&format!(" MODSEQ ({})", m.modseq));
                    }
                    if items.contains("BODY.PEEK[]") {
                        out.push_str(&format!(
                            "* {} FETCH ({parts} BODY[] {{{}}}\r\n",
                            seq + 1,
                            m.raw.len()
                        ));
                        out.push_str(std::str::from_utf8(&m.raw).unwrap());
                        out.push_str(")\r\n");
                    } else {
                        out.push_str(&format!("* {} FETCH ({parts})\r\n", seq + 1));
                    }
                }
                out.push_str(&format!("{tag} OK FETCH completed\r\n"));
            }
            "UID STORE" => {
                let (index, read_only) = selected.unwrap();
                if read_only {
                    out = format!("{tag} NO mailbox is read-only\r\n");
                } else {
                    let set = args[2].text();
                    let item = args[3].text().to_ascii_uppercase();
                    let values = args[4].list();
                    let adding = item.starts_with('+');
                    let labels = item.contains("X-GM-LABELS");
                    assert!(!labels || caps.gmail, "X-GM-LABELS asked of another server");
                    let mut state = state.lock().unwrap();
                    state.modseq += 1;
                    let modseq = state.modseq;
                    let folder = &mut state.folders[index];
                    let max = folder.messages.iter().map(|m| m.uid).max().unwrap_or(0);
                    for m in &mut folder.messages {
                        if !in_set(&set, m.uid, max) {
                            continue;
                        }
                        for value in &values {
                            let text = value.text();
                            if labels {
                                m.labels.retain(|l| tokens(l)[0].text() != text);
                                if adding {
                                    m.labels.push(quote(&text));
                                }
                                continue;
                            }
                            m.flags.retain(|f| !f.eq_ignore_ascii_case(&text));
                            if adding {
                                m.flags.push(text);
                            }
                        }
                        m.modseq = modseq;
                    }
                    out = format!("{tag} OK STORE completed\r\n");
                }
            }
            "UID COPY" | "UID MOVE" => {
                assert!(verb == "UID COPY" || caps.moves, "MOVE without MOVE");
                let (source, _) = selected.unwrap();
                let set = args[2].text();
                let name = args[3].text();
                let mut state = state.lock().unwrap();
                match state.folders.iter().position(|f| f.raw == name) {
                    None => out = format!("{tag} NO [TRYCREATE] no such mailbox\r\n"),
                    Some(target) => {
                        let max = state.folders[source]
                            .messages
                            .iter()
                            .map(|m| m.uid)
                            .max()
                            .unwrap_or(0);
                        let picked: Vec<Msg> = state.folders[source]
                            .messages
                            .iter()
                            .filter(|m| in_set(&set, m.uid, max))
                            .cloned()
                            .collect();
                        state.modseq += 1;
                        let modseq = state.modseq;
                        for mut m in picked.clone() {
                            let folder = &mut state.folders[target];
                            m.uid = folder.uid_next;
                            folder.uid_next += 1;
                            m.modseq = modseq;
                            m.flags.retain(|f| !f.eq_ignore_ascii_case("\\Deleted"));
                            folder.messages.push(m);
                        }
                        if verb == "UID MOVE" {
                            let folder = &mut state.folders[source];
                            while let Some(seq) = folder
                                .messages
                                .iter()
                                .rposition(|m| picked.iter().any(|p| p.uid == m.uid))
                            {
                                folder.messages.remove(seq);
                                out.push_str(&format!("* {} EXPUNGE\r\n", seq + 1));
                            }
                        }
                        out.push_str(&format!("{tag} OK done\r\n"));
                    }
                }
            }
            "UID EXPUNGE" | "EXPUNGE" => {
                assert!(
                    verb == "EXPUNGE" || caps.uidplus,
                    "UID EXPUNGE without UIDPLUS"
                );
                let set = (verb == "UID EXPUNGE").then(|| args[2].text());
                let mut state = state.lock().unwrap();
                let folder = &mut state.folders[selected.unwrap().0];
                let max = folder.messages.iter().map(|m| m.uid).max().unwrap_or(0);
                while let Some(seq) = folder.messages.iter().rposition(|m| {
                    has(&m.flags, "\\Deleted") && set.as_ref().is_none_or(|s| in_set(s, m.uid, max))
                }) {
                    folder.messages.remove(seq);
                    out.push_str(&format!("* {} EXPUNGE\r\n", seq + 1));
                }
                out.push_str(&format!("{tag} OK done\r\n"));
            }
            "APPEND" => {
                let name = args[1].text();
                let flags = args[2].list().iter().map(Tok::text).collect::<Vec<_>>();
                let date = match args.get(3) {
                    Some(Tok::Str(date)) => Some(date.clone()),
                    _ => None,
                };
                let size: usize = upper
                    .rsplit_once('{')
                    .and_then(|(_, n)| n.trim_end_matches('}').parse().ok())
                    .unwrap();
                let target = state
                    .lock()
                    .unwrap()
                    .folders
                    .iter()
                    .position(|f| f.raw == name && !f.attributes.contains("Noselect"));
                match target {
                    None => out = format!("{tag} NO [TRYCREATE] no such mailbox\r\n"),
                    Some(target) => {
                        write
                            .write_all(b"+ Ready for literal data\r\n")
                            .await
                            .unwrap();
                        let mut raw = vec![0; size];
                        reader.read_exact(&mut raw).await.unwrap();
                        let mut end = Vec::new();
                        reader.read_until(b'\n', &mut end).await.unwrap();
                        let mut state = state.lock().unwrap();
                        state.modseq += 1;
                        state.next_msgid += 7;
                        let (modseq, msgid) = (state.modseq, state.next_msgid);
                        let folder = &mut state.folders[target];
                        let uid = folder.uid_next;
                        folder.uid_next += 1;
                        folder.messages.push(Msg {
                            uid,
                            flags,
                            labels: Vec::new(),
                            modseq,
                            msgid,
                            raw,
                            date,
                        });
                        out = format!("{tag} OK APPEND completed\r\n");
                    }
                }
            }
            "LOGOUT" => {
                let _ = write
                    .write_all(format!("* BYE\r\n{tag} OK done\r\n").as_bytes())
                    .await;
                return;
            }
            _ => out = format!("{tag} BAD unknown command\r\n"),
        }
        if write.write_all(out.as_bytes()).await.is_err() {
            return;
        }
    }
}

fn verbs(fake: &Fake) -> Vec<String> {
    fake.commands()
        .iter()
        .map(|c| {
            let mut words = c.split_whitespace();
            let first = words.next().unwrap_or_default().to_ascii_uppercase();
            if first == "UID" {
                format!(
                    "UID {}",
                    words.next().unwrap_or_default().to_ascii_uppercase()
                )
            } else {
                first
            }
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_contract_without_condstore() {
    let fake = Fake::start(BARE).await;
    conformance(Arc::new(fake.provider()), Arc::new(fake.clone()), "INBOX").await;
    let verbs = verbs(&fake);
    assert!(
        !verbs.iter().any(|v| v == "SELECT"),
        "reading only examines"
    );
    assert!(!fake.commands().iter().any(|c| c.contains("CHANGEDSINCE")));
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_contract_with_condstore() {
    let fake = Fake::start(FULL).await;
    conformance(Arc::new(fake.provider()), Arc::new(fake.clone()), "INBOX").await;
    assert!(fake.commands().iter().any(|c| c.contains("CHANGEDSINCE")));
    assert!(!verbs(&fake).iter().any(|v| v == "SELECT"));
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_contract_on_gmail() {
    let fake = Fake::start(GMAIL).await;
    conformance(Arc::new(fake.provider()), Arc::new(fake.clone()), "INBOX").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_contract_over_tls() {
    let ca = TestCa::new(&["localhost"]);
    let fake = Fake::start_with(FULL, Transport::Tls(ca.acceptor()), Some(&ca)).await;
    conformance(Arc::new(fake.provider()), Arc::new(fake.clone()), "INBOX").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_contract_over_starttls() {
    let ca = TestCa::new(&["localhost"]);
    let fake = Fake::start_with(BARE, Transport::Starttls(ca.acceptor()), Some(&ca)).await;
    conformance(Arc::new(fake.provider()), Arc::new(fake.clone()), "INBOX").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unchanged_mailbox_with_condstore_costs_one_examine() {
    let fake = Fake::start(FULL).await;
    for n in 0..5 {
        fake.add(
            "INBOX",
            format!("Subject: {n}\r\n\r\n{n}\r\n").as_bytes(),
            Flags::default(),
        )
        .await;
    }
    let mut session = fake.provider().connect().await.unwrap();
    let first = session.changes("INBOX", None, 100).await.unwrap();
    let before = fake.commands().len();
    let again = session
        .changes("INBOX", Some(&first.cursor), 100)
        .await
        .unwrap();
    assert!(again.changes.is_empty());
    assert_eq!(&fake.commands()[before..], ["EXAMINE \"INBOX\""]);

    fake.add("INBOX", b"Subject: new\r\n\r\nnew\r\n", Flags::default())
        .await;
    let before = fake.commands().len();
    let third = session
        .changes("INBOX", Some(&again.cursor), 100)
        .await
        .unwrap();
    assert_eq!(third.changes.len(), 1);
    let sent = &fake.commands()[before..];
    assert!(
        !sent.iter().any(|c| c.contains("SEARCH ALL")),
        "a new message alone needs no full search: {sent:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_cursor_resets() {
    let fake = Fake::start(BARE).await;
    fake.add("INBOX", b"Subject: a\r\n\r\na\r\n", Flags::default())
        .await;
    let mut session = fake.provider().connect().await.unwrap();
    let batch = session
        .changes(
            "INBOX",
            Some(&skein_mail::Cursor(Bytes::from_static(b"junk"))),
            10,
        )
        .await
        .unwrap();
    assert!(
        matches!(&batch.changes[0], MailChange::Reset { reason } if reason == "unreadable_cursor")
    );
    assert_eq!(batch.changes.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn lists_mailboxes_with_roles_and_utf7_names() {
    let fake = Fake::start(BARE).await;
    let mut session = fake.provider().connect().await.unwrap();
    let boxes = session.mailboxes().await.unwrap();
    let find = |id: &str| boxes.iter().find(|b| b.id == id).unwrap().clone();
    assert_eq!(find("INBOX").role, Some(MailboxRole::Inbox));
    assert_eq!(find("INBOX/Отправленные").role, Some(MailboxRole::Sent));
    assert_eq!(find("INBOX/Archive").role, Some(MailboxRole::Archive));
    assert_eq!(
        find("Junk").role,
        Some(MailboxRole::Junk),
        "guessed from the name"
    );
    assert!(!find("Shared").selectable);
    assert!(boxes.iter().all(|b| !b.label));
    assert!(matches!(
        session.changes("Shared", None, 10).await,
        Err(MailError::MailboxNotFound)
    ));
    assert!(matches!(
        session.changes("Nowhere", None, 10).await,
        Err(MailError::MailboxNotFound)
    ));
    fake.add(
        "INBOX/Отправленные",
        b"Subject: s\r\n\r\ns\r\n",
        Flags::default(),
    )
    .await;
    let sent = session
        .changes("INBOX/Отправленные", None, 10)
        .await
        .unwrap();
    assert_eq!(sent.changes.len(), 1);
    assert!(
        fake.commands()
            .iter()
            .any(|c| c == "EXAMINE \"INBOX.&BB4EQgQ,BEAEMAQyBDsENQQ9BD0ESwQ1-\"")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn uses_gmail_message_ids_and_labels() {
    let fake = Fake::start(GMAIL).await;
    let mut session = fake.provider().connect().await.unwrap();
    let boxes = session.mailboxes().await.unwrap();
    let find = |id: &str| boxes.iter().find(|b| b.id == id).unwrap().clone();
    assert!(find("INBOX").label);
    assert!(find("Projects/Важное").label);
    let all = find("[Gmail]/All Mail");
    assert_eq!(all.role, Some(MailboxRole::All));
    assert!(!all.label);
    assert!(!find("[Gmail]/Spam").label);
    assert!(!find("[Gmail]/Trash").label);
    assert!(!find("[Gmail]").label && !find("[Gmail]").selectable);

    let raw = b"From: ada@example.com\r\nSubject: One\r\n\r\nFirst\r\n";
    fake.add("[Gmail]/All Mail", raw, Flags::new(["\\Seen"]))
        .await;
    fake.set_labels(
        "[Gmail]/All Mail",
        1,
        &["\"\\\\Inbox\"", "Projects/&BBIEMAQ2BD0EPgQ1-"],
    );
    let msgid = fake.messages("[Gmail]/All Mail")[0].msgid;
    let first = session.changes("[Gmail]/All Mail", None, 10).await.unwrap();
    let MailChange::Added {
        item,
        labels,
        received_at,
        ..
    } = &first.changes[0]
    else {
        panic!("{:?}", first.changes);
    };
    assert_eq!(item.id, msgid.to_string());
    assert_eq!(item.uid, Some(1));
    assert_eq!(
        labels.as_deref(),
        Some(&["Inbox".to_owned(), "Projects/Важное".into()][..])
    );
    assert_eq!(*received_at, Some(Timestamp(1_741_941_000_000)));

    fake.set_labels("[Gmail]/All Mail", 1, &["Work"]);
    let second = session
        .changes("[Gmail]/All Mail", Some(&first.cursor), 10)
        .await
        .unwrap();
    assert_eq!(
        second.changes,
        [MailChange::Labels {
            item: item.clone(),
            labels: vec!["Work".into()],
        }],
        "a label change alone is not a flag change"
    );

    let got = session
        .fetch("[Gmail]/All Mail", std::slice::from_ref(item))
        .await
        .unwrap();
    assert_eq!(&got[0].bytes[..], raw);
    let wrong = ItemRef {
        id: (msgid + 1).to_string(),
        uid: Some(1),
    };
    assert!(
        session
            .fetch("[Gmail]/All Mail", std::slice::from_ref(&wrong))
            .await
            .unwrap()
            .is_empty(),
        "a UID that now holds another message is left out"
    );
    let outcome = session
        .apply(
            &CommandBody::SetFlags {
                mailbox: "[Gmail]/All Mail".into(),
                items: vec![wrong],
                add: Flags::new(["\\Flagged"]),
                remove: Flags::default(),
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Applied);
    assert!(!fake.commands().iter().any(|c| c.starts_with("UID STORE")));
}

fn delete(mailbox: &str, items: Vec<ItemRef>) -> CommandBody {
    CommandBody::Delete {
        mailbox: mailbox.into(),
        items,
        to_trash: false,
    }
}

async fn listed(fake: &Fake, mailbox: &str) -> Vec<ItemRef> {
    let mut session = fake.provider().connect().await.unwrap();
    let batch = session.changes(mailbox, None, 100).await.unwrap();
    batch
        .changes
        .into_iter()
        .filter_map(|c| match c {
            MailChange::Added { item, .. } => Some(item),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn applies_flags_moves_deletes_and_appends() {
    let fake = Fake::start(FULL).await;
    for n in 1..=3 {
        fake.add(
            "INBOX",
            format!("Subject: {n}\r\n\r\n{n}\r\n").as_bytes(),
            Flags::new(["\\Seen"]),
        )
        .await;
    }
    let items = listed(&fake, "INBOX").await;
    let mut session = fake.provider().connect().await.unwrap();

    let outcome = session
        .apply(
            &CommandBody::SetFlags {
                mailbox: "INBOX".into(),
                items: vec![items[0].clone()],
                add: Flags::new(["\\Flagged", "$Work"]),
                remove: Flags::new(["\\Seen"]),
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Applied);
    let mut flags = fake.messages("INBOX")[0].flags.clone();
    flags.sort();
    assert_eq!(flags, ["$Work", "\\Flagged"]);
    let commands = fake.commands();
    assert!(
        commands
            .iter()
            .any(|c| c == "UID STORE 1 -FLAGS.SILENT (\\Seen)")
    );
    assert!(
        commands
            .iter()
            .any(|c| c == "UID STORE 1 +FLAGS.SILENT ($Work \\Flagged)")
    );
    assert!(commands.iter().any(|c| c == "SELECT \"INBOX\""));

    let bad = session
        .apply(
            &CommandBody::SetFlags {
                mailbox: "INBOX".into(),
                items: vec![items[0].clone()],
                add: Flags::new(["\\Recent"]),
                remove: Flags::default(),
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        bad,
        WriteOutcome::Failed {
            reason: "invalid_flag".into()
        }
    );

    let moved = session
        .apply(
            &CommandBody::Move {
                from: "INBOX".into(),
                to: "INBOX/Archive".into(),
                items: vec![items[1].clone()],
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(moved, WriteOutcome::Applied);
    assert!(
        fake.commands()
            .iter()
            .any(|c| c == "UID MOVE 2 \"INBOX.Archive\"")
    );
    assert_eq!(fake.messages("INBOX/Archive").len(), 1);
    let nowhere = session
        .apply(
            &CommandBody::Move {
                from: "INBOX".into(),
                to: "Nowhere".into(),
                items: vec![items[2].clone()],
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        nowhere,
        WriteOutcome::Failed {
            reason: "no_such_mailbox".into()
        }
    );

    let stale = ItemRef {
        id: "999:3".into(),
        uid: Some(3),
    };
    assert_eq!(
        session
            .apply(&delete("INBOX", vec![stale]), None)
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert_eq!(
        fake.messages("INBOX").len(),
        2,
        "an id of another UIDVALIDITY is not touched"
    );
    assert_eq!(
        session
            .apply(&delete("INBOX", vec![items[2].clone()]), None)
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert!(fake.commands().iter().any(|c| c == "UID EXPUNGE 3"));
    assert_eq!(fake.messages("INBOX").len(), 1);

    let raw = Bytes::from_static(b"From: ada@example.com\r\nSubject: Sent\r\n\r\nHello\r\n");
    let append = CommandBody::Append {
        mailbox: "INBOX/Отправленные".into(),
        blob: BlobHash::of(&raw),
        flags: Flags::new(["\\Seen", "$Sent"]),
        received_at: None,
    };
    assert_eq!(
        session.apply(&append, Some(raw.clone())).await.unwrap(),
        WriteOutcome::Applied
    );
    let sent = fake.messages("INBOX/Отправленные");
    assert_eq!(sent[0].raw, raw);
    assert_eq!(sent[0].flags, ["$Sent", "\\Seen"]);
    assert_eq!(
        session.apply(&append, None).await.unwrap(),
        WriteOutcome::Failed {
            reason: "missing_content".into()
        }
    );
    assert!(matches!(
        session
            .apply(
                &CommandBody::Append {
                    mailbox: "Nowhere".into(),
                    blob: BlobHash::of(&raw),
                    flags: Flags::default(),
                    received_at: None,
                },
                Some(raw.clone())
            )
            .await,
        Err(MailError::MailboxNotFound)
    ));
    assert_eq!(
        session
            .apply(
                &CommandBody::Refetch {
                    mailbox: "INBOX".into(),
                    item: items[0].clone(),
                },
                None
            )
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "unsupported".into()
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn moves_by_copy_with_uidplus_and_refuses_without_it() {
    let copy = Fake::start(Caps {
        uidplus: true,
        ..BARE
    })
    .await;
    copy.add("INBOX", b"Subject: a\r\n\r\na\r\n", Flags::default())
        .await;
    copy.add(
        "INBOX",
        b"Subject: b\r\n\r\nb\r\n",
        Flags::new(["\\Deleted"]),
    )
    .await;
    let items = listed(&copy, "INBOX").await;
    let mut session = copy.provider().connect().await.unwrap();
    let moved = session
        .apply(
            &CommandBody::Move {
                from: "INBOX".into(),
                to: "INBOX/Archive".into(),
                items: vec![items[0].clone()],
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(moved, WriteOutcome::Applied);
    let v = verbs(&copy);
    assert!(v.contains(&"UID COPY".to_owned()) && v.contains(&"UID EXPUNGE".to_owned()));
    assert!(!v.contains(&"EXPUNGE".to_owned()));
    assert_eq!(
        copy.messages("INBOX").len(),
        1,
        "the other deleted message stays"
    );

    let bare = Fake::start(BARE).await;
    bare.add("INBOX", b"Subject: a\r\n\r\na\r\n", Flags::default())
        .await;
    let items = listed(&bare, "INBOX").await;
    let mut session = bare.provider().connect().await.unwrap();
    let before = bare.commands().len();
    assert_eq!(
        session
            .apply(&delete("INBOX", items.clone()), None)
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "no_uidplus".into()
        }
    );
    let moved = session
        .apply(
            &CommandBody::Move {
                from: "INBOX".into(),
                to: "INBOX/Archive".into(),
                items,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        moved,
        WriteOutcome::Failed {
            reason: "no_uidplus".into()
        }
    );
    assert_eq!(bare.commands().len(), before, "refused before any command");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_lost_after_a_write_is_uncertain() {
    let fake = Fake::start(FULL).await;
    fake.add("INBOX", b"Subject: a\r\n\r\na\r\n", Flags::default())
        .await;
    let items = listed(&fake, "INBOX").await;
    let mut session = fake.provider().connect().await.unwrap();
    fake.state.lock().unwrap().drop_on = Some("UID STORE");
    let outcome = session
        .apply(
            &CommandBody::SetFlags {
                mailbox: "INBOX".into(),
                items,
                add: Flags::new(["\\Seen"]),
                remove: Flags::default(),
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Uncertain);
    assert!(matches!(
        session.mailboxes().await,
        Err(MailError::Network(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn signs_in_with_an_access_token() {
    let fake = Fake::start(BARE).await;
    let provider = fake.provider_with(Credentials::AccessToken {
        token: "good-token".into(),
    });
    provider.connect().await.unwrap().logout().await.unwrap();
    let refused = fake.provider_with(Credentials::AccessToken {
        token: "expired".into(),
    });
    assert!(matches!(
        refused.connect().await.err(),
        Some(MailError::Auth)
    ));
}

#[test]
fn builds_the_xoauth2_response() {
    assert_eq!(
        xoauth2("ada@example.com", "t0k"),
        "user=ada@example.com\u{1}auth=Bearer t0k\u{1}\u{1}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn maps_refusals_and_unreachable_servers() {
    let fake = Fake::start(BARE).await;
    let wrong = fake.provider_with(Credentials::Password {
        secret: "wrong".into(),
    });
    assert!(matches!(wrong.connect().await.err(), Some(MailError::Auth)));
    let busy = fake.provider_with(Credentials::Password {
        secret: "busy".into(),
    });
    assert!(matches!(
        busy.connect().await.err(),
        Some(MailError::Throttled { .. })
    ));
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut settings = fake.settings();
    settings.port = Some(closed);
    let gone = ImapProvider::new(
        settings,
        Credentials::Password {
            secret: "secret".into(),
        },
    )
    .unwrap();
    assert!(matches!(
        gone.connect().await.err(),
        Some(MailError::Network(_))
    ));
}

#[test]
fn refuses_plain_text_to_remote_hosts() {
    let password = || Credentials::Password {
        secret: "secret".into(),
    };
    let mut settings = ImapSettings::new("imap.example.com", "ada@example.com");
    settings.security = Security::Plain;
    assert!(matches!(
        ImapProvider::new(settings.clone(), password()),
        Err(MailError::Config(_))
    ));
    settings.allow_insecure_plain = true;
    assert!(ImapProvider::new(settings, password()).is_ok());
    for host in [
        "127.0.0.1",
        "127.8.9.10",
        "::1",
        "[::1]",
        "localhost",
        "LOCALHOST",
    ] {
        let mut local = ImapSettings::new(host, "ada@example.com");
        local.security = Security::Plain;
        assert!(ImapProvider::new(local, password()).is_ok(), "{host}");
    }
    for host in ["10.0.0.1", "192.168.1.1", "localhost.example.com", ""] {
        let mut remote = ImapSettings::new(host, "ada@example.com");
        remote.security = Security::Plain;
        assert!(ImapProvider::new(remote, password()).is_err(), "{host}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_server_without_starttls() {
    let fake = Fake::start(BARE).await;
    let mut settings = fake.settings();
    settings.security = Security::Starttls;
    let provider = ImapProvider::new(
        settings,
        Credentials::Password {
            secret: "secret".into(),
        },
    )
    .unwrap()
    .with_timeout(Duration::from_secs(5));
    let error = provider.connect().await.err().unwrap();
    assert!(matches!(error, MailError::Config(_)), "{error:?}");
    assert!(
        !verbs(&fake).iter().any(|v| v == "LOGIN"),
        "no credentials after a refused STARTTLS"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn trusts_extra_roots_only_when_given() {
    let ca = TestCa::new(&["localhost"]);
    let fake = Fake::start_with(BARE, Transport::Tls(ca.acceptor()), Some(&ca)).await;
    assert!(fake.provider().connect().await.is_ok());
    let mut settings = fake.settings();
    settings.roots = skein_core::TlsRoots::default();
    let untrusted = ImapProvider::new(
        settings.clone(),
        Credentials::Password {
            secret: "secret".into(),
        },
    )
    .unwrap();
    assert!(matches!(
        untrusted.connect().await.err(),
        Some(MailError::Network(_))
    ));
    settings.roots = TestCa::new(&["localhost"]).roots();
    let other = ImapProvider::new(
        settings,
        Credentials::Password {
            secret: "secret".into(),
        },
    )
    .unwrap();
    assert!(matches!(
        other.connect().await.err(),
        Some(MailError::Network(_))
    ));
    assert_eq!(verbs(&fake).iter().filter(|v| *v == "LOGIN").count(), 1);

    let garbage = skein_core::TlsRoots::from_der(vec![vec![1, 2, 3]]);
    let mut bad = ImapSettings::new("imap.example.com", "ada@example.com");
    bad.roots = garbage;
    assert!(matches!(
        ImapProvider::new(bad, Credentials::Password { secret: "x".into() }),
        Err(MailError::Config(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn gives_up_on_a_server_that_stops_answering() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut open = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            open.push(socket);
        }
    });
    let mut settings = ImapSettings::new("127.0.0.1", "ada@example.com");
    settings.port = Some(port);
    settings.security = Security::Plain;
    let started = std::time::Instant::now();
    let error = ImapProvider::new(
        settings,
        Credentials::Password {
            secret: "secret".into(),
        },
    )
    .unwrap()
    .with_timeout(Duration::from_millis(300))
    .connect()
    .await
    .err()
    .unwrap();
    assert!(matches!(error, MailError::Network(_)), "{error}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn settings_default_to_tls_and_hide_the_user() {
    let settings = ImapSettings::from_json(
        &serde_json::json!({ "host": "imap.example.com", "username": "ada@example.com" }),
    )
    .unwrap();
    assert_eq!(settings.security, Security::Tls);
    assert_eq!(settings.port(), 993);
    assert!(!settings.allow_insecure_plain);
    assert!(!format!("{settings:?}").contains("ada@"));
    assert!(matches!(
        ImapSettings::from_json(&serde_json::json!({ "host": "x" })),
        Err(MailError::Config(_))
    ));
}

#[test]
fn compresses_uid_sets() {
    assert_eq!(uid_set(&[1, 2, 3, 7, 9]), "1:3,7,9");
    assert_eq!(uid_set(&[5]), "5");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removal_during_a_paged_listing_is_not_lost() {
    for caps in [BARE, FULL] {
        let fake = Fake::start(caps).await;
        for n in 1..=4 {
            fake.add(
                "INBOX",
                format!("Subject: {n}\r\n\r\n{n}\r\n").as_bytes(),
                Flags::default(),
            )
            .await;
        }
        let mut session = fake.provider().connect().await.unwrap();
        let first = session.changes("INBOX", None, 2).await.unwrap();
        assert!(first.more);
        fake.remove("INBOX", b"Subject: 1\r\n\r\n1\r\n").await;
        let second = session
            .changes("INBOX", Some(&first.cursor), 2)
            .await
            .unwrap();
        assert!(!second.more);
        assert_eq!(second.changes.len(), 3, "{:?}", second.changes);
        assert!(matches!(&second.changes[0], MailChange::Removed { item } if item.uid == Some(1)));
        let third = session
            .changes("INBOX", Some(&second.cursor), 2)
            .await
            .unwrap();
        assert!(third.changes.is_empty());
    }
}

mod write;
