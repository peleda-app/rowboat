#![no_main]

use libfuzzer_sys::fuzz_target;
use rusqlite::Connection;

#[allow(dead_code)]
#[path = "../../crates/view/src/parse.rs"]
mod parse;
#[path = "../../crates/view/src/threads.rs"]
mod threads;

const SCHEMA: &str = "
CREATE TABLE threads (id INTEGER PRIMARY KEY, account TEXT NOT NULL, subject_key TEXT);
CREATE TABLE thread_ids (account TEXT NOT NULL, msgid TEXT NOT NULL, thread INTEGER NOT NULL,
  PRIMARY KEY (account, msgid));
CREATE TABLE messages (account TEXT NOT NULL, thread_id INTEGER);
";

fuzz_target!(|data: &[u8]| {
    let tags: Vec<String> = String::from_utf8_lossy(data)
        .split([' ', '\0'])
        .map(str::to_owned)
        .collect();
    let kept = parse::clean_tags(&tags);
    assert!(kept.len() <= parse::MAX_TAGS);
    assert!(kept.iter().all(|t| parse::valid_tag(t)));
    assert!(kept.windows(2).all(|w| w[0] < w[1]));
    let messages: Vec<parse::Parsed> = data.split(|b| *b == 0).take(4).map(parse::parse).collect();
    for p in &messages {
        if let Some(text) = &p.text {
            assert!(text.len() <= parse::TEXT_CAP);
        }
        if let Some(html) = &p.html {
            assert!(html.len() <= parse::HTML_CAP);
        }
        if let Some(snippet) = &p.snippet {
            assert!(snippet.chars().count() <= parse::SNIPPET_CHARS);
        }
        for id in p
            .message_id
            .iter()
            .chain(&p.in_reply_to)
            .chain(&p.references)
        {
            assert!(!id.is_empty() && !id.starts_with('<') && !id.ends_with('>'));
        }
        let _ = threads::subject_key(p.subject.as_deref());
    }
    let mut db = Connection::open_in_memory().expect("an in-memory database");
    db.execute_batch(SCHEMA).expect("the schema applies");
    let tx = db.transaction().expect("a transaction");
    for p in &messages {
        threads::assign(&tx, "a1", p).expect("a message gets a thread");
    }
});
