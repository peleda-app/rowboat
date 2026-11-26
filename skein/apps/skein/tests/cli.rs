//! The management subcommands against a real config with file storage: everything the HTTP
//! management API used to do for operators, without a listener.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

struct Node {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Node {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("skein.toml");
        std::fs::write(
            &config,
            format!(
                "[node]\nid = \"cli\"\n[storage]\nkind = \"fs\"\npath = \"{}\"\n[keyring]\nmaster_key_file = \"{}\"\n[server]\nenabled = false\n[webhooks]\nallow_http_loopback = true\n",
                dir.path().join("data").display(),
                dir.path().join("master.key").display(),
            ),
        )
        .unwrap();
        Self { dir, config }
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_skein"))
            .args(args)
            .env("SKEIN_CONFIG", &self.config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn ok(&self, args: &[&str], stdin: &str) -> String {
        let out = self.run(args, stdin);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn fails(&self, args: &[&str], stdin: &str) -> String {
        let out = self.run(args, stdin);
        assert!(!out.status.success(), "{args:?} should fail");
        String::from_utf8(out.stderr).unwrap()
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    }

    fn data(&self) -> &Path {
        self.dir.path()
    }
}

fn contains_anywhere(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().any(|e| {
        let path = e.unwrap().path();
        if path.is_dir() {
            contains_anywhere(&path, needle)
        } else {
            std::fs::read(&path)
                .map(|b| b.windows(needle.len()).any(|w| w == needle))
                .unwrap_or(false)
        }
    })
}

#[test]
fn tenants_accounts_and_secrets_are_managed_without_an_api() {
    let n = Node::new();
    n.ok(&["tenant", "add", "acme"], "");
    n.ok(&["tenant", "add", "acme"], "");
    n.ok(&["tenant", "add", "globex"], "");
    assert_eq!(n.ok(&["tenant", "list"], ""), "acme\nglobex\n");
    n.fails(&["tenant", "add", "_nodes"], "");

    let record = n.file(
        "box.json",
        r#"{"provider": "imap", "settings": {"host": "imap.example.com", "username": "ada@example.com"}, "auth": {"type": "password"}}"#,
    );
    n.ok(
        &[
            "account", "put", "--tenant", "acme", "box", "--file", &record,
        ],
        "",
    );
    n.fails(
        &[
            "account", "put", "--tenant", "nobody", "box", "--file", &record,
        ],
        "",
    );
    let other = n.file(
        "other.json",
        r#"{"account": "other", "provider": "imap", "settings": {}, "auth": {"type": "password"}}"#,
    );
    assert!(
        n.fails(
            &[
                "account", "put", "--tenant", "acme", "box", "--file", &other
            ],
            ""
        )
        .contains("another account")
    );
    let bad = n.file(
        "bad.json",
        r#"{"provider": "imap", "settings": "imap.example.com", "auth": {"type": "password"}}"#,
    );
    assert!(
        n.fails(
            &["account", "put", "--tenant", "acme", "box", "--file", &bad],
            ""
        )
        .contains("invalid_settings")
    );

    let password = "correct-horse-battery-EXAMPLE";
    n.ok(
        &["account", "password", "--tenant", "acme", "box"],
        &format!("{password}\n"),
    );
    n.fails(&["account", "password", "--tenant", "acme", "box"], "");
    n.fails(&["account", "password", "--tenant", "acme", "ghost"], "x\n");
    let token = "ya29.access-EXAMPLE";
    n.ok(
        &["account", "grant", "--tenant", "acme", "box"],
        &format!("{token}\nrefresh-EXAMPLE\n"),
    );
    assert!(!contains_anywhere(n.data(), password.as_bytes()));
    assert!(!contains_anywhere(n.data(), token.as_bytes()));

    let listed = n.ok(&["account", "list", "--tenant", "acme"], "");
    let line: Value = serde_json::from_str(listed.lines().next().unwrap()).unwrap();
    assert_eq!(line["record"]["account"], "box");
    assert_eq!(line["health"]["head"], 0);
    assert!(!listed.contains(password) && !listed.contains(token));
    let shown: Value =
        serde_json::from_str(&n.ok(&["account", "show", "--tenant", "acme", "box"], "")).unwrap();
    assert_eq!(shown["record"]["settings"]["host"], "imap.example.com");

    n.ok(&["account", "remove", "--tenant", "acme", "box"], "");
    n.fails(&["account", "show", "--tenant", "acme", "box"], "");
    n.fails(&["account", "remove", "--tenant", "acme", "box"], "");

    n.ok(&["tenant", "remove", "globex"], "");
    assert_eq!(n.ok(&["tenant", "list"], ""), "acme\n");
    n.fails(&["tenant", "remove", "globex"], "");
}

#[test]
fn commands_blobs_and_the_journal() {
    let n = Node::new();
    n.ok(&["tenant", "add", "acme"], "");
    let record = n.file(
        "box.json",
        r#"{"provider": "imap", "settings": {"host": "imap.example.com"}, "auth": {"type": "password"}}"#,
    );
    n.ok(
        &[
            "account", "put", "--tenant", "acme", "box", "--file", &record,
        ],
        "",
    );
    let message = n.file(
        "message.eml",
        "From: ada@example.com\r\nTo: sam@example.org\r\nSubject: Hi\r\n\r\nHello.\r\n",
    );
    let hash = n
        .ok(
            &[
                "journal", "put-blob", "--tenant", "acme", "--file", &message,
            ],
            "",
        )
        .trim()
        .to_owned();
    assert_eq!(hash.len(), 64);
    let copy = n.data().join("copy.eml");
    n.ok(
        &[
            "journal",
            "get-blob",
            "--tenant",
            "acme",
            &hash,
            "--out",
            copy.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(
        std::fs::read(&copy).unwrap(),
        std::fs::read(&message).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&copy).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "blobs are written for the owner only");
        let target = n.data().join("target.txt");
        std::fs::write(&target, "keep").unwrap();
        let link = n.data().join("link.eml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        n.fails(
            &[
                "journal",
                "get-blob",
                "--tenant",
                "acme",
                &hash,
                "--out",
                link.to_str().unwrap(),
            ],
            "",
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }
    std::fs::write(&copy, "older").unwrap();
    n.fails(
        &[
            "journal",
            "get-blob",
            "--tenant",
            "acme",
            &hash,
            "--out",
            copy.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), "older");

    let append = n.file(
        "append.json",
        &format!(
            r#"{{"id": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "body": {{"type": "append", "mailbox": "INBOX", "blob": "{hash}", "flags": ["\\Seen"]}}}}"#
        ),
    );
    let first: Value = serde_json::from_str(&n.ok(
        &[
            "journal", "submit", "--tenant", "acme", "box", "--file", &append,
        ],
        "",
    ))
    .unwrap();
    assert_eq!(first["id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    assert_eq!(first["duplicate"], false);
    let again: Value = serde_json::from_str(&n.ok(
        &[
            "journal", "submit", "--tenant", "acme", "box", "--file", &append,
        ],
        "",
    ))
    .unwrap();
    assert_eq!(again["duplicate"], true);
    let missing = n.file(
        "missing.json",
        &format!(
            r#"{{"body": {{"type": "append", "mailbox": "INBOX", "blob": "{}", "flags": []}}}}"#,
            "0".repeat(64)
        ),
    );
    n.fails(
        &[
            "journal", "submit", "--tenant", "acme", "box", "--file", &missing,
        ],
        "",
    );
    let dirty = n.file(
        "dirty.json",
        r#"{"body": {"type": "create_mailbox", "path": "a//b"}}"#,
    );
    assert!(
        n.fails(
            &[
                "journal", "submit", "--tenant", "acme", "box", "--file", &dirty
            ],
            ""
        )
        .contains("invalid_path")
    );
    n.fails(
        &[
            "journal", "submit", "--tenant", "acme", "ghost", "--file", &append,
        ],
        "",
    );
    n.ok(
        &[
            "journal",
            "cancel",
            "--tenant",
            "acme",
            "box",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ],
        "",
    );
    n.ok(
        &[
            "journal",
            "cancel",
            "--tenant",
            "acme",
            "box",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ],
        "",
    );
    assert_eq!(
        n.ok(&["journal", "events", "--tenant", "acme", "box"], ""),
        ""
    );
}

#[test]
fn webhooks_show_their_secret_once() {
    let n = Node::new();
    n.ok(&["tenant", "add", "acme"], "");
    let added: Value = serde_json::from_str(&n.ok(
        &[
            "webhook",
            "add",
            "--tenant",
            "acme",
            "--url",
            "http://127.0.0.1:9/hook",
            "--events",
            "message_added",
        ],
        "",
    ))
    .unwrap();
    let id = added["id"].as_str().unwrap().to_owned();
    let secret = added["secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("whsec_"));
    let listed = n.ok(&["webhook", "list", "--tenant", "acme"], "");
    assert!(listed.contains(&id) && !listed.contains(&secret));
    assert!(!contains_anywhere(n.data(), secret.as_bytes()));
    let paused: Value =
        serde_json::from_str(&n.ok(&["webhook", "pause", "--tenant", "acme", &id], "")).unwrap();
    assert_eq!(paused["paused"], true);
    n.ok(&["webhook", "resume", "--tenant", "acme", &id], "");
    let rotated = n.ok(&["webhook", "rotate", "--tenant", "acme", &id], "");
    assert_ne!(rotated.trim(), secret);
    n.fails(
        &[
            "webhook",
            "add",
            "--tenant",
            "acme",
            "--url",
            "http://203.0.113.9/hook",
        ],
        "",
    );
    n.ok(&["webhook", "remove", "--tenant", "acme", &id], "");
    n.fails(&["webhook", "remove", "--tenant", "acme", &id], "");
}

#[test]
fn purging_needs_confirmation_and_is_final() {
    let n = Node::new();
    n.ok(&["tenant", "add", "acme"], "");
    for args in [
        vec!["tenant", "remove", "acme", "--purge"],
        vec!["tenant", "remove", "acme", "--purge", "--confirm", "globex"],
    ] {
        assert!(n.fails(&args, "").contains("--confirm"));
    }
    assert_eq!(n.ok(&["tenant", "list"], ""), "acme\n");
    n.ok(
        &["tenant", "remove", "acme", "--purge", "--confirm", "acme"],
        "",
    );
    assert_eq!(n.ok(&["tenant", "list"], ""), "");
    assert!(n.fails(&["tenant", "add", "acme"], "").contains("purged"));
}

#[test]
fn memory_storage_has_nothing_to_manage() {
    let n = Node::new();
    let config = n.file(
        "memory.toml",
        "[node]\nid = \"m\"\n[storage]\nkind = \"memory\"\n[keyring]\nmaster_key_file = \"k\"\n",
    );
    assert!(
        n.fails(&["tenant", "list", "--config", &config], "")
            .contains("memory")
    );
}
