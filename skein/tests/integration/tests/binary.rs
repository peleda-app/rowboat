//! The real `skein` binary end to end: started from a config file, managed only through its
//! subcommands (there is no management API), syncing an IMAP account and a CalDAV calendar in the
//! integration stack. Skips unless `SKEIN_IT=1` and `SKEIN_IT_BIN` points at a built binary
//! (`it.sh` sets both).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

struct Node {
    child: Child,
    base: String,
    config: PathBuf,
    http: reqwest::Client,
}

impl Node {
    fn cli(&self, args: &[&str], stdin: &str) -> String {
        cli(&self.config, args, stdin)
    }

    fn events(&self) -> Vec<Value> {
        self.cli(
            &[
                "journal", "events", "--tenant", "acme", "box", "--from", "1", "--limit", "1000",
            ],
            "",
        )
        .lines()
        .map(|l| serde_json::from_str(l).expect("an event per line"))
        .collect()
    }
}

fn cli(config: &Path, args: &[&str], stdin: &str) -> String {
    let mut child = Command::new(env("SKEIN_IT_BIN"))
        .args(args)
        .arg("--config")
        .arg(config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run the binary");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "skein {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for(node: &Node, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(found) = node.events().into_iter().find(|e| pred(e)) {
            return found;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn the_binary_syncs_an_account_configured_through_its_subcommands() {
    if std::env::var("SKEIN_IT").as_deref() != Ok("1") || std::env::var("SKEIN_IT_BIN").is_err() {
        eprintln!("SKEIN_IT or SKEIN_IT_BIN is not set; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let metrics_port = free_port();
    let config = format!(
        r#"
[node]
id = "it-node"

[storage]
kind = "fs"
path = "{data}"

[keyring]
master_key_file = "{key}"

[server]
listen = "127.0.0.1:{port}"

[engine]
heartbeat_secs = 1
interval_secs = 5

[metrics]
listen = "127.0.0.1:{metrics_port}"

[telemetry]
filter = "warn,skein=info"
"#,
        data = dir.path().join("data").display(),
        key = dir.path().join("master.key").display(),
    );
    let config_path = dir.path().join("skein.toml");
    std::fs::write(&config_path, config).unwrap();
    let log = std::fs::File::create(dir.path().join("skein.log")).unwrap();
    let child = Command::new(env("SKEIN_IT_BIN"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .expect("start the binary");
    let node = Node {
        child,
        base: format!("http://127.0.0.1:{port}"),
        config: config_path.clone(),
        http: reqwest::Client::new(),
    };

    let deadline = Instant::now() + Duration::from_secs(30);
    while node
        .http
        .get(format!("{}/v1/health", node.base))
        .send()
        .await
        .is_err()
    {
        assert!(Instant::now() < deadline, "the binary did not start");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    for path in [
        "/v1/tenants",
        "/v1/tenants/acme/accounts/box/events",
        "/v1/openapi.json",
        "/",
    ] {
        let status = node
            .http
            .get(format!("{}{path}", node.base))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        assert_eq!(status, 404, "{path} is not served");
    }

    let echoed = node
        .http
        .post(format!(
            "{}/v1/push/graph?validationToken=it-check",
            node.base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(echoed.status().as_u16(), 200);
    assert_eq!(echoed.text().await.unwrap(), "it-check");
    let gmail = node
        .http
        .post(format!("{}/v1/push/gmail/anything", node.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        gmail.status().as_u16(),
        404,
        "Gmail push is off without a token"
    );

    node.cli(&["tenant", "add", "acme"], "");
    let record = json!({
        "provider": "imap",
        "settings": {
            "host": env("SKEIN_IT_IMAP_HOST"),
            "port": env("SKEIN_IT_IMAP_PORT").parse::<u16>().unwrap(),
            "security": "plain",
            "username": env("SKEIN_IT_IMAP_USER"),
        },
        "auth": {"type": "password"},
        "include": ["INBOX"],
        "pim": {"kind": "dav", "auth": {"type": "password"}, "settings": {
            "calendars": format!("{}/{}/", env("SKEIN_IT_RADICALE_URL"), env("SKEIN_IT_RADICALE_USER")),
        }},
    });
    let record_path = dir.path().join("box.json");
    std::fs::write(&record_path, record.to_string()).unwrap();
    node.cli(
        &[
            "account",
            "put",
            "--tenant",
            "acme",
            "box",
            "--file",
            record_path.to_str().unwrap(),
        ],
        "",
    );
    node.cli(
        &["account", "password", "--tenant", "acme", "box"],
        &format!("{}\n", env("SKEIN_IT_IMAP_PASSWORD")),
    );
    node.cli(
        &["account", "password", "--tenant", "acme", "box", "--pim"],
        &format!("{}\n", env("SKEIN_IT_RADICALE_PASSWORD")),
    );

    let tag = format!("bin-{port}-{}", std::process::id());
    let message = format!(
        "From: Skein Test <skein-test@example.com>\r\nTo: ada@example.com\r\nSubject: binary {tag}\r\nMessage-ID: <{tag}@example.com>\r\n\r\nWritten by the binary test.\r\n"
    );
    let message_path = dir.path().join("message.eml");
    std::fs::write(&message_path, &message).unwrap();
    let hash = node
        .cli(
            &[
                "journal",
                "put-blob",
                "--tenant",
                "acme",
                "--file",
                message_path.to_str().unwrap(),
            ],
            "",
        )
        .trim()
        .to_owned();

    let submit = |name: &str, command: Value| -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, command.to_string()).unwrap();
        let out: Value = serde_json::from_str(&node.cli(
            &[
                "journal",
                "submit",
                "--tenant",
                "acme",
                "box",
                "--file",
                path.to_str().unwrap(),
            ],
            "",
        ))
        .unwrap();
        assert_eq!(out["duplicate"], false);
        out["id"].as_str().unwrap().to_owned()
    };
    let command = submit(
        "append.json",
        json!({"body": {"type": "append", "mailbox": "INBOX", "blob": hash, "flags": []}}),
    );

    wait_for(&node, "the append's outcome", |e| {
        e["origin"] == command && e["body"]["type"] == "write_applied"
    })
    .await;
    let added = wait_for(&node, "the appended message in the journal", |e| {
        e["body"]["type"] == "message_added" && e["body"]["blob"] == hash
    })
    .await;
    let item = added["body"]["item"].clone();

    let copy = dir.path().join("copy.eml");
    node.cli(
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
        message.as_bytes(),
        "the blob is the original bytes"
    );

    submit(
        "delete.json",
        json!({"body": {"type": "delete", "mailbox": "INBOX", "items": [item.clone()]}}),
    );
    wait_for(&node, "the removal in the journal", |e| {
        e["body"]["type"] == "message_removed" && e["body"]["item"] == item
    })
    .await;

    let shown: Value =
        serde_json::from_str(&node.cli(&["account", "show", "--tenant", "acme", "box"], ""))
            .unwrap();
    assert!(shown["health"]["head"].as_u64().unwrap() > 0, "{shown}");

    let radicale = env("SKEIN_IT_RADICALE_URL");
    let dav_user = env("SKEIN_IT_RADICALE_USER");
    let calendar = format!("/{dav_user}/bin-{port}/");
    let status = node
        .http
        .request(
            reqwest::Method::from_bytes(b"MKCALENDAR").unwrap(),
            format!("{radicale}{calendar}"),
        )
        .basic_auth(&dav_user, Some(env("SKEIN_IT_RADICALE_PASSWORD")))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 201, "the test calendar is created");
    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Skein test//EN\r\nBEGIN:VEVENT\r\nUID:{tag}@example.com\r\nDTSTAMP:20251120T100000Z\r\nDTSTART:20251121T100000Z\r\nSUMMARY:Binary test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    );
    let ics_path = dir.path().join("event.ics");
    std::fs::write(&ics_path, ics).unwrap();
    let ics_hash = node
        .cli(
            &[
                "journal",
                "put-blob",
                "--tenant",
                "acme",
                "--file",
                ics_path.to_str().unwrap(),
            ],
            "",
        )
        .trim()
        .to_owned();
    let put = submit(
        "put.json",
        json!({"body": {"type": "put_object", "collection": calendar, "blob": ics_hash}}),
    );
    wait_for(&node, "the event's outcome", |e| {
        e["origin"] == put && e["body"]["type"] == "write_applied"
    })
    .await;
    wait_for(&node, "the event in the journal", |e| {
        e["body"]["type"] == "object_upserted" && e["body"]["collection"] == calendar
    })
    .await;
    let _ = node
        .http
        .delete(format!("{radicale}{calendar}"))
        .basic_auth(&dav_user, Some(env("SKEIN_IT_RADICALE_PASSWORD")))
        .send()
        .await;

    let metrics = node
        .http
        .get(format!("http://127.0.0.1:{metrics_port}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let value = |line: &str| -> u64 {
        metrics
            .lines()
            .find(|l| l.starts_with(line))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    assert!(
        value("skein_sync_runs_total{result=\"ok\"}") > 0,
        "{metrics}"
    );
    assert!(
        value("skein_commands_total{outcome=\"applied\"}") >= 2,
        "{metrics}"
    );
    assert!(
        value("skein_storage_requests_total{op=\"put\"}") > 0,
        "{metrics}"
    );
    assert!(
        !metrics.contains("acme") && !metrics.contains("box"),
        "no tenant or account in metrics"
    );

    let pid = node.child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let mut node = node;
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        if let Some(status) = node.child.try_wait().unwrap() {
            assert!(
                status.success(),
                "the binary stops cleanly on SIGTERM: {status}"
            );
            break;
        }
        assert!(Instant::now() < deadline, "the binary did not stop");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let log = std::fs::read_to_string(dir.path().join("skein.log")).unwrap();
    assert!(
        !log.contains(&env("SKEIN_IT_IMAP_PASSWORD")),
        "the password never reaches the log"
    );
    assert!(
        !log.contains(&env("SKEIN_IT_RADICALE_PASSWORD")),
        "the calendar password never reaches the log"
    );
}
