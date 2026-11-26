use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use skein_core::Credentials;
use skein_mail::{MailError, MailProvider};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use super::*;

const FOLDERS: [&str; 3] = ["INBOX", "Archive", "Work"];

#[derive(Default)]
struct Counts {
    connections: usize,
    idles: usize,
    dones: usize,
    notify_sets: usize,
    logouts: usize,
    messages: HashMap<String, usize>,
}

/// An IMAP server in the test process that speaks just enough for watches: `IDLE`, optionally
/// `NOTIFY`, and deliveries announced to idling connections.
#[derive(Clone)]
struct IdleServer {
    port: u16,
    events: broadcast::Sender<String>,
    counts: Arc<Mutex<Counts>>,
    kill: broadcast::Sender<()>,
}

impl IdleServer {
    async fn start(capabilities: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (events, _) = broadcast::channel(64);
        let (kill, _) = broadcast::channel(4);
        let server = Self {
            port,
            events,
            counts: Arc::default(),
            kill,
        };
        let spawned = server.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                spawned.counts.lock().unwrap().connections += 1;
                tokio::spawn(spawned.clone().session(socket, capabilities));
            }
        });
        server
    }

    fn source(&self) -> ImapProvider {
        let mut settings = ImapSettings::new("127.0.0.1", "ada@example.com");
        settings.port = Some(self.port);
        settings.security = Security::Plain;
        ImapProvider::new(
            settings,
            Credentials::Password {
                secret: "secret".into(),
            },
        )
        .unwrap()
        .with_timeout(Duration::from_secs(5))
    }

    fn counts<T>(&self, read: impl FnOnce(&Counts) -> T) -> T {
        read(&self.counts.lock().unwrap())
    }

    async fn session(self, socket: tokio::net::TcpStream, capabilities: &'static str) {
        let mut events = self.events.subscribe();
        let mut kill = self.kill.subscribe();
        let (read, mut write) = socket.into_split();
        let mut lines = BufReader::new(read).lines();
        let _ = write.write_all(b"* OK fake idle server\r\n").await;
        let mut selected: Option<String> = None;
        let mut notified: Vec<String> = Vec::new();
        let mut idling: Option<String> = None;
        let mut pending: Vec<String> = Vec::new();
        loop {
            let line = tokio::select! {
                line = lines.next_line() => match line {
                    Ok(Some(line)) => line,
                    _ => return,
                },
                event = events.recv() => {
                    let Ok(folder) = event else { continue };
                    pending.push(folder);
                    if idling.is_some() {
                        let out = self.announce(&mut pending, selected.as_deref(), &notified);
                        if write.write_all(out.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                    continue;
                }
                _ = kill.recv() => return,
            };
            if let Some(tag) = &idling {
                assert_eq!(line, "DONE", "only DONE ends IDLE");
                self.counts.lock().unwrap().dones += 1;
                let _ = write
                    .write_all(format!("{tag} OK IDLE terminated\r\n").as_bytes())
                    .await;
                idling = None;
                continue;
            }
            let (tag, rest) = line.split_once(' ').unwrap_or((&line, ""));
            let upper = rest.to_ascii_uppercase();
            let out = if upper.starts_with("CAPABILITY") {
                format!("* CAPABILITY IMAP4rev1 {capabilities}\r\n{tag} OK done\r\n")
            } else if upper.starts_with("LOGIN") {
                if rest.contains("\"secret\"") || rest.contains(" secret") {
                    format!("{tag} OK LOGIN completed\r\n")
                } else {
                    format!("{tag} NO [AUTHENTICATIONFAILED] refused\r\n")
                }
            } else if upper.starts_with("LIST") {
                let mut out = String::new();
                for folder in FOLDERS {
                    out.push_str(&format!("* LIST (\\HasNoChildren) \"/\" \"{folder}\"\r\n"));
                }
                out + &format!("{tag} OK LIST completed\r\n")
            } else if upper.starts_with("EXAMINE") {
                let name = rest[8..].trim().trim_matches('"').to_owned();
                let count = self.counts(|c| c.messages.get(&name).copied().unwrap_or(0));
                selected = Some(name);
                format!(
                    "* {count} EXISTS\r\n* OK [UIDVALIDITY 1] valid\r\n{tag} OK [READ-ONLY] done\r\n"
                )
            } else if upper.starts_with("NOTIFY SET") {
                assert!(capabilities.contains("NOTIFY"), "NOTIFY sent without it");
                self.counts.lock().unwrap().notify_sets += 1;
                notified = FOLDERS
                    .iter()
                    .filter(|f| rest.contains(&format!("\"{f}\"")))
                    .map(|f| f.to_string())
                    .collect();
                format!("{tag} OK NOTIFY completed\r\n")
            } else if upper.starts_with("IDLE") {
                assert!(capabilities.contains("IDLE"), "IDLE sent without it");
                self.counts.lock().unwrap().idles += 1;
                idling = Some(tag.to_owned());
                "+ idling\r\n".to_owned()
                    + &self.announce(&mut pending, selected.as_deref(), &notified)
            } else if upper.starts_with("LOGOUT") {
                self.counts.lock().unwrap().logouts += 1;
                let _ = write
                    .write_all(format!("* BYE\r\n{tag} OK LOGOUT completed\r\n").as_bytes())
                    .await;
                return;
            } else {
                format!("{tag} BAD unknown\r\n")
            };
            if write.write_all(out.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    fn announce(
        &self,
        pending: &mut Vec<String>,
        selected: Option<&str>,
        notified: &[String],
    ) -> String {
        let mut out = String::new();
        for folder in pending.drain(..) {
            let count = self.counts(|c| c.messages.get(&folder).copied().unwrap_or(0));
            if selected == Some(folder.as_str()) {
                out.push_str(&format!("* {count} EXISTS\r\n* 1 RECENT\r\n"));
            } else if notified.contains(&folder) {
                out.push_str(&format!(
                    "* STATUS \"{folder}\" (MESSAGES {count} UIDNEXT {})\r\n",
                    count + 1
                ));
            }
        }
        out
    }

    async fn wait_for_idles(&self, at_least: usize) {
        for _ in 0..200 {
            if self.counts(|c| c.idles) >= at_least {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the watch never started IDLE");
    }
}

impl IdleServer {
    async fn deliver(&self, path: &str) {
        *self
            .counts
            .lock()
            .unwrap()
            .messages
            .entry(path.to_owned())
            .or_default() += 1;
        let _ = self.events.send(path.to_owned());
    }
}

#[tokio::test]
async fn a_server_without_idle_is_not_watched() {
    let server = IdleServer::start("").await;
    assert!(server.source().watch(&[]).await.unwrap().is_none());
    assert_eq!(server.counts(|c| c.logouts), 1, "the probe signs out");
}

#[tokio::test]
async fn idle_wakes_the_watch_on_a_delivery() {
    let server = IdleServer::start("IDLE").await;
    let mut watch = server
        .source()
        .watch(&["INBOX".into()])
        .await
        .unwrap()
        .unwrap();
    server.wait_for_idles(1).await;
    server.deliver("Archive").await;
    server.deliver("INBOX").await;
    let changed = tokio::time::timeout(Duration::from_secs(5), watch.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed.mailboxes, Some(vec!["INBOX".to_owned()]));
    server.deliver("INBOX").await;
    tokio::time::timeout(Duration::from_secs(5), watch.next())
        .await
        .expect("a second delivery wakes the watch again")
        .unwrap();
    assert_eq!(
        server.counts(|c| c.connections),
        1,
        "one mailbox, one connection"
    );
}

#[tokio::test]
async fn notify_watches_several_folders_on_one_connection() {
    let server = IdleServer::start("IDLE NOTIFY").await;
    let source = server.source();
    let mut watch = source
        .watch(&["INBOX".into(), "Work".into(), "Gone".into()])
        .await
        .unwrap()
        .unwrap();
    server.wait_for_idles(1).await;
    assert_eq!(server.counts(|c| c.notify_sets), 1);
    server.deliver("Work").await;
    let changed = tokio::time::timeout(Duration::from_secs(5), watch.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed.mailboxes, Some(vec!["Work".to_owned()]));
    server.deliver("Archive").await;
    server.deliver("INBOX").await;
    let changed = tokio::time::timeout(Duration::from_secs(5), watch.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        changed.mailboxes,
        Some(vec!["INBOX".to_owned()]),
        "Archive is not watched"
    );
    drop(watch);
    assert_eq!(server.counts(|c| c.connections), 1);
}

#[tokio::test]
async fn without_notify_each_folder_gets_a_connection_up_to_the_limit() {
    let server = IdleServer::start("IDLE").await;
    let source = server.source();
    let mut watch = source
        .watch(&[
            "INBOX".into(),
            "Archive".into(),
            "Work".into(),
            "INBOX".into(),
        ])
        .await
        .unwrap()
        .unwrap();
    server.wait_for_idles(3).await;
    assert_eq!(server.counts(|c| c.connections), 3);
    server.deliver("Archive").await;
    let changed = tokio::time::timeout(Duration::from_secs(5), watch.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed.mailboxes, Some(vec!["Archive".to_owned()]));
    drop(watch);
}

#[tokio::test]
async fn idle_is_renewed_and_a_lost_connection_ends_the_watch() {
    let server = IdleServer::start("IDLE").await;
    let source = server.source().with_idle_renew(Duration::from_millis(100));
    let mut watch = source.watch(&[]).await.unwrap().unwrap();
    server.wait_for_idles(3).await;
    assert!(
        server.counts(|c| c.dones) >= 2,
        "each renewal ends the IDLE before"
    );
    let _ = server.kill.send(());
    let ended = tokio::time::timeout(Duration::from_secs(5), watch.next())
        .await
        .expect("a dead connection ends the watch");
    assert!(matches!(ended, Err(MailError::Network(_))));
}

#[tokio::test]
async fn a_refused_sign_in_fails_the_watch() {
    let server = IdleServer::start("IDLE").await;
    let mut settings = ImapSettings::new("127.0.0.1", "ada@example.com");
    settings.port = Some(server.port);
    settings.security = Security::Plain;
    let provider = ImapProvider::new(
        settings,
        Credentials::Password {
            secret: "wrong".into(),
        },
    )
    .unwrap();
    assert!(matches!(provider.watch(&[]).await, Err(MailError::Auth)));
}
