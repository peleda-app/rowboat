use std::collections::{BTreeSet, HashMap};

use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;

use crate::parse::Parsed;

/// The thread key of a subject: `Re:`, `Fwd:` and list tags stripped, lower case. `None` for
/// an empty subject.
pub fn subject_key(subject: Option<&str>) -> Option<String> {
    let s = mail_parser::thread_name(subject?.trim())
        .trim()
        .to_lowercase();
    (!s.is_empty()).then_some(s)
}

fn has_reply_prefix(subject: Option<&str>) -> bool {
    subject.is_some_and(|s| mail_parser::thread_name(s.trim()).len() < s.trim().len())
}

/// Picks the thread of a new message and records its ids, inside the caller's transaction.
///
/// JWZ grouping without the tree: the message joins the thread of any message that shares its
/// `Message-ID`, an `In-Reply-To` id or a `References` id, including ids only referenced so
/// far (a reply that arrives first leaves its parent's id behind, and the parent joins it).
/// When the ids reach several threads they are merged into the oldest. A message without any
/// reference ids whose subject has a reply prefix joins the newest thread with the same
/// subject key. Threads never split when messages leave.
pub fn assign(tx: &Transaction<'_>, account: &str, parsed: &Parsed) -> rusqlite::Result<i64> {
    let mut ids: Vec<&str> = Vec::new();
    for id in parsed
        .message_id
        .iter()
        .chain(&parsed.in_reply_to)
        .chain(&parsed.references)
    {
        if !ids.contains(&id.as_str()) {
            ids.push(id);
        }
    }
    let mut found = BTreeSet::new();
    {
        let mut q =
            tx.prepare_cached("SELECT thread FROM thread_ids WHERE account = ?1 AND msgid = ?2")?;
        for id in &ids {
            if let Some(t) = q
                .query_row(params![account, id], |r| r.get::<_, i64>(0))
                .optional()?
            {
                found.insert(t);
            }
        }
    }
    let key = subject_key(parsed.subject.as_deref());
    let unreferenced = parsed.in_reply_to.is_empty() && parsed.references.is_empty();
    if found.is_empty()
        && unreferenced
        && has_reply_prefix(parsed.subject.as_deref())
        && let Some(key) = &key
        && let Some(t) = tx
            .query_row(
                "SELECT id FROM threads WHERE account = ?1 AND subject_key = ?2 ORDER BY id DESC LIMIT 1",
                params![account, key],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
    {
        found.insert(t);
    }
    let thread = match found.first() {
        Some(t) => *t,
        None => {
            tx.execute(
                "INSERT INTO threads (account, subject_key) VALUES (?1, ?2)",
                params![account, key],
            )?;
            tx.last_insert_rowid()
        }
    };
    for other in found.iter().skip(1) {
        tx.execute(
            "UPDATE messages SET thread_id = ?1 WHERE account = ?2 AND thread_id = ?3",
            params![thread, account, other],
        )?;
        tx.execute(
            "UPDATE thread_ids SET thread = ?1 WHERE account = ?2 AND thread = ?3",
            params![thread, account, other],
        )?;
        tx.execute("DELETE FROM threads WHERE id = ?1", params![other])?;
    }
    let mut put = tx.prepare_cached(
        "INSERT INTO thread_ids (account, msgid, thread) VALUES (?1, ?2, ?3)
         ON CONFLICT (account, msgid) DO UPDATE SET thread = excluded.thread",
    )?;
    for id in ids {
        put.execute(params![account, id, thread])?;
    }
    Ok(thread)
}

/// A message as the tree builder sees it.
pub struct Link<'a> {
    /// The message id in this API (the blob hash).
    pub id: &'a str,
    /// The `Message-ID` header.
    pub message_id: Option<&'a str>,
    /// `References` ids, in header order.
    pub references: &'a [String],
    /// `In-Reply-To` ids.
    pub in_reply_to: &'a [String],
    /// The time it sorts by.
    pub sort_date: i64,
}

/// A container of the JWZ tree: a message, or a placeholder for a message that is referenced
/// but not here (`id` missing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Node {
    /// The message id in this API; absent for a placeholder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The `Message-ID` the container stands for; absent for a message without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Replies, oldest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Node>,
}

#[derive(Default)]
struct Container {
    message: Option<usize>,
    message_id: Option<String>,
    parent: Option<usize>,
    children: Vec<usize>,
}

fn is_ancestor(containers: &[Container], ancestor: usize, mut of: usize) -> bool {
    let mut steps = 0;
    loop {
        if of == ancestor {
            return true;
        }
        match containers[of].parent {
            Some(p) if steps <= containers.len() => {
                of = p;
                steps += 1;
            }
            _ => return false,
        }
    }
}

fn link(containers: &mut [Container], parent: usize, child: usize) {
    if parent == child || is_ancestor(containers, child, parent) {
        return;
    }
    if let Some(old) = containers[child].parent.take() {
        containers[old].children.retain(|c| *c != child);
    }
    containers[child].parent = Some(parent);
    containers[parent].children.push(child);
}

/// The JWZ container tree of a thread's messages (steps 1 to 4 of the algorithm; grouping by
/// subject is done when messages are threaded). Each message is linked under the last id of its
/// `References`, or else of its `In-Reply-To`, and consecutive `References` ids are linked to
/// each other unless already placed; links that would make a loop are skipped. Ids referenced
/// but not present become placeholders: one without children is dropped, one below another
/// container is replaced by its children, and a root one with a single child gives way to it.
/// Messages sharing a `Message-ID` are kept apart, the later one as if it had none. Siblings
/// and roots are ordered by the oldest message under them, then by id.
pub fn tree(messages: &[Link<'_>]) -> Vec<Node> {
    let mut containers: Vec<Container> = Vec::new();
    let mut by_id: HashMap<String, usize> = HashMap::new();
    let mut get = |containers: &mut Vec<Container>, id: &str| -> usize {
        *by_id.entry(id.to_owned()).or_insert_with(|| {
            containers.push(Container {
                message_id: Some(id.to_owned()),
                ..Container::default()
            });
            containers.len() - 1
        })
    };
    for (n, m) in messages.iter().enumerate() {
        let own = match m.message_id {
            Some(mid) => {
                let c = get(&mut containers, mid);
                if containers[c].message.is_none() {
                    c
                } else {
                    containers.push(Container::default());
                    containers.len() - 1
                }
            }
            None => {
                containers.push(Container::default());
                containers.len() - 1
            }
        };
        containers[own].message = Some(n);
        let chain: &[String] = if m.references.is_empty() {
            m.in_reply_to
                .last()
                .map(std::slice::from_ref)
                .unwrap_or(&[])
        } else {
            m.references
        };
        let ids: Vec<usize> = chain.iter().map(|id| get(&mut containers, id)).collect();
        for pair in ids.windows(2) {
            if containers[pair[1]].parent.is_none() {
                link(&mut containers, pair[0], pair[1]);
            }
        }
        if let Some(&parent) = ids.last() {
            link(&mut containers, parent, own);
        }
    }
    let mut keys: Vec<(i64, &str)> = vec![(i64::MAX, ""); containers.len()];
    for (c, container) in containers.iter().enumerate() {
        let Some(n) = container.message else {
            continue;
        };
        let key = (messages[n].sort_date, messages[n].id);
        let mut at = Some(c);
        let mut steps = 0;
        while let Some(x) = at.filter(|_| steps <= containers.len()) {
            if key < keys[x] {
                keys[x] = key;
            }
            at = containers[x].parent;
            steps += 1;
        }
    }
    fn build(
        containers: &[Container],
        messages: &[Link<'_>],
        keys: &[(i64, &str)],
        c: usize,
    ) -> Vec<Node> {
        let mut kids: Vec<usize> = containers[c].children.clone();
        kids.sort_by_key(|k| keys[*k]);
        let children: Vec<Node> = kids
            .into_iter()
            .flat_map(|k| build(containers, messages, keys, k))
            .collect();
        match containers[c].message {
            Some(n) => vec![Node {
                id: Some(messages[n].id.to_owned()),
                message_id: containers[c].message_id.clone(),
                children,
            }],
            None if containers[c].parent.is_some() => children,
            None if children.len() <= 1 => children,
            None => vec![Node {
                id: None,
                message_id: containers[c].message_id.clone(),
                children,
            }],
        }
    }
    let mut roots: Vec<usize> = (0..containers.len())
        .filter(|c| containers[*c].parent.is_none())
        .collect();
    roots.sort_by_key(|r| keys[*r]);
    roots
        .into_iter()
        .flat_map(|r| build(&containers, messages, &keys, r))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn shape(nodes: &[Node]) -> String {
        nodes
            .iter()
            .map(|n| {
                let name = n
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("[{}]", n.message_id.clone().unwrap_or_default()));
                if n.children.is_empty() {
                    name
                } else {
                    format!("{name}({})", shape(&n.children))
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn builds_the_reply_tree_with_placeholders() {
        let none: Vec<String> = Vec::new();
        let r_a = ids(&["root"]);
        let r_b = ids(&["root", "a"]);
        let r_c = ids(&["gone", "lost"]);
        let r_d = ids(&["gone"]);
        let r_e = ids(&["gone2"]);
        let r_f = ids(&["gone2"]);
        let r_loop = ids(&["loop"]);
        let msgs = [
            Link {
                id: "B",
                message_id: Some("b"),
                references: &r_b,
                in_reply_to: &none,
                sort_date: 3,
            },
            Link {
                id: "R",
                message_id: Some("root"),
                references: &none,
                in_reply_to: &none,
                sort_date: 1,
            },
            Link {
                id: "A",
                message_id: Some("a"),
                references: &r_a,
                in_reply_to: &none,
                sort_date: 2,
            },
            Link {
                id: "C",
                message_id: Some("c"),
                references: &r_c,
                in_reply_to: &none,
                sort_date: 4,
            },
            Link {
                id: "D",
                message_id: Some("d"),
                references: &r_d,
                in_reply_to: &none,
                sort_date: 5,
            },
            Link {
                id: "E",
                message_id: Some("e"),
                references: &none,
                in_reply_to: &r_e,
                sort_date: 6,
            },
            Link {
                id: "F",
                message_id: Some("f"),
                references: &r_f,
                in_reply_to: &none,
                sort_date: 7,
            },
            Link {
                id: "L",
                message_id: Some("loop"),
                references: &r_loop,
                in_reply_to: &none,
                sort_date: 8,
            },
            Link {
                id: "R2",
                message_id: Some("root"),
                references: &none,
                in_reply_to: &none,
                sort_date: 9,
            },
        ];
        assert_eq!(shape(&tree(&msgs)), "R(A(B)) [gone](C D) [gone2](E F) L R2");
    }

    #[test]
    fn a_lone_placeholder_root_gives_way_to_its_child() {
        let none: Vec<String> = Vec::new();
        let refs = ids(&["missing"]);
        let msgs = [Link {
            id: "X",
            message_id: None,
            references: &refs,
            in_reply_to: &none,
            sort_date: 1,
        }];
        let t = tree(&msgs);
        assert_eq!(shape(&t), "X");
        assert_eq!(t[0].message_id, None);
    }

    #[test]
    fn subject_keys_strip_prefixes() {
        assert_eq!(
            subject_key(Some("Re: Fwd: [garden] Lunch on Friday")).as_deref(),
            Some("lunch on friday")
        );
        assert_eq!(subject_key(Some("  ")), None);
        assert_eq!(subject_key(None), None);
        assert!(has_reply_prefix(Some("RE: x")));
        assert!(!has_reply_prefix(Some("x")));
    }
}
