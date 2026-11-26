//! Resource key epochs: generating keys and sealing them to exactly the recipients the log
//! authorizes, sharing an epoch with a newly authorized device, and opening one's own box.

use std::collections::BTreeMap;

use baton_core::{ResourceId, Timestamp};
use baton_keys::{KemPublic, KemSecret, open_box, seal_box};
use baton_seal::Key;

use crate::{Commitments, GroupError, GroupLog, GroupState, KeyBox, Op, Recipient};

/// The keys of one resource epoch.
pub struct ResourceKeys {
    /// Seals the resource's data.
    pub data: Key,
    /// Seals the resource's secrets; `None` when the opener may not lead.
    pub secret: Option<Key>,
}

impl std::fmt::Debug for ResourceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResourceKeys(<redacted>)")
    }
}

fn aad(
    state: &GroupState,
    resource: &ResourceId,
    epoch: u64,
    recipient: &Recipient,
    which: &str,
) -> Vec<u8> {
    let mut out = b"baton-epoch/v1\0".to_vec();
    out.extend(state.group().as_str().as_bytes());
    out.push(0);
    out.extend(resource.as_str().as_bytes());
    out.push(0);
    out.extend(epoch.to_be_bytes());
    out.extend(postcard::to_stdvec(recipient).expect("a recipient serializes"));
    out.extend(which.as_bytes());
    out
}

fn backend(e: impl std::fmt::Display) -> GroupError {
    GroupError::Backend(e.to_string())
}

fn boxes_for(
    state: &GroupState,
    resource: &ResourceId,
    epoch: u64,
    keys: &ResourceKeys,
    recipients: &BTreeMap<Recipient, (KemPublic, bool)>,
) -> Result<Vec<KeyBox>, GroupError> {
    recipients
        .iter()
        .map(|(r, (kem, lead))| {
            let data = seal_box(
                kem,
                &aad(state, resource, epoch, r, "data"),
                keys.data.expose(),
            )
            .map_err(backend)?;
            let secret = match (lead, &keys.secret) {
                (true, Some(s)) => Some(
                    seal_box(kem, &aad(state, resource, epoch, r, "secret"), s.expose())
                        .map_err(backend)?,
                ),
                (true, None) => {
                    return Err(GroupError::Invalid(
                        "the secret key is needed to share with someone who may lead",
                    ));
                }
                (false, _) => None,
            };
            Ok(KeyBox {
                recipient: *r,
                data,
                secret,
            })
        })
        .collect()
}

/// A new epoch of `resource` with fresh keys, sealed to exactly the recipients authorized at
/// `at`. Append the returned op to the log; keep the keys.
pub fn new_epoch(
    state: &GroupState,
    resource: &ResourceId,
    at: Timestamp,
) -> Result<(Op, ResourceKeys), GroupError> {
    let r = state
        .resource(resource)
        .ok_or(GroupError::Invalid("no such resource"))?;
    let epoch = r.epoch() + 1;
    let keys = ResourceKeys {
        data: Key::generate().map_err(backend)?,
        secret: Some(Key::generate().map_err(backend)?),
    };
    let required = state.required_recipients(resource, at);
    let boxes = boxes_for(state, resource, epoch, &keys, &required)?;
    let commitments = Commitments::of(
        keys.data.expose(),
        keys.secret.as_ref().expect("generated").expose(),
    );
    Ok((
        Op::KeyEpoch {
            resource: resource.clone(),
            epoch,
            commitments,
            boxes,
        },
        keys,
    ))
}

fn matches(c: &Commitments, data: &[u8; 32], secret: Option<&[u8; 32]>) -> bool {
    let d = Commitments::of(data, &[0; 32]).data;
    d == c.data && secret.is_none_or(|s| Commitments::of(&[0; 32], s).secret == c.secret)
}

/// Boxes of `epoch` for the recipients authorized at `at` that do not hold it yet (a member's new
/// device), or `None` when nobody is missing. Without `keys.secret`, only recipients that may not
/// lead are served. Keys that do not match the epoch's commitments are refused.
pub fn share_epoch(
    state: &GroupState,
    resource: &ResourceId,
    epoch: u64,
    keys: &ResourceKeys,
    at: Timestamp,
) -> Result<Option<Op>, GroupError> {
    let r = state
        .resource(resource)
        .ok_or(GroupError::Invalid("no such resource"))?;
    let e = r
        .epoch_state(epoch)
        .ok_or(GroupError::Invalid("no such epoch"))?;
    if !matches(
        &e.commitments,
        keys.data.expose(),
        keys.secret.as_ref().map(|k| k.expose()),
    ) {
        return Err(GroupError::Invalid("these are not the epoch's keys"));
    }
    let missing: BTreeMap<_, _> = state
        .required_recipients(resource, at)
        .into_iter()
        .filter(|(k, (_, lead))| !e.recipients.contains_key(k) && (keys.secret.is_some() || !lead))
        .collect();
    if missing.is_empty() {
        return Ok(None);
    }
    let boxes = boxes_for(state, resource, epoch, keys, &missing)?;
    Ok(Some(Op::ShareEpoch {
        resource: resource.clone(),
        epoch,
        boxes,
    }))
}

/// Opens `recipient`'s box of `epoch` with its KEM key, searching the log from the newest entry.
/// A box whose keys do not match the epoch's commitments is skipped, so a forged box shared by
/// someone else never shadows a genuine one.
pub fn open(
    log: &GroupLog,
    resource: &ResourceId,
    epoch: u64,
    recipient: &Recipient,
    kem: &KemSecret,
) -> Result<ResourceKeys, GroupError> {
    let state = log.state();
    let e = state
        .resource(resource)
        .and_then(|r| r.epoch_state(epoch))
        .ok_or(GroupError::Invalid("no such epoch"))?;
    for entry in log.entries().iter().rev() {
        let (Op::KeyEpoch {
            resource: r,
            epoch: n,
            boxes,
            ..
        }
        | Op::ShareEpoch {
            resource: r,
            epoch: n,
            boxes,
        }) = entry.op()
        else {
            continue;
        };
        if r != resource || *n != epoch {
            continue;
        }
        for b in boxes.iter().filter(|b| &b.recipient == recipient) {
            let Ok(data) = open_box(
                kem,
                &aad(state, resource, epoch, recipient, "data"),
                &b.data,
            ) else {
                continue;
            };
            let secret = match &b.secret {
                Some(s) => {
                    match open_box(kem, &aad(state, resource, epoch, recipient, "secret"), s) {
                        Ok(v) => Some(v),
                        Err(_) => continue,
                    }
                }
                None => None,
            };
            let (Ok(data), secret) = (Key::from_slice(&data), secret.map(|s| Key::from_slice(&s)))
            else {
                continue;
            };
            let secret = match secret {
                Some(Ok(k)) => Some(k),
                Some(Err(_)) => continue,
                None => None,
            };
            if matches(
                &e.commitments,
                data.expose(),
                secret.as_ref().map(|k| k.expose()),
            ) {
                return Ok(ResourceKeys { data, secret });
            }
        }
    }
    Err(GroupError::Invalid("no genuine key box for this recipient"))
}
