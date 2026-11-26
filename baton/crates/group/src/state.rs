use std::collections::{BTreeMap, BTreeSet};

use baton_core::{GroupId, ResourceId, Timestamp};
use baton_identity::PublicKey;
use baton_keys::{KemPublic, RecoveryPublic};
use baton_lease::NodeClass;

use crate::{
    Capability, Commitments, Entry, GroupError, KeyBox, NodeCert, Op, Principal, Recipient, Role,
};

/// How a reported head relates to a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadCheck {
    /// The same head.
    Same,
    /// An older head of the same log: a stale copy, or a rollback by whoever reported it.
    Behind,
    /// A head beyond this log: fetch the missing entries.
    Ahead,
    /// A different entry at a position this log has: the log forked.
    Fork,
}

#[derive(Debug, Clone)]
struct MemberState {
    role: Role,
    recovery: RecoveryPublic,
}

#[derive(Debug, Clone)]
struct NodeState {
    cert: NodeCert,
    revoked: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct EpochState {
    pub(crate) recipients: BTreeMap<Recipient, bool>,
    pub(crate) commitments: Commitments,
}

/// What the log says about one resource.
#[derive(Debug, Clone)]
pub struct ResourceState {
    creator: PublicKey,
    grants: BTreeMap<Principal, BTreeSet<Capability>>,
    pub(crate) epochs: Vec<EpochState>,
}

impl ResourceState {
    /// The current key epoch (0 before the first).
    pub fn epoch(&self) -> u64 {
        self.epochs.len() as u64
    }

    /// Who holds `epoch` and whether they got its secret key.
    pub fn recipients(&self, epoch: u64) -> Option<&BTreeMap<Recipient, bool>> {
        self.epoch_state(epoch).map(|e| &e.recipients)
    }

    pub(crate) fn epoch_state(&self, epoch: u64) -> Option<&EpochState> {
        epoch
            .checked_sub(1)
            .and_then(|i| self.epochs.get(i as usize))
    }

    /// The member that created the resource (its key after any rekey).
    pub fn creator(&self) -> &PublicKey {
        &self.creator
    }
}

/// The state a verified log produces.
#[derive(Debug, Clone)]
pub struct GroupState {
    pub(crate) group: GroupId,
    members: BTreeMap<PublicKey, MemberState>,
    removed: BTreeSet<PublicKey>,
    nodes: BTreeMap<PublicKey, NodeState>,
    group_recovery: RecoveryPublic,
    resources: BTreeMap<ResourceId, ResourceState>,
    checkpoint: Option<u64>,
    used_keys: BTreeSet<PublicKey>,
    used_kems: BTreeSet<Vec<u8>>,
    last_at: Timestamp,
}

enum Signer {
    Node {
        node: PublicKey,
        member: PublicKey,
        role: Role,
    },
    GroupRecovery,
    MemberRecovery(PublicKey),
}

fn valid_class(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn reads(caps: &BTreeSet<Capability>) -> bool {
    caps.contains(&Capability::Read) || caps.contains(&Capability::Lead)
}

impl GroupState {
    pub(crate) fn from_genesis(entry: &Entry) -> Result<Self, GroupError> {
        let Op::Genesis {
            owner,
            owner_recovery,
            group_recovery,
            founder,
        } = entry.op()
        else {
            return Err(GroupError::Chain);
        };
        if entry.seq() != 0 || entry.body.prev != [0; 32] || entry.body.v != crate::ENTRY_VERSION {
            return Err(GroupError::Chain);
        }
        founder.verify()?;
        owner_recovery
            .verify()
            .map_err(|_| GroupError::BadSignature)?;
        group_recovery
            .verify()
            .map_err(|_| GroupError::BadSignature)?;
        if &founder.member != owner
            || entry.signer() != &founder.node
            || founder.expires < entry.at()
        {
            return Err(GroupError::NotAuthorized(
                "the founder node must be the owner's and sign genesis",
            ));
        }
        let keys = [
            *owner,
            founder.node,
            owner_recovery.sign,
            group_recovery.sign,
        ];
        let distinct: BTreeSet<_> = keys.iter().collect();
        if distinct.len() != keys.len() || owner_recovery.kem == group_recovery.kem {
            return Err(GroupError::Invalid("every key of genesis is distinct"));
        }
        let mut members = BTreeMap::new();
        members.insert(
            *owner,
            MemberState {
                role: Role::Owner,
                recovery: owner_recovery.clone(),
            },
        );
        let mut nodes = BTreeMap::new();
        nodes.insert(
            founder.node,
            NodeState {
                cert: founder.clone(),
                revoked: false,
            },
        );
        Ok(Self {
            group: entry.group().clone(),
            members,
            removed: BTreeSet::new(),
            nodes,
            group_recovery: group_recovery.clone(),
            resources: BTreeMap::new(),
            checkpoint: None,
            used_keys: keys.into_iter().collect(),
            used_kems: [
                owner_recovery.kem.as_bytes().to_vec(),
                group_recovery.kem.as_bytes().to_vec(),
            ]
            .into(),
            last_at: entry.at(),
        })
    }

    /// The group.
    pub fn group(&self) -> &GroupId {
        &self.group
    }

    /// The latest entry time seen; entry times never go back.
    pub fn last_at(&self) -> Timestamp {
        self.last_at
    }

    /// A member's role, if the member is in the group.
    pub fn role(&self, member: &PublicKey) -> Option<Role> {
        self.members.get(member).map(|m| m.role)
    }

    /// Every member and their role.
    pub fn members(&self) -> impl Iterator<Item = (&PublicKey, Role)> {
        self.members.iter().map(|(k, m)| (k, m.role))
    }

    /// A member's recovery key.
    pub fn member_recovery(&self, member: &PublicKey) -> Option<&RecoveryPublic> {
        self.members.get(member).map(|m| &m.recovery)
    }

    /// The group's recovery key.
    pub fn group_recovery(&self) -> &RecoveryPublic {
        &self.group_recovery
    }

    /// The certificate of a node that counts now: certified, not revoked, its member still in
    /// the group, and not expired at `at`.
    pub fn node(&self, node: &PublicKey, at: Timestamp) -> Option<&NodeCert> {
        self.nodes
            .get(node)
            .filter(|n| {
                !n.revoked && n.cert.expires >= at && self.members.contains_key(&n.cert.member)
            })
            .map(|n| &n.cert)
    }

    /// Every node that counts at `at`.
    pub fn nodes(&self, at: Timestamp) -> Vec<&NodeCert> {
        self.nodes.keys().filter_map(|k| self.node(k, at)).collect()
    }

    /// Whether a node key was ever certified in this log (revoked, expired or of a removed member
    /// included).
    pub fn was_certified(&self, node: &PublicKey) -> bool {
        self.nodes.contains_key(node)
    }

    /// Whether a node key was ever revoked.
    pub fn is_revoked(&self, node: &PublicKey) -> bool {
        self.nodes.get(node).is_some_and(|n| n.revoked)
    }

    /// A resource, if it exists.
    pub fn resource(&self, resource: &ResourceId) -> Option<&ResourceState> {
        self.resources.get(resource)
    }

    /// The last entry a recovery key vouched for, if any.
    pub fn checkpoint(&self) -> Option<u64> {
        self.checkpoint
    }

    /// What `node` may do with `resource` at `at`: the grants to its member and to itself, if the
    /// node counts. Blind nodes may do nothing, whatever the grants say.
    pub fn capabilities(
        &self,
        resource: &ResourceId,
        node: &PublicKey,
        at: Timestamp,
    ) -> BTreeSet<Capability> {
        let (Some(cert), Some(r)) = (self.node(node, at), self.resources.get(resource)) else {
            return BTreeSet::new();
        };
        if cert.class == NodeClass::Blind {
            return BTreeSet::new();
        }
        let mut caps = r
            .grants
            .get(&Principal::Member(cert.member))
            .cloned()
            .unwrap_or_default();
        caps.extend(
            r.grants
                .get(&Principal::Node(*node))
                .cloned()
                .unwrap_or_default(),
        );
        caps
    }

    /// Whether `node` holds `capability` on `resource` at `at`.
    pub fn may(
        &self,
        node: &PublicKey,
        resource: &ResourceId,
        capability: &Capability,
        at: Timestamp,
    ) -> bool {
        self.capabilities(resource, node, at).contains(capability)
    }

    /// Exactly who must hold the keys of `resource` now, with their KEM key and whether they get
    /// the secret key: every counting, non-blind node with `Read` or `Lead` (the secret key only
    /// with `Lead`); the recovery key of every member involved (the secret key only if that member
    /// or one of its nodes may lead); and, for a shared resource (more than one member involved),
    /// the group's recovery key with both keys.
    pub fn required_recipients(
        &self,
        resource: &ResourceId,
        at: Timestamp,
    ) -> BTreeMap<Recipient, (KemPublic, bool)> {
        let mut out = BTreeMap::new();
        let Some(r) = self.resources.get(resource) else {
            return out;
        };
        let mut members: BTreeMap<PublicKey, bool> = BTreeMap::new();
        for cert in self.nodes(at) {
            let caps = self.capabilities(resource, &cert.node, at);
            if reads(&caps) {
                let lead = caps.contains(&Capability::Lead);
                out.insert(Recipient::Node(cert.node), (cert.kem.clone(), lead));
                *members.entry(cert.member).or_default() |= lead;
            }
        }
        for (p, caps) in &r.grants {
            if let Principal::Member(m) = p
                && reads(caps)
                && self.members.contains_key(m)
            {
                *members.entry(*m).or_default() |= caps.contains(&Capability::Lead);
            }
        }
        let shared = members.len() > 1;
        for (m, lead) in members {
            let rec = &self.members[&m].recovery;
            out.insert(Recipient::Recovery(rec.sign), (rec.kem.clone(), lead));
        }
        if shared {
            out.insert(
                Recipient::Recovery(self.group_recovery.sign),
                (self.group_recovery.kem.clone(), true),
            );
        }
        out
    }

    /// Whether someone holding the current epoch's keys is no longer allowed to, or holds its
    /// secret key without being allowed to lead, so a new epoch must start.
    pub fn needs_rotation(&self, resource: &ResourceId, at: Timestamp) -> bool {
        let Some(current) = self.resources.get(resource).and_then(|r| r.epochs.last()) else {
            return false;
        };
        let required = self.required_recipients(resource, at);
        current
            .recipients
            .iter()
            .any(|(r, got_secret)| match required.get(r) {
                None => true,
                Some((_, lead)) => *got_secret && !lead,
            })
    }

    fn signer(&self, key: &PublicKey, at: Timestamp) -> Option<Signer> {
        if let Some(cert) = self.node(key, at) {
            let role = self.members[&cert.member].role;
            return Some(Signer::Node {
                node: *key,
                member: cert.member,
                role,
            });
        }
        if key == &self.group_recovery.sign {
            return Some(Signer::GroupRecovery);
        }
        self.members
            .iter()
            .find(|(_, m)| &m.recovery.sign == key)
            .map(|(k, _)| Signer::MemberRecovery(*k))
    }

    fn fresh_key(&self, key: &PublicKey) -> Result<(), GroupError> {
        if self.used_keys.contains(key) {
            Err(GroupError::Invalid(
                "a key is used once, in one role, for the life of the group",
            ))
        } else {
            Ok(())
        }
    }

    fn fresh_recovery(&self, recovery: &RecoveryPublic) -> Result<(), GroupError> {
        recovery.verify().map_err(|_| GroupError::BadSignature)?;
        self.fresh_key(&recovery.sign)?;
        if self.used_kems.contains(recovery.kem.as_bytes()) {
            return Err(GroupError::Invalid("a recovery KEM key is used once"));
        }
        Ok(())
    }

    fn remember_recovery(&mut self, recovery: &RecoveryPublic) {
        self.used_keys.insert(recovery.sign);
        self.used_kems.insert(recovery.kem.as_bytes().to_vec());
    }

    fn owner_of(&self, principal: &Principal, at: Timestamp) -> Option<PublicKey> {
        match principal {
            Principal::Member(m) => self.members.contains_key(m).then_some(*m),
            Principal::Node(n) => self.node(n, at).map(|c| c.member),
        }
    }

    fn check_boxes(
        &self,
        boxes: &[KeyBox],
        allowed: &BTreeMap<Recipient, (KemPublic, bool)>,
        exact: bool,
    ) -> Result<BTreeMap<Recipient, bool>, GroupError> {
        let mut seen = BTreeMap::new();
        for b in boxes {
            let Some((_, lead)) = allowed.get(&b.recipient) else {
                return Err(GroupError::Invalid(
                    "a key box for someone not allowed to hold the keys",
                ));
            };
            if seen.insert(b.recipient, *lead).is_some() {
                return Err(GroupError::Invalid("a recipient boxed twice"));
            }
            if b.secret.is_some() != *lead {
                return Err(GroupError::Invalid(
                    "the secret key goes exactly to those who may lead",
                ));
            }
        }
        if exact && seen.len() != allowed.len() {
            return Err(GroupError::Invalid(
                "a new epoch must be sealed to every authorized recipient",
            ));
        }
        Ok(seen)
    }

    /// Checks `entry` against this state and, only if every check passes, applies it. Nothing
    /// changes when it fails.
    pub(crate) fn apply(&mut self, entry: &Entry) -> Result<(), GroupError> {
        let at = entry.at();
        if at < self.last_at {
            return Err(GroupError::Invalid("entry times never go back"));
        }
        let signer = self
            .signer(entry.signer(), at)
            .ok_or(GroupError::NotAuthorized(
                "the signer is neither a node that counts nor a recovery key",
            ))?;
        self.check_and_apply(entry, at, signer)?;
        self.last_at = at;
        Ok(())
    }

    fn check_and_apply(
        &mut self,
        entry: &Entry,
        at: Timestamp,
        signer: Signer,
    ) -> Result<(), GroupError> {
        match entry.op() {
            Op::Genesis { .. } => Err(GroupError::Chain),
            Op::AddMember {
                member,
                recovery,
                role,
            } => {
                let Signer::Node { role: by, .. } = signer else {
                    return Err(GroupError::NotAuthorized("members are added from a node"));
                };
                let allowed = match role {
                    Role::Member => by >= Role::Admin,
                    Role::Admin | Role::Owner => by == Role::Owner,
                };
                if !allowed {
                    return Err(GroupError::NotAuthorized(
                        "admins add members; only owners add admins and owners",
                    ));
                }
                self.fresh_key(member)?;
                self.fresh_recovery(recovery)?;
                if &recovery.sign == member {
                    return Err(GroupError::Invalid(
                        "the member key and the recovery key differ",
                    ));
                }
                self.used_keys.insert(*member);
                self.remember_recovery(recovery);
                self.members.insert(
                    *member,
                    MemberState {
                        role: *role,
                        recovery: recovery.clone(),
                    },
                );
                Ok(())
            }
            Op::RemoveMember { member } => {
                let target = self
                    .members
                    .get(member)
                    .ok_or(GroupError::Invalid("not a member"))?
                    .role;
                let allowed = match signer {
                    Signer::Node { member: m, .. } if &m == member => true,
                    Signer::Node { role, .. } => {
                        role == Role::Owner || (role == Role::Admin && target == Role::Member)
                    }
                    Signer::MemberRecovery(m) => &m == member,
                    Signer::GroupRecovery => true,
                };
                if !allowed {
                    return Err(GroupError::NotAuthorized("removing this member"));
                }
                if target == Role::Owner
                    && self
                        .members
                        .values()
                        .filter(|m| m.role == Role::Owner)
                        .count()
                        == 1
                {
                    return Err(GroupError::Invalid("the last owner cannot be removed"));
                }
                self.members.remove(member);
                self.removed.insert(*member);
                Ok(())
            }
            Op::RekeyMember { member, new_key } => {
                if !matches!(signer, Signer::MemberRecovery(m) if &m == member) {
                    return Err(GroupError::NotAuthorized(
                        "a member key is replaced only by that member's recovery key",
                    ));
                }
                self.fresh_key(new_key)?;
                let state = self
                    .members
                    .remove(member)
                    .ok_or(GroupError::Invalid("not a member"))?;
                self.used_keys.insert(*new_key);
                self.members.insert(*new_key, state);
                self.removed.insert(*member);
                for r in self.resources.values_mut() {
                    if let Some(caps) = r.grants.remove(&Principal::Member(*member)) {
                        r.grants.insert(Principal::Member(*new_key), caps);
                    }
                    if &r.creator == member {
                        r.creator = *new_key;
                    }
                }
                Ok(())
            }
            Op::CertifyNode { cert } => {
                cert.verify()?;
                let target = self
                    .members
                    .get(&cert.member)
                    .ok_or(GroupError::Invalid("the node's member is not in the group"))?
                    .role;
                self.fresh_key(&cert.node)?;
                if cert.expires < at {
                    return Err(GroupError::Invalid("the certificate has expired"));
                }
                let allowed = match signer {
                    Signer::Node { member, role, .. } => {
                        member == cert.member
                            || role == Role::Owner
                            || (role == Role::Admin && target == Role::Member)
                    }
                    Signer::MemberRecovery(m) => m == cert.member,
                    Signer::GroupRecovery => true,
                };
                if !allowed {
                    return Err(GroupError::NotAuthorized(
                        "certifying a node for another member",
                    ));
                }
                self.used_keys.insert(cert.node);
                self.nodes.insert(
                    cert.node,
                    NodeState {
                        cert: cert.clone(),
                        revoked: false,
                    },
                );
                Ok(())
            }
            Op::RevokeNode { node } => {
                let target = self
                    .nodes
                    .get(node)
                    .filter(|n| !n.revoked)
                    .ok_or(GroupError::Invalid("not a node"))?;
                let owner = target.cert.member;
                let owner_role = self.members.get(&owner).map(|m| m.role);
                let allowed = match signer {
                    Signer::Node { member, role, .. } => {
                        member == owner
                            || role == Role::Owner
                            || (role == Role::Admin && owner_role.is_none_or(|r| r == Role::Member))
                    }
                    Signer::MemberRecovery(m) => m == owner,
                    Signer::GroupRecovery => true,
                };
                if !allowed {
                    return Err(GroupError::NotAuthorized("revoking this node"));
                }
                self.nodes.get_mut(node).expect("checked").revoked = true;
                Ok(())
            }
            Op::CreateResource { resource } => {
                let Signer::Node { node, member, .. } = signer else {
                    return Err(GroupError::NotAuthorized(
                        "resources are created from a node",
                    ));
                };
                if self
                    .node(&node, at)
                    .is_some_and(|c| c.class == NodeClass::Blind)
                {
                    return Err(GroupError::NotAuthorized("a blind node creates nothing"));
                }
                if self.resources.contains_key(resource) {
                    return Err(GroupError::Invalid("the resource exists"));
                }
                let mut grants = BTreeMap::new();
                grants.insert(
                    Principal::Member(member),
                    BTreeSet::from([Capability::Read, Capability::Lead, Capability::Admin]),
                );
                self.resources.insert(
                    resource.clone(),
                    ResourceState {
                        creator: member,
                        grants,
                        epochs: Vec::new(),
                    },
                );
                Ok(())
            }
            Op::Grant {
                resource,
                principal,
                capabilities,
            } => {
                let r = self
                    .resources
                    .get(resource)
                    .ok_or(GroupError::Invalid("no such resource"))?;
                let Signer::Node { node, member, .. } = signer else {
                    return Err(GroupError::NotAuthorized("grants are made from a node"));
                };
                if !self.may(&node, resource, &Capability::Admin, at) {
                    return Err(GroupError::NotAuthorized(
                        "granting needs admin on the resource",
                    ));
                }
                let target = self
                    .owner_of(principal, at)
                    .ok_or(GroupError::Invalid("the principal is not in the group"))?;
                if target == member && r.creator != member {
                    return Err(GroupError::NotAuthorized(
                        "only the creator changes its own member's grants",
                    ));
                }
                if let Principal::Node(n) = principal
                    && self
                        .node(n, at)
                        .is_some_and(|c| c.class == NodeClass::Blind)
                {
                    return Err(GroupError::Invalid("a blind node holds no capability"));
                }
                for c in capabilities {
                    if let Capability::Command(name) = c {
                        if !valid_class(name) {
                            return Err(GroupError::Invalid(
                                "a command class is 1-32 bytes of a-z, 0-9, '_' and '-'",
                            ));
                        }
                        if !capabilities.contains(&Capability::Read) {
                            return Err(GroupError::Invalid("commands need read"));
                        }
                    }
                }
                let r = self.resources.get_mut(resource).expect("checked");
                if capabilities.is_empty() {
                    r.grants.remove(principal);
                } else {
                    r.grants.insert(*principal, capabilities.clone());
                }
                Ok(())
            }
            Op::KeyEpoch {
                resource,
                epoch,
                commitments,
                boxes,
            } => {
                let r = self
                    .resources
                    .get(resource)
                    .ok_or(GroupError::Invalid("no such resource"))?;
                let may = match &signer {
                    Signer::Node { node, .. } => {
                        self.may(node, resource, &Capability::Admin, at)
                            || self.may(node, resource, &Capability::Lead, at)
                    }
                    _ => false,
                };
                if !may {
                    return Err(GroupError::NotAuthorized(
                        "a new epoch needs admin or lead on the resource",
                    ));
                }
                if *epoch != r.epoch() + 1 {
                    return Err(GroupError::Invalid("epochs follow each other"));
                }
                let required = self.required_recipients(resource, at);
                let recipients = self.check_boxes(boxes, &required, true)?;
                self.resources
                    .get_mut(resource)
                    .expect("checked")
                    .epochs
                    .push(EpochState {
                        recipients,
                        commitments: commitments.clone(),
                    });
                Ok(())
            }
            Op::ShareEpoch {
                resource,
                epoch,
                boxes,
            } => {
                let r = self
                    .resources
                    .get(resource)
                    .ok_or(GroupError::Invalid("no such resource"))?;
                if r.epoch_state(*epoch).is_none() {
                    return Err(GroupError::Invalid("no such epoch"));
                }
                let Signer::Node { node, .. } = signer else {
                    return Err(GroupError::NotAuthorized("epochs are shared from a node"));
                };
                if !self.may(&node, resource, &Capability::Read, at) {
                    return Err(GroupError::NotAuthorized(
                        "sharing an epoch needs read on the resource",
                    ));
                }
                let holds_secret = self.may(&node, resource, &Capability::Lead, at)
                    || self.may(&node, resource, &Capability::Admin, at);
                if boxes.iter().any(|b| b.secret.is_some()) && !holds_secret {
                    return Err(GroupError::NotAuthorized(
                        "only nodes that may lead share the secret key",
                    ));
                }
                if boxes.is_empty() {
                    return Err(GroupError::Invalid("nothing to share"));
                }
                let required = self.required_recipients(resource, at);
                let added = self.check_boxes(boxes, &required, false)?;
                let e = &mut self.resources.get_mut(resource).expect("checked").epochs
                    [(*epoch - 1) as usize];
                for (rcpt, secret) in added {
                    let got = e.recipients.entry(rcpt).or_insert(false);
                    *got |= secret;
                }
                Ok(())
            }
            Op::Checkpoint => {
                if !matches!(signer, Signer::GroupRecovery) {
                    return Err(GroupError::NotAuthorized(
                        "checkpoints are signed by the group's recovery key",
                    ));
                }
                self.checkpoint = Some(entry.seq());
                Ok(())
            }
            Op::RotateRecovery { member, recovery } => {
                self.fresh_recovery(recovery)?;
                match member {
                    Some(m) => {
                        if !matches!(signer, Signer::MemberRecovery(by) if &by == m) {
                            return Err(GroupError::NotAuthorized(
                                "a member's recovery key is rotated only by that key",
                            ));
                        }
                        self.members
                            .get_mut(m)
                            .ok_or(GroupError::Invalid("not a member"))?
                            .recovery = recovery.clone();
                    }
                    None => {
                        if !matches!(signer, Signer::GroupRecovery) {
                            return Err(GroupError::NotAuthorized(
                                "the group's recovery key is rotated only by that key",
                            ));
                        }
                        self.group_recovery = recovery.clone();
                    }
                }
                self.remember_recovery(recovery);
                Ok(())
            }
        }
    }
}
