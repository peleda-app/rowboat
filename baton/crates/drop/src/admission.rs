//! Who may create a box: an operator token, a proof of work, or anybody on an open service.
//!
//! The proof of work is hashcash over argon2id: find a nonce such that
//! `argon2id(password = label ‖ box id ‖ nonce, salt = operator salt)` starts with `difficulty`
//! zero bits. It is bound to one box and one operator, costs the client about `2^difficulty`
//! evaluations and the service one, which stays a few milliseconds and at most [`MAX_M_COST_KIB`]
//! of memory because the parameters are capped on both sides.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use baton_mailbox::BoxId;

use crate::ConfigError;

/// The highest difficulty a service may ask for and a client agrees to solve.
pub const MAX_DIFFICULTY: u8 = 24;
/// The most argon2 memory per evaluation, in KiB.
pub const MAX_M_COST_KIB: u32 = 4096;
/// The most argon2 passes per evaluation.
pub const MAX_T_COST: u32 = 3;
/// The shortest operator salt.
pub const MIN_SALT: usize = 16;
/// The longest operator salt.
pub const MAX_SALT: usize = 64;
/// The shortest operator token.
pub const MIN_TOKEN: usize = 16;

const LABEL: &[u8] = b"baton/drop/work/1";

/// The proof-of-work challenge an operator publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkParams {
    /// The operator's salt, [`MIN_SALT`] to [`MAX_SALT`] bytes.
    pub salt: Vec<u8>,
    /// Leading zero bits required, at most [`MAX_DIFFICULTY`].
    pub difficulty: u8,
    /// argon2id memory in KiB, 8 to [`MAX_M_COST_KIB`].
    pub m_cost_kib: u32,
    /// argon2id passes, 1 to [`MAX_T_COST`].
    pub t_cost: u32,
}

impl WorkParams {
    /// A challenge with a fresh random salt.
    pub fn generate(difficulty: u8, m_cost_kib: u32, t_cost: u32) -> Result<Self, ConfigError> {
        let mut salt = vec![0u8; 32];
        getrandom::fill(&mut salt).expect("the operating system provides randomness");
        let p = Self {
            salt,
            difficulty,
            m_cost_kib,
            t_cost,
        };
        if p.within_caps() {
            Ok(p)
        } else {
            Err(ConfigError("proof-of-work parameters out of range"))
        }
    }

    /// Whether every parameter is within the caps both sides enforce.
    pub fn within_caps(&self) -> bool {
        (MIN_SALT..=MAX_SALT).contains(&self.salt.len())
            && self.difficulty <= MAX_DIFFICULTY
            && (8..=MAX_M_COST_KIB).contains(&self.m_cost_kib)
            && (1..=MAX_T_COST).contains(&self.t_cost)
    }

    fn digest(&self, box_id: &BoxId, nonce: u64) -> Option<[u8; 32]> {
        if !self.within_caps() {
            return None;
        }
        let params = argon2::Params::new(self.m_cost_kib, self.t_cost, 1, Some(32)).ok()?;
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut pwd = Vec::with_capacity(LABEL.len() + 40);
        pwd.extend_from_slice(LABEL);
        pwd.extend_from_slice(box_id.as_bytes());
        pwd.extend_from_slice(&nonce.to_le_bytes());
        let mut out = [0u8; 32];
        a.hash_password_into(&pwd, &self.salt, &mut out).ok()?;
        Some(out)
    }

    /// Whether `nonce` is a valid proof for `box_id` under this challenge. One argon2id
    /// evaluation; false for parameters outside the caps.
    pub fn verify(&self, box_id: &BoxId, nonce: u64) -> bool {
        self.digest(box_id, nonce)
            .is_some_and(|d| leading_zero_bits(&d) >= u32::from(self.difficulty))
    }

    /// Finds a proof for `box_id`, about `2^difficulty` evaluations. Blocking: run it on a
    /// blocking thread. `None` for parameters outside the caps.
    pub fn solve(&self, box_id: &BoxId) -> Option<u64> {
        if !self.within_caps() {
            return None;
        }
        let mut start = [0u8; 8];
        getrandom::fill(&mut start).expect("the operating system provides randomness");
        let mut nonce = u64::from_le_bytes(start);
        loop {
            if self.verify(box_id, nonce) {
                return Some(nonce);
            }
            nonce = nonce.wrapping_add(1);
        }
    }
}

/// Leading zero bits of a digest.
pub fn leading_zero_bits(d: &[u8]) -> u32 {
    let mut n = 0;
    for b in d {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// What admits a box creation. A creation is admitted when the service is open, or it carries a
/// token the operator configured, or a valid proof of work. `Debug` never shows token hashes.
#[derive(Clone, Default)]
pub struct AdmissionConfig {
    open: bool,
    tokens: Vec<[u8; 32]>,
    work: Option<WorkParams>,
}

impl std::fmt::Debug for AdmissionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionConfig")
            .field("open", &self.open)
            .field("tokens", &self.tokens.len())
            .field("work", &self.work)
            .finish()
    }
}

impl AdmissionConfig {
    /// Admits nothing until a token or work is added.
    pub fn closed() -> Self {
        Self::default()
    }

    /// Admits every creation (for a private deployment behind other access control).
    pub fn open() -> Self {
        Self {
            open: true,
            ..Self::default()
        }
    }

    /// Also admits creations carrying `token` (at least [`MIN_TOKEN`] bytes). Only its hash is
    /// kept.
    pub fn with_token(mut self, token: &[u8]) -> Result<Self, ConfigError> {
        if token.len() < MIN_TOKEN || token.len() > crate::wire::MAX_TOKEN {
            return Err(ConfigError("operator token must be 16 to 256 bytes"));
        }
        self.tokens.push(*blake3::hash(token).as_bytes());
        Ok(self)
    }

    /// Also admits creations with a valid proof of work under `work`.
    pub fn with_work(mut self, work: WorkParams) -> Result<Self, ConfigError> {
        if !work.within_caps() {
            return Err(ConfigError("proof-of-work parameters out of range"));
        }
        self.work = Some(work);
        Ok(self)
    }

    /// Whether creations without admission are accepted.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Whether any token is configured.
    pub fn has_tokens(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// The proof-of-work challenge, if any.
    pub fn work(&self) -> Option<&WorkParams> {
        self.work.as_ref()
    }

    /// Whether `token` is one of the configured tokens. Compares hashes in constant time and
    /// always looks at every configured token.
    pub fn accepts_token(&self, token: &[u8]) -> bool {
        let h = blake3::hash(token);
        let mut ok = subtle::Choice::from(0);
        for t in &self.tokens {
            ok |= t.ct_eq(h.as_bytes());
        }
        bool::from(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn easy() -> WorkParams {
        WorkParams::generate(4, 64, 1).unwrap()
    }

    #[test]
    fn leading_zero_bits_counts() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x80]), 16);
        assert_eq!(leading_zero_bits(&[0, 0x01]), 15);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
    }

    #[test]
    fn a_proof_is_bound_to_box_salt_and_difficulty() {
        let w = easy();
        let id = BoxId([3; 32]);
        let n = w.solve(&id).unwrap();
        assert!(w.verify(&id, n));

        let mut other_salt = w.clone();
        other_salt.salt[0] ^= 1;
        let other_box = BoxId([4; 32]);
        let mut harder = w.clone();
        harder.difficulty = 20;
        let mut fails = [0usize; 3];
        for k in 0..64u64 {
            let n = w.solve(&BoxId([k as u8; 32])).unwrap();
            let id = BoxId([k as u8; 32]);
            fails[0] += usize::from(!other_salt.verify(&id, n));
            fails[1] += usize::from(!w.verify(&other_box, n) || id == other_box);
            fails[2] += usize::from(!harder.verify(&id, n));
        }
        assert!(
            fails[0] > 48,
            "a proof under another salt mostly fails: {fails:?}"
        );
        assert!(
            fails[1] > 48,
            "a proof for another box mostly fails: {fails:?}"
        );
        assert!(fails[2] > 60, "a harder challenge refuses: {fails:?}");
    }

    #[test]
    fn parameters_outside_caps_never_verify_or_solve() {
        let mut w = easy();
        w.m_cost_kib = MAX_M_COST_KIB + 1;
        assert!(!w.verify(&BoxId([0; 32]), 0));
        assert!(w.solve(&BoxId([0; 32])).is_none());
        assert!(WorkParams::generate(MAX_DIFFICULTY + 1, 64, 1).is_err());
        assert!(WorkParams::generate(1, 4, 1).is_err());
        assert!(WorkParams::generate(1, 64, 0).is_err());
        let mut short = easy();
        short.salt.truncate(MIN_SALT - 1);
        assert!(!short.within_caps());
    }

    #[test]
    fn difficulty_zero_accepts_any_nonce() {
        let w = WorkParams::generate(0, 8, 1).unwrap();
        assert!(w.verify(&BoxId([0; 32]), 12345));
    }

    #[test]
    fn verification_is_cheap_at_the_caps() {
        let w = WorkParams::generate(MAX_DIFFICULTY, MAX_M_COST_KIB, 1).unwrap();
        let started = std::time::Instant::now();
        for n in 0..4 {
            w.verify(&BoxId([1; 32]), n);
        }
        let each = started.elapsed() / 4;
        assert!(
            each < std::time::Duration::from_millis(250),
            "one verification took {each:?}"
        );
    }

    #[test]
    fn tokens_match_exactly_and_hide_in_debug() {
        let a = AdmissionConfig::closed()
            .with_token(b"operator-token-0001")
            .unwrap()
            .with_token(b"operator-token-0002")
            .unwrap();
        assert!(a.accepts_token(b"operator-token-0001"));
        assert!(a.accepts_token(b"operator-token-0002"));
        assert!(!a.accepts_token(b"operator-token-0003"));
        assert!(!a.accepts_token(b"operator-token-000"));
        assert!(!a.accepts_token(b""));
        assert!(!format!("{a:?}").contains("operator"));
        assert!(AdmissionConfig::closed().with_token(b"short").is_err());
        assert!(!AdmissionConfig::closed().accepts_token(b"anything-at-all-x"));
    }
}
