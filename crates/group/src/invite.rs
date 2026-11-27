//! What an invite looks like outside the node: the QR payload, the short code and the pairing
//! address a server prints. Every decoder here reads text a person scanned or typed, so each caps
//! its input, never panics and has a fuzz target.

use std::fmt;
use std::net::SocketAddr;

use baton_core::{GroupId, Timestamp};
use baton_identity::PublicKey;
use baton_link::{PeerHint, RelayUrl};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::MembershipError;

/// The prefix of a QR payload. It names no host, so a camera app that opens it sends nothing.
pub const QR_PREFIX: &str = "peleda-pair:";
/// The prefix of a pairing address.
pub const ADDRESS_PREFIX: &str = "peleda-addr:";
/// The longest QR payload or pairing address accepted, in characters.
pub const MAX_CODE_TEXT: usize = 2048;
/// The most direct addresses a hint carries.
pub const MAX_HINT_ADDRS: usize = 8;
/// The invite format version.
pub const INVITE_VERSION: u8 = 1;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// What an invite asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InviteKind {
    /// A member device invites a new device into its group; the device that scans it joins.
    Device,
    /// A server asks to be adopted; the member device that scans or types it certifies the
    /// server into its own group.
    Server,
}

/// Where an endpoint can be reached, in a form that travels in invites and pairing messages.
///
/// Guarantees: at most [`MAX_HINT_ADDRS`] direct addresses and a relay that passes
/// [`RelayUrl::new`]; [`WireHint::check`] refuses anything else.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireHint {
    /// Direct socket addresses.
    pub direct: Vec<SocketAddr>,
    /// A relay URL.
    pub relay: Option<String>,
}

impl WireHint {
    /// The hint of an endpoint, trimmed to [`MAX_HINT_ADDRS`] direct addresses.
    pub fn from_peer(hint: &PeerHint) -> Self {
        Self {
            direct: hint.direct.iter().take(MAX_HINT_ADDRS).copied().collect(),
            relay: hint.relay.as_ref().map(|r| r.as_str().to_owned()),
        }
    }

    /// Checks the caps and the relay URL.
    pub fn check(&self) -> Result<(), MembershipError> {
        if self.direct.len() > MAX_HINT_ADDRS {
            return Err(MembershipError::Malformed);
        }
        if let Some(r) = &self.relay {
            RelayUrl::new(r).map_err(|_| MembershipError::Malformed)?;
        }
        Ok(())
    }

    /// The hint for a link.
    pub fn to_peer(&self) -> Result<PeerHint, MembershipError> {
        self.check()?;
        Ok(PeerHint {
            direct: self.direct.clone(),
            relay: self
                .relay
                .as_deref()
                .map(RelayUrl::new)
                .transpose()
                .map_err(|_| MembershipError::Malformed)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct QrBody {
    v: u8,
    kind: InviteKind,
    group: Option<GroupId>,
    inviter: Option<PublicKey>,
    id: u64,
    secret: [u8; 16],
    endpoint: PublicKey,
    hint: WireHint,
    expires_at: Timestamp,
}

impl Drop for QrBody {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// An invite as the QR code carries it. Whoever holds it can try to pair once, so the fingerprint
/// confirmation still decides; `Debug` never shows the secret.
///
/// Guarantees of [`Invite::from_qr`]: version [`INVITE_VERSION`]; a device invite names its group
/// and the inviting node, a server invite names neither; the hint passes [`WireHint::check`].
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    /// What it asks for.
    pub kind: InviteKind,
    /// The group to join (device invites only).
    pub group: Option<GroupId>,
    /// The node that will certify the joiner (device invites only).
    pub inviter: Option<PublicKey>,
    /// The invite's public number.
    pub id: u64,
    secret: [u8; 16],
    /// The pairing endpoint's key.
    pub endpoint: PublicKey,
    /// Where the pairing endpoint listens.
    pub hint: WireHint,
    /// After this moment the inviter refuses it.
    pub expires_at: Timestamp,
}

impl Invite {
    /// Assembles an invite; used by the inviting side.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: InviteKind,
        group: Option<GroupId>,
        inviter: Option<PublicKey>,
        id: u64,
        secret: [u8; 16],
        endpoint: PublicKey,
        hint: WireHint,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            kind,
            group,
            inviter,
            id,
            secret,
            endpoint,
            hint,
            expires_at,
        }
    }

    pub(crate) fn secret(&self) -> &[u8; 16] {
        &self.secret
    }

    /// The QR payload: [`QR_PREFIX`] and the invite in unpadded base32.
    pub fn to_qr(&self) -> String {
        let body = QrBody {
            v: INVITE_VERSION,
            kind: self.kind,
            group: self.group.clone(),
            inviter: self.inviter,
            id: self.id,
            secret: self.secret,
            endpoint: self.endpoint,
            hint: self.hint.clone(),
            expires_at: self.expires_at,
        };
        let mut bytes = postcard::to_stdvec(&body).expect("an invite serializes");
        let text = format!("{QR_PREFIX}{}", BASE32_NOPAD.encode(&bytes));
        bytes.zeroize();
        text
    }

    /// Parses a QR payload (the prefix in any case).
    pub fn from_qr(text: &str) -> Result<Self, MembershipError> {
        let payload = strip_prefix(text, QR_PREFIX)?;
        let mut bytes = decode_base32(payload)?;
        let parsed = postcard::from_bytes::<QrBody>(&bytes);
        bytes.zeroize();
        let body = parsed.map_err(|_| MembershipError::Malformed)?;
        let shape = match body.kind {
            InviteKind::Device => body.group.is_some() && body.inviter.is_some(),
            InviteKind::Server => body.group.is_none() && body.inviter.is_none(),
        };
        if body.v != INVITE_VERSION || !shape {
            return Err(MembershipError::Malformed);
        }
        body.hint.check()?;
        Ok(Self {
            kind: body.kind,
            group: body.group.clone(),
            inviter: body.inviter,
            id: body.id,
            secret: body.secret,
            endpoint: body.endpoint,
            hint: body.hint.clone(),
            expires_at: body.expires_at,
        })
    }
}

impl Drop for Invite {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("kind", &self.kind)
            .field("group", &self.group)
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

fn strip_prefix<'a>(text: &'a str, prefix: &str) -> Result<&'a str, MembershipError> {
    let text = text.trim();
    if text.len() > MAX_CODE_TEXT
        || text.len() < prefix.len()
        || !text.is_char_boundary(prefix.len())
    {
        return Err(MembershipError::Malformed);
    }
    let (head, rest) = text.split_at(prefix.len());
    if !head.eq_ignore_ascii_case(prefix) {
        return Err(MembershipError::Malformed);
    }
    Ok(rest)
}

fn decode_base32(text: &str) -> Result<Vec<u8>, MembershipError> {
    BASE32_NOPAD
        .decode(text.to_ascii_uppercase().as_bytes())
        .map_err(|_| MembershipError::Malformed)
}

/// A short code a person types: 10 characters of Crockford base32 shown as `XX-XXXX-XXXX`. The
/// first two characters (10 bits) pick the pending invite, the other eight (40 bits) are the
/// secret the PAKE runs over. `Debug` never shows the secret.
///
/// Guarantees of [`ShortCode::parse`]: case-insensitive, `-` and spaces ignored, `O` read as `0`
/// and `I` and `L` as `1`; anything but exactly 10 code characters is refused.
#[derive(Clone, PartialEq, Eq)]
pub struct ShortCode {
    id: u16,
    secret: [u8; 5],
}

impl ShortCode {
    /// A code from its parts; `id` keeps its low 10 bits.
    pub fn new(id: u16, secret: [u8; 5]) -> Self {
        Self {
            id: id & 0x3ff,
            secret,
        }
    }

    /// Which pending invite it names (10 bits).
    pub fn id(&self) -> u16 {
        self.id
    }

    pub(crate) fn secret(&self) -> &[u8; 5] {
        &self.secret
    }

    fn value(&self) -> u64 {
        let mut v = u64::from(self.id);
        for b in self.secret {
            v = (v << 8) | u64::from(b);
        }
        v
    }

    /// The code as shown: `XX-XXXX-XXXX`.
    pub fn display(&self) -> String {
        let v = self.value();
        let chars: Vec<char> = (0..10)
            .rev()
            .map(|i| CROCKFORD[((v >> (i * 5)) & 31) as usize] as char)
            .collect();
        let s: String = chars.into_iter().collect();
        format!("{}-{}-{}", &s[..2], &s[2..6], &s[6..])
    }

    /// Parses what a person typed.
    pub fn parse(text: &str) -> Result<Self, MembershipError> {
        if text.len() > 64 {
            return Err(MembershipError::Malformed);
        }
        let mut v: u64 = 0;
        let mut n = 0;
        for c in text.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            let digit = CROCKFORD
                .iter()
                .position(|&d| d as char == c)
                .ok_or(MembershipError::Malformed)?;
            n += 1;
            if n > 10 {
                return Err(MembershipError::Malformed);
            }
            v = (v << 5) | digit as u64;
        }
        if n != 10 {
            return Err(MembershipError::Malformed);
        }
        let mut secret = [0u8; 5];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (v >> (8 * (4 - i))) as u8;
        }
        Ok(Self {
            id: (v >> 40) as u16,
            secret,
        })
    }
}

impl Drop for ShortCode {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for ShortCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShortCode({}, <secret redacted>)", self.id)
    }
}

#[derive(Serialize, Deserialize)]
struct AddressBody {
    v: u8,
    endpoint: PublicKey,
    hint: WireHint,
}

/// Where a joiner with a short code dials: the pairing endpoint's key and hint, printed by a
/// server next to its short code. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairAddress {
    /// The pairing endpoint's key.
    pub endpoint: PublicKey,
    /// Where it listens.
    pub hint: WireHint,
}

impl PairAddress {
    /// [`ADDRESS_PREFIX`] and the address in unpadded base32.
    pub fn to_text(&self) -> String {
        let bytes = postcard::to_stdvec(&AddressBody {
            v: INVITE_VERSION,
            endpoint: self.endpoint,
            hint: self.hint.clone(),
        })
        .expect("an address serializes");
        format!("{ADDRESS_PREFIX}{}", BASE32_NOPAD.encode(&bytes))
    }

    /// Parses a pairing address (the prefix in any case).
    pub fn parse(text: &str) -> Result<Self, MembershipError> {
        let bytes = decode_base32(strip_prefix(text, ADDRESS_PREFIX)?)?;
        let body: AddressBody =
            postcard::from_bytes(&bytes).map_err(|_| MembershipError::Malformed)?;
        if body.v != INVITE_VERSION {
            return Err(MembershipError::Malformed);
        }
        body.hint.check()?;
        Ok(Self {
            endpoint: body.endpoint,
            hint: body.hint,
        })
    }
}

/// What a joiner holds: a scanned QR invite, or a typed short code with the address to dial.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum PairingCode {
    /// A scanned QR payload.
    Qr(Box<Invite>),
    /// A typed short code. Short codes are always server invites in this version.
    Short {
        /// The code.
        code: ShortCode,
        /// Where to dial.
        address: PairAddress,
    },
}

impl PairingCode {
    /// What the invite asks for.
    pub fn kind(&self) -> InviteKind {
        match self {
            Self::Qr(i) => i.kind,
            Self::Short { .. } => InviteKind::Server,
        }
    }

    pub(crate) fn endpoint(&self) -> (PublicKey, &WireHint) {
        match self {
            Self::Qr(i) => (i.endpoint, &i.hint),
            Self::Short { address, .. } => (address.endpoint, &address.hint),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baton_identity::Identity;
    use proptest::prelude::*;

    fn invite(kind: InviteKind) -> Invite {
        let (group, inviter) = match kind {
            InviteKind::Device => (
                Some(GroupId::new("gabc").unwrap()),
                Some(Identity::generate().public()),
            ),
            InviteKind::Server => (None, None),
        };
        Invite::new(
            kind,
            group,
            inviter,
            42,
            [7; 16],
            Identity::generate().public(),
            WireHint {
                direct: vec!["127.0.0.1:4000".parse().unwrap()],
                relay: Some("https://relay.example.com".into()),
            },
            Timestamp(1_000),
        )
    }

    #[test]
    fn qr_round_trips_and_hides_the_secret() {
        for kind in [InviteKind::Device, InviteKind::Server] {
            let i = invite(kind);
            let text = i.to_qr();
            assert!(text.starts_with(QR_PREFIX));
            assert!(!text[QR_PREFIX.len()..].contains(':'), "no host, no scheme");
            assert_eq!(Invite::from_qr(&text).unwrap(), i);
            assert_eq!(Invite::from_qr(&text.to_ascii_lowercase()).unwrap(), i);
            assert!(format!("{i:?}").contains("redacted"));
            assert!(!format!("{i:?}").contains("[7, 7"));
        }
    }

    #[test]
    fn malformed_qr_payloads_are_refused() {
        let good = invite(InviteKind::Device).to_qr();
        let long = format!("{QR_PREFIX}{}", "A".repeat(MAX_CODE_TEXT));
        let truncated = &good[..good.len() - 5];
        for bad in [
            "",
            "peleda-pair",
            "https://example.com/peleda-pair:AAAA",
            "peleda-pair:!!!!",
            truncated,
            long.as_str(),
            "peleda-pair:\u{e9}",
        ] {
            assert_eq!(
                Invite::from_qr(bad),
                Err(MembershipError::Malformed),
                "{bad:?}"
            );
        }
        let mut body: QrBody = postcard::from_bytes(
            &BASE32_NOPAD
                .decode(&good.as_bytes()[QR_PREFIX.len()..])
                .unwrap(),
        )
        .unwrap();
        body.group = None;
        let shapeless = format!(
            "{QR_PREFIX}{}",
            BASE32_NOPAD.encode(&postcard::to_stdvec(&body).unwrap())
        );
        assert_eq!(Invite::from_qr(&shapeless), Err(MembershipError::Malformed));
        body.group = Some(GroupId::new("gabc").unwrap());
        body.v = 2;
        let future = format!(
            "{QR_PREFIX}{}",
            BASE32_NOPAD.encode(&postcard::to_stdvec(&body).unwrap())
        );
        assert_eq!(Invite::from_qr(&future), Err(MembershipError::Malformed));
        body.v = 1;
        body.hint.direct = vec!["127.0.0.1:1".parse().unwrap(); MAX_HINT_ADDRS + 1];
        let crowded = format!(
            "{QR_PREFIX}{}",
            BASE32_NOPAD.encode(&postcard::to_stdvec(&body).unwrap())
        );
        assert_eq!(Invite::from_qr(&crowded), Err(MembershipError::Malformed));
    }

    #[test]
    fn short_codes_fold_and_check_length() {
        let c = ShortCode::new(0x3ff, [0xde, 0xad, 0xbe, 0xef, 0x01]);
        let shown = c.display();
        assert_eq!(shown.len(), 12);
        assert_eq!(&shown[2..3], "-");
        assert_eq!(ShortCode::parse(&shown).unwrap(), c);
        assert_eq!(ShortCode::parse(&shown.to_ascii_lowercase()).unwrap(), c);
        assert_eq!(ShortCode::parse(&shown.replace('-', " ")).unwrap(), c);
        let zero = ShortCode::new(0, [0; 5]);
        assert_eq!(zero.display(), "00-0000-0000");
        assert_eq!(ShortCode::parse("oO-OOOO-oooo").unwrap(), zero);
        let ones = ShortCode::parse("11-1111-1111").unwrap();
        assert_eq!(ShortCode::parse("iL-lIiI-1111").unwrap(), ones);
        for bad in [
            "",
            "00-0000-000",
            "00-0000-00000",
            "00-0000-000U",
            "ab*cdefghj",
            &"0".repeat(65),
        ] {
            assert_eq!(
                ShortCode::parse(bad),
                Err(MembershipError::Malformed),
                "{bad:?}"
            );
        }
        assert!(format!("{c:?}").contains("redacted"));
    }

    #[test]
    fn addresses_round_trip() {
        let a = PairAddress {
            endpoint: Identity::generate().public(),
            hint: WireHint {
                direct: vec!["192.0.2.1:9".parse().unwrap()],
                relay: None,
            },
        };
        assert_eq!(PairAddress::parse(&a.to_text()).unwrap(), a);
        assert!(PairAddress::parse("peleda-addr:ZZZZ").is_err());
        assert!(PairAddress::parse(&a.to_text().replace(ADDRESS_PREFIX, QR_PREFIX)).is_err());
        let bad_relay = WireHint {
            direct: vec![],
            relay: Some("ftp://relay.example.com".into()),
        };
        assert!(bad_relay.to_peer().is_err());
    }

    proptest! {
        #[test]
        fn short_codes_round_trip(id in 0u16..1024, secret in any::<[u8; 5]>()) {
            let c = ShortCode::new(id, secret);
            prop_assert_eq!(ShortCode::parse(&c.display()).unwrap(), c);
        }

        #[test]
        fn decoders_never_panic(text in "\\PC{0,300}") {
            let _ = Invite::from_qr(&text);
            let _ = ShortCode::parse(&text);
            let _ = PairAddress::parse(&text);
            let _ = Invite::from_qr(&format!("{QR_PREFIX}{text}"));
        }
    }
}
