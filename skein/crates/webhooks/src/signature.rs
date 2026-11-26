use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::WebhookError;

/// Header with the batch id; the same batch keeps its id across retries.
pub const ID_HEADER: &str = "Skein-Webhook-Id";
/// Header with the time the request was signed, in Unix seconds.
pub const TIMESTAMP_HEADER: &str = "Skein-Timestamp";
/// Header with the signature, `v1=<hex HMAC-SHA256>`.
pub const SIGNATURE_HEADER: &str = "Skein-Signature";
/// How far a timestamp may be from the receiver's clock, in seconds, before [`verify`] refuses
/// it: 5 minutes either way.
pub const TOLERANCE_SECS: i64 = 300;
/// Every signing secret starts with this.
pub const SECRET_PREFIX: &str = "whsec_";

fn mac(secret: &str, timestamp: &str, body: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// The `Skein-Signature` value for `body` sent at `timestamp` (Unix seconds):
/// `v1=` and the lowercase hex HMAC-SHA256 of `"{timestamp}.{body}"`, keyed with the UTF-8 bytes
/// of the whole secret (prefix included). Deterministic.
pub fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    format!(
        "v1={}",
        hex(&mac(secret, &timestamp.to_string(), body)
            .finalize()
            .into_bytes())
    )
}

/// Why [`verify`] refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// `Skein-Timestamp` is not a number of seconds.
    #[error("the timestamp is not a number of seconds")]
    BadTimestamp,
    /// The timestamp is more than [`TOLERANCE_SECS`] away from `now`: a replay or a wrong clock.
    #[error("the timestamp is too far from now")]
    Stale,
    /// The header holds no `v1=` signature.
    #[error("no v1 signature")]
    Missing,
    /// No `v1=` signature matches.
    #[error("the signature does not match")]
    Mismatch,
}

/// Checks a request as a receiver gets it: `timestamp` and `header` are the raw
/// `Skein-Timestamp` and `Skein-Signature` values, `body` the raw bytes, `now` the receiver's
/// clock in Unix seconds.
///
/// Accepts when the timestamp is within [`TOLERANCE_SECS`] of `now` and any `v1=` entry of the
/// header (entries separated by commas or spaces) matches. Signatures are compared in constant
/// time. Entries with other versions are ignored, so receivers keep working when new ones are
/// added next to `v1`.
pub fn verify(
    secret: &str,
    timestamp: &str,
    body: &[u8],
    header: &str,
    now: i64,
) -> Result<(), VerifyError> {
    if timestamp.is_empty()
        || timestamp.len() > 18
        || !timestamp.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(VerifyError::BadTimestamp);
    }
    let sent: i64 = timestamp.parse().map_err(|_| VerifyError::BadTimestamp)?;
    if sent.abs_diff(now) > TOLERANCE_SECS as u64 {
        return Err(VerifyError::Stale);
    }
    let candidates: Vec<&str> = header
        .split([',', ' '])
        .filter_map(|part| part.trim().strip_prefix("v1="))
        .collect();
    if candidates.is_empty() {
        return Err(VerifyError::Missing);
    }
    let matched = candidates.iter().fold(false, |found, candidate| {
        let ok = unhex(candidate)
            .is_some_and(|bytes| mac(secret, timestamp, body).verify_slice(&bytes).is_ok());
        found | ok
    });
    if matched {
        Ok(())
    } else {
        Err(VerifyError::Mismatch)
    }
}

/// A new signing secret: [`SECRET_PREFIX`] and 32 bytes from the system's random source in
/// unpadded base64url (43 characters).
pub fn new_secret() -> Result<String, WebhookError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| WebhookError::Random)?;
    Ok(format!("{SECRET_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_dGVzdC1zZWNyZXQtZm9yLXNpZ25hdHVyZS12ZWN0b3JzLW9ubHk";

    #[test]
    fn signature_vectors() {
        // Computed independently with `printf '%s' "{timestamp}.{body}" | openssl dgst -sha256
        // -hmac "{secret}"`.
        assert_eq!(
            sign("key", 0, b""),
            "v1=85841b4efc3cd7776c3c8f9b7cca9e281c550e5d19889d78e9e669c6337f000d"
        );
        assert_eq!(
            sign(SECRET, 1_700_000_000, br#"{"events":[]}"#),
            "v1=360196fb8ed5cf2c5c3a415cb4273e0d287c88a73e12c024aebf272311cb7890"
        );
        assert_eq!(
            sign(
                SECRET,
                1_732_147_200,
                br#"{"endpoint":"01jd0000000000000000000000","tenant":"acme","account":"box","events":[]}"#
            ),
            "v1=53770078f4a8609f0131bf00875635bba41bfbbc443a59f636b7f279f3223ef6"
        );
    }

    #[test]
    fn verify_accepts_fresh_matching_signatures_only() {
        let body = br#"{"endpoint":"e","events":[]}"#;
        let header = sign(SECRET, 1_000, body);
        assert_eq!(verify(SECRET, "1000", body, &header, 1_000), Ok(()));
        assert_eq!(verify(SECRET, "1000", body, &header, 1_300), Ok(()));
        assert_eq!(verify(SECRET, "1000", body, &header, 700), Ok(()));
        assert_eq!(
            verify(SECRET, "1000", body, &header, 1_301),
            Err(VerifyError::Stale)
        );
        assert_eq!(
            verify(SECRET, "1000", body, &header, 699),
            Err(VerifyError::Stale)
        );
        assert_eq!(
            verify(SECRET, "1001", body, &header, 1_000),
            Err(VerifyError::Mismatch)
        );
        assert_eq!(
            verify(SECRET, "1000", b"{}", &header, 1_000),
            Err(VerifyError::Mismatch)
        );
        assert_eq!(
            verify("whsec_other", "1000", body, &header, 1_000),
            Err(VerifyError::Mismatch)
        );
        for bad in ["", "-1", "+1000", "1e3", "10.0", "99999999999999999999"] {
            assert_eq!(
                verify(SECRET, bad, body, &header, 1_000),
                Err(VerifyError::BadTimestamp),
                "{bad}"
            );
        }
        assert_eq!(
            verify(SECRET, "1000", body, "v0=abc", 1_000),
            Err(VerifyError::Missing)
        );
        assert_eq!(
            verify(SECRET, "1000", body, "v1=zz", 1_000),
            Err(VerifyError::Mismatch)
        );
        let several = format!("v2=ignored, v1=00ff {header}");
        assert_eq!(verify(SECRET, "1000", body, &several, 1_000), Ok(()));
    }

    #[test]
    fn secrets_are_fresh_and_well_formed() {
        let a = new_secret().unwrap();
        let b = new_secret().unwrap();
        assert_ne!(a, b);
        let rest = a.strip_prefix(SECRET_PREFIX).unwrap();
        assert_eq!(rest.len(), 43);
        assert_eq!(URL_SAFE_NO_PAD.decode(rest).unwrap().len(), 32);
    }
}
