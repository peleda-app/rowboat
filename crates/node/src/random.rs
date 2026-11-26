const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub(crate) fn bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("the operating system's random source");
    out
}

/// `prefix` and 26 characters of lowercase base32 (`[a-z2-7]`), 130 random bits.
pub(crate) fn base32_id(prefix: char) -> String {
    let raw: [u8; 26] = bytes();
    let mut out = String::with_capacity(27);
    out.push(prefix);
    out.extend(raw.iter().map(|b| ALPHABET[(b & 31) as usize] as char));
    out
}

/// `n` (at most 64) random characters of `[a-f0-9]`.
pub(crate) fn alnum(n: usize) -> String {
    let raw: [u8; 32] = bytes();
    let hex = data_encoding::HEXLOWER.encode(&raw);
    hex[..n.min(64)].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_the_api_shape() {
        let a = base32_id('a');
        assert!(rowboat_api::AccountId::new(a.clone()).is_ok(), "{a}");
        assert_ne!(base32_id('a'), base32_id('a'));
        assert_eq!(alnum(16).len(), 16);
    }
}
