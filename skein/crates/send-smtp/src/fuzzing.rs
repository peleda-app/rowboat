//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

/// Reads `bytes` as everything an SMTP server sends on one connection: replies one after the
/// other, multi-line ones included, each also read as an EHLO answer, until the bytes run out or
/// a reply is malformed.
pub fn replies(bytes: &[u8]) {
    crate::session::fuzz_replies(bytes);
}
