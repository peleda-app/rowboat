//! The networked halves of discovery: [`Https`], an [`HttpsFetcher`] over HTTPS with a verified
//! certificate, and [`UdpResolver`], an [`SrvResolver`] asking the system's name servers over
//! UDP. Both bound time and bytes; the DNS answer reader ([`dns::parse_answer`]) is a decoder of
//! untrusted input with a fuzz target.
//!
//! [`HttpsFetcher`]: rowboat_discover::HttpsFetcher
//! [`SrvResolver`]: rowboat_discover::SrvResolver

pub mod dns;
mod https;

pub use dns::UdpResolver;
pub use https::Https;
