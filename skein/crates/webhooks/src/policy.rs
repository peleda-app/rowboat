use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use url::{Host, Url};

use crate::SendError;

/// Longest endpoint address accepted.
pub const MAX_URL_LEN: usize = 2048;

/// An IPv4 or IPv6 network such as `10.20.0.0/16`, or a single address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

/// A network that does not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not an IP network")]
pub struct InvalidNetwork;

impl FromStr for Network {
    type Err = InvalidNetwork;

    fn from_str(s: &str) -> Result<Self, InvalidNetwork> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.trim().parse().map_err(|_| InvalidNetwork)?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.trim().parse::<u8>().map_err(|_| InvalidNetwork)?,
            None => max,
        };
        if prefix > max {
            return Err(InvalidNetwork);
        }
        Ok(Self { addr, prefix })
    }
}

impl Network {
    /// Whether `ip` is in this network. IPv4 networks never contain IPv6 addresses; callers
    /// canonicalize mapped addresses first.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Where webhook requests may go.
///
/// By default only `https` addresses whose host is, or resolves only to, public unicast
/// addresses. The connection goes to the very addresses that were checked, so a host name cannot
/// be re-pointed between the check and the request.
#[derive(Debug, Clone)]
pub struct WebhookPolicy {
    /// Allows loopback addresses, and plain `http` to a loopback address or `localhost`. For
    /// tests and single-machine setups only.
    pub allow_http_loopback: bool,
    /// Networks allowed even though they are private or reserved, such as an internal receiver
    /// at `10.20.0.0/16`.
    pub allowed_networks: Vec<Network>,
    /// Longest wait for one request, connection and answer included. Default 10 s.
    pub timeout: Duration,
}

impl Default for WebhookPolicy {
    fn default() -> Self {
        Self {
            allow_http_loopback: false,
            allowed_networks: Vec::new(),
            timeout: Duration::from_secs(10),
        }
    }
}

fn v4_public(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || ip.is_documentation()
        || (a == 198 && (b == 18 || b == 19))
        || ip.is_multicast()
        || a >= 240)
}

fn v6_public(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x2001 && s[1] == 0)
        || s[0] == 0x2002
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
        || s[..6] == [0; 6])
}

/// IPv4-mapped (`::ffff:a.b.c.d`) and NAT64 (`64:ff9b::a.b.c.d`) addresses are judged by the
/// IPv4 address they carry.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
                let o = v6.octets();
                IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

pub(crate) fn is_localhost_name(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost")
}

impl WebhookPolicy {
    /// Whether a request may connect to `ip`.
    pub fn address_allowed(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        if self.allowed_networks.iter().any(|n| n.contains(ip)) {
            return true;
        }
        if self.allow_http_loopback && ip.is_loopback() {
            return true;
        }
        match ip {
            IpAddr::V4(v4) => v4_public(v4),
            IpAddr::V6(v6) => v6_public(v6),
        }
    }

    /// Checks the address without resolving it: a URL of at most [`MAX_URL_LEN`] bytes,
    /// `https` (or `http` to loopback when allowed), a host, no user name or password, and an
    /// allowed address when the host is an IP literal. Fragments are dropped.
    pub fn parse(&self, url: &str) -> Result<Url, SendError> {
        if url.len() > MAX_URL_LEN {
            return Err(SendError::InvalidUrl("the address is too long"));
        }
        let mut parsed = Url::parse(url).map_err(|_| SendError::InvalidUrl("not a URL"))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(SendError::InvalidUrl("credentials in the address"));
        }
        parsed.set_fragment(None);
        let ip = match parsed.host() {
            None => return Err(SendError::InvalidUrl("no host")),
            Some(Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
            Some(Host::Domain(_)) => None,
        };
        let loopback_host = match (ip, parsed.host_str()) {
            (Some(ip), _) => canonical(ip).is_loopback(),
            (None, Some(name)) => is_localhost_name(name),
            _ => false,
        };
        match parsed.scheme() {
            "https" => {}
            "http" if self.allow_http_loopback && loopback_host => {}
            _ => return Err(SendError::InvalidUrl("only https addresses")),
        }
        if let Some(ip) = ip
            && !self.address_allowed(ip)
        {
            return Err(SendError::AddressRefused("private or reserved address"));
        }
        if ip.is_none() && loopback_host && !self.allow_http_loopback {
            return Err(SendError::AddressRefused("localhost"));
        }
        Ok(parsed)
    }

    /// [`WebhookPolicy::parse`], then resolves a host name and refuses it unless it resolves to
    /// at least one address and every address is allowed. What endpoint creation runs.
    pub async fn check(&self, url: &str) -> Result<Url, SendError> {
        let parsed = self.parse(url)?;
        if let Some(Host::Domain(name)) = parsed.host() {
            let addrs = resolve(name).await?;
            self.judge(name, &addrs)?;
        }
        Ok(parsed)
    }

    pub(crate) fn judge(&self, name: &str, addrs: &[IpAddr]) -> Result<(), SendError> {
        if addrs.is_empty() {
            return Err(SendError::Unresolved);
        }
        let local = is_localhost_name(name);
        for ip in addrs {
            if !self.address_allowed(*ip) || (local && !canonical(*ip).is_loopback()) {
                return Err(SendError::AddressRefused(
                    "the host resolves to a private or reserved address",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) async fn resolve(name: &str) -> Result<Vec<IpAddr>, SendError> {
    let addrs = tokio::net::lookup_host((name.trim_end_matches('.'), 0))
        .await
        .map_err(|_| SendError::Unresolved)?;
    Ok(addrs.map(|a| a.ip()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn refuses_private_and_reserved_addresses() {
        let policy = WebhookPolicy::default();
        for refused in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.8.9.10",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.10",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "2002:a00:1::1",
            "100::1",
            "::a00:1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
        ] {
            assert!(!policy.address_allowed(ip(refused)), "{refused}");
        }
        for allowed in [
            "93.184.215.14",
            "1.1.1.1",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700::1111",
            "::ffff:93.184.215.14",
            "64:ff9b::5db8:d70e",
        ] {
            assert!(policy.address_allowed(ip(allowed)), "{allowed}");
        }
    }

    #[test]
    fn exceptions_are_explicit() {
        let policy = WebhookPolicy {
            allowed_networks: vec!["10.20.0.0/16".parse().unwrap(), "fd00::5".parse().unwrap()],
            ..Default::default()
        };
        assert!(policy.address_allowed(ip("10.20.3.4")));
        assert!(policy.address_allowed(ip("::ffff:10.20.3.4")));
        assert!(!policy.address_allowed(ip("10.21.0.1")));
        assert!(policy.address_allowed(ip("fd00::5")));
        assert!(!policy.address_allowed(ip("fd00::6")));
        assert!(!policy.address_allowed(ip("127.0.0.1")));
        let loopback = WebhookPolicy {
            allow_http_loopback: true,
            ..Default::default()
        };
        assert!(loopback.address_allowed(ip("127.0.0.1")));
        assert!(loopback.address_allowed(ip("::1")));
        assert!(!loopback.address_allowed(ip("10.0.0.1")));
        for bad in ["", "10.0.0.0/33", "fd00::/129", "example.com", "10.0.0.0/x"] {
            assert!(bad.parse::<Network>().is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_only_https_without_credentials() {
        let policy = WebhookPolicy::default();
        assert!(policy.parse("https://hooks.example.com/in?x=1").is_ok());
        for (url, kind) in [
            ("http://hooks.example.com/in", "invalid_url"),
            ("ftp://hooks.example.com/in", "invalid_url"),
            ("file:///etc/passwd", "invalid_url"),
            ("not a url", "invalid_url"),
            ("https://user:pass@hooks.example.com/", "invalid_url"),
            ("https://user@hooks.example.com/", "invalid_url"),
            ("https://10.0.0.1/hook", "address_refused"),
            ("https://[::1]/hook", "address_refused"),
            ("https://[::ffff:192.168.0.1]/hook", "address_refused"),
            ("https://0x7f000001/hook", "address_refused"),
            ("https://2130706433/hook", "address_refused"),
            ("https://localhost/hook", "address_refused"),
            ("https://api.localhost/hook", "address_refused"),
            ("http://127.0.0.1:8080/hook", "invalid_url"),
        ] {
            assert_eq!(policy.parse(url).unwrap_err().kind(), kind, "{url}");
        }
        let long = format!("https://hooks.example.com/{}", "a".repeat(MAX_URL_LEN));
        assert!(policy.parse(&long).is_err());
        let loopback = WebhookPolicy {
            allow_http_loopback: true,
            ..Default::default()
        };
        assert!(loopback.parse("http://127.0.0.1:8080/hook").is_ok());
        assert!(loopback.parse("http://localhost:8080/hook").is_ok());
        assert!(loopback.parse("http://[::1]:8080/hook").is_ok());
        assert!(loopback.parse("http://hooks.example.com/hook").is_err());
        assert!(loopback.parse("http://10.0.0.1/hook").is_err());
    }

    #[test]
    fn names_must_resolve_only_to_allowed_addresses() {
        let policy = WebhookPolicy::default();
        assert!(
            policy
                .judge("hooks.example.com", &[ip("93.184.215.14")])
                .is_ok()
        );
        assert_eq!(
            policy.judge("hooks.example.com", &[]),
            Err(SendError::Unresolved)
        );
        assert!(
            policy
                .judge("hooks.example.com", &[ip("93.184.215.14"), ip("10.0.0.1")])
                .is_err(),
            "one private answer is enough to refuse"
        );
        let loopback = WebhookPolicy {
            allow_http_loopback: true,
            ..Default::default()
        };
        assert!(loopback.judge("localhost", &[ip("127.0.0.1")]).is_ok());
        assert!(
            loopback.judge("localhost", &[ip("93.184.215.14")]).is_err(),
            "localhost must stay local"
        );
    }

    #[tokio::test]
    async fn localhost_is_refused_after_resolution() {
        let policy = WebhookPolicy::default();
        assert!(policy.check("https://localhost/hook").await.is_err());
    }
}
