//! A small DNS client for SRV records: one question over UDP to the system's name servers, a
//! bounded reader of the answer.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use rowboat_discover::{DiscoverError, MAX_SRV_RECORDS, SrvRecord, SrvResolver, valid_srv_name};
use tokio::net::UdpSocket;

/// The largest answer read; without EDNS a server sends at most 512 bytes over UDP.
pub const MAX_MESSAGE: usize = 4096;
/// Most name servers asked, in order.
pub const MAX_SERVERS: usize = 3;
/// Most answer records read from one message.
pub const MAX_ANSWERS: usize = 64;
/// Most compression pointers followed in one name.
pub const MAX_JUMPS: usize = 16;

const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1;

/// Why an answer was not read. Carries no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerError {
    /// The bytes are not a DNS message within the limits.
    Malformed,
    /// The message is not the answer to this question (another id, another name, a query).
    NotOurs,
    /// The answer was cut short (`TC`); UDP is not retried over TCP.
    Truncated,
    /// The server failed (`SERVFAIL`, `REFUSED` and the like).
    Failed,
}

/// The query for the SRV records of `name` with `id`, recursion desired. `None` for a name that
/// cannot be encoded (a label over 63 bytes, a name over 253).
pub fn query(id: u16, name: &str) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut out = Vec::with_capacity(18 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&TYPE_SRV.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(out)
}

fn u16_at(msg: &[u8], at: usize) -> Result<u16, AnswerError> {
    msg.get(at..at + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or(AnswerError::Malformed)
}

/// A name at `at`: its text (lower case, labels joined by `.`, the root as an empty string, or
/// `None` when a label holds a byte other than a letter, digit, `-` or `_`) and the position
/// after it in the message. Pointers must point backwards, at most [`MAX_JUMPS`] of them; the
/// name is at most 255 bytes on the wire.
fn read_name(msg: &[u8], mut at: usize) -> Result<(Option<String>, usize), AnswerError> {
    let mut text = String::new();
    let mut plain = true;
    let mut end = None;
    let mut jumps = 0;
    let mut wire = 0usize;
    loop {
        let len = *msg.get(at).ok_or(AnswerError::Malformed)? as usize;
        match len & 0xc0 {
            0x00 if len == 0 => {
                let next = end.unwrap_or(at + 1);
                return Ok((plain.then_some(text), next));
            }
            0x00 => {
                wire += len + 1;
                if wire > 255 {
                    return Err(AnswerError::Malformed);
                }
                let label = msg
                    .get(at + 1..at + 1 + len)
                    .ok_or(AnswerError::Malformed)?;
                if !label
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
                {
                    plain = false;
                }
                if plain {
                    if !text.is_empty() {
                        text.push('.');
                    }
                    text.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
                }
                at += 1 + len;
            }
            0xc0 => {
                let target = (u16_at(msg, at)? & 0x3fff) as usize;
                jumps += 1;
                if jumps > MAX_JUMPS || target >= at {
                    return Err(AnswerError::Malformed);
                }
                end.get_or_insert(at + 2);
                at = target;
            }
            _ => return Err(AnswerError::Malformed),
        }
    }
}

/// The SRV records answering `name` (lower case, as asked) in the message `msg` for query `id`.
///
/// Checks: at most [`MAX_MESSAGE`] bytes; a response (`QR`) to a standard query with the same
/// id and one question equal to `name`, type SRV, class IN; not truncated. `NXDOMAIN` is an
/// empty answer; any other error code is [`AnswerError::Failed`]. Only `IN SRV` records whose
/// owner is `name` are kept (so a CNAME chain or an extra record cannot add hosts), at most
/// [`MAX_ANSWERS`] records read and [`MAX_SRV_RECORDS`] kept, in message order. A target with
/// odd bytes is dropped; the root target is kept as an empty string. Never panics.
pub fn parse_answer(msg: &[u8], id: u16, name: &str) -> Result<Vec<SrvRecord>, AnswerError> {
    if msg.len() < 12 || msg.len() > MAX_MESSAGE {
        return Err(AnswerError::Malformed);
    }
    let flags = u16_at(msg, 2)?;
    if u16_at(msg, 0)? != id || flags & 0x8000 == 0 || (flags >> 11) & 0x0f != 0 {
        return Err(AnswerError::NotOurs);
    }
    if flags & 0x0200 != 0 {
        return Err(AnswerError::Truncated);
    }
    if u16_at(msg, 4)? != 1 {
        return Err(AnswerError::NotOurs);
    }
    let answers = u16_at(msg, 6)? as usize;
    let (qname, mut at) = read_name(msg, 12)?;
    if qname.as_deref() != Some(name)
        || u16_at(msg, at)? != TYPE_SRV
        || u16_at(msg, at + 2)? != CLASS_IN
    {
        return Err(AnswerError::NotOurs);
    }
    at += 4;
    match flags & 0x000f {
        0 => {}
        3 => return Ok(Vec::new()),
        _ => return Err(AnswerError::Failed),
    }
    let mut out = Vec::new();
    for _ in 0..answers.min(MAX_ANSWERS) {
        let (owner, next) = read_name(msg, at)?;
        let kind = u16_at(msg, next)?;
        let class = u16_at(msg, next + 2)?;
        let length = u16_at(msg, next + 8)? as usize;
        let start = next + 10;
        let stop = start + length;
        if stop > msg.len() {
            return Err(AnswerError::Malformed);
        }
        if kind == TYPE_SRV && class == CLASS_IN && owner.as_deref() == Some(name) {
            if length < 7 {
                return Err(AnswerError::Malformed);
            }
            let (target, end) = read_name(msg, start + 6)?;
            if end > stop {
                return Err(AnswerError::Malformed);
            }
            if let Some(target) = target
                && out.len() < MAX_SRV_RECORDS
            {
                out.push(SrvRecord {
                    priority: u16_at(msg, start)?,
                    weight: u16_at(msg, start + 2)?,
                    port: u16_at(msg, start + 4)?,
                    target,
                });
            }
        }
        at = stop;
    }
    Ok(out)
}

/// The name servers in a `resolv.conf` text: `nameserver` lines with an IP address, port 53, at
/// most [`MAX_SERVERS`], in order; everything else ignored. Pure.
pub fn name_servers(conf: &str) -> Vec<SocketAddr> {
    conf.lines()
        .take(1000)
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver"))
                .then(|| words.next())
                .flatten()
                .and_then(|w| w.split('%').next())
                .and_then(|w| w.parse::<IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .take(MAX_SERVERS)
        .collect()
}

/// An [`SrvResolver`] asking name servers over UDP: a random query id from the operating
/// system, a fresh socket (so a random source port) per question, answers only from the server
/// asked (the socket is connected), at most 8 datagrams read per server before the next one,
/// each server within the timeout (3 s by default). No TCP fallback: a truncated answer counts
/// as no answer.
#[derive(Debug, Clone)]
pub struct UdpResolver {
    servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl UdpResolver {
    /// A resolver over `servers` (at most [`MAX_SERVERS`] used) with `timeout` per server.
    pub fn new(servers: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self {
            servers: servers.into_iter().take(MAX_SERVERS).collect(),
            timeout,
        }
    }

    /// A resolver over the name servers in `/etc/resolv.conf`. [`DiscoverError::Unavailable`]
    /// when the file is missing, larger than 64 KiB or names none (macOS writes the file for
    /// the primary network service; a VPN's split DNS is not seen).
    pub fn system() -> Result<Self, DiscoverError> {
        let file =
            std::fs::File::open("/etc/resolv.conf").map_err(|_| DiscoverError::Unavailable)?;
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::Read::take(file, 64 * 1024), &mut text)
            .map_err(|_| DiscoverError::Unavailable)?;
        let servers = name_servers(&text);
        if servers.is_empty() {
            return Err(DiscoverError::Unavailable);
        }
        Ok(Self::new(servers, Duration::from_secs(3)))
    }

    async fn ask(&self, server: SocketAddr, name: &str) -> Result<Vec<SrvRecord>, DiscoverError> {
        let mut id = [0u8; 2];
        getrandom::fill(&mut id).map_err(|_| DiscoverError::Unavailable)?;
        let id = u16::from_be_bytes(id);
        let packet = query(id, name).ok_or(DiscoverError::Invalid)?;
        let local: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().expect("address")
        } else {
            "[::]:0".parse().expect("address")
        };
        let socket = UdpSocket::bind(local)
            .await
            .map_err(|_| DiscoverError::Unavailable)?;
        socket
            .connect(server)
            .await
            .map_err(|_| DiscoverError::Unreachable)?;
        tokio::time::timeout(self.timeout, async {
            socket
                .send(&packet)
                .await
                .map_err(|_| DiscoverError::Unreachable)?;
            let mut buf = vec![0u8; MAX_MESSAGE];
            for _ in 0..8 {
                let n = socket
                    .recv(&mut buf)
                    .await
                    .map_err(|_| DiscoverError::Unreachable)?;
                match parse_answer(&buf[..n], id, name) {
                    Ok(records) => return Ok(records),
                    Err(AnswerError::NotOurs) => continue,
                    Err(_) => return Err(DiscoverError::Unavailable),
                }
            }
            Err(DiscoverError::Unavailable)
        })
        .await
        .map_err(|_| DiscoverError::Timeout)?
    }
}

#[async_trait]
impl SrvResolver for UdpResolver {
    async fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, DiscoverError> {
        if !valid_srv_name(name) {
            return Err(DiscoverError::Invalid);
        }
        let mut last = DiscoverError::Unavailable;
        for server in &self.servers {
            match self.ask(*server, name).await {
                Ok(records) => return Ok(records),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests;
