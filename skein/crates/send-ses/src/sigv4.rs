//! AWS Signature Version 4 for header-signed requests.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// An access key pair, with a session token for temporary credentials.
#[derive(Clone)]
pub(crate) struct Key {
    pub(crate) id: String,
    pub(crate) secret: String,
    pub(crate) session_token: Option<String>,
}

/// What gets signed. `path` and `query` are already URI-encoded as they go on the wire;
/// `headers` hold every header to sign, `host` and `x-amz-date` included.
pub(crate) struct Request<'a> {
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) query: &'a str,
    pub(crate) headers: &'a [(String, String)],
    pub(crate) payload: &'a [u8],
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// The canonical request and its signed header list.
pub(crate) fn canonical_request(request: &Request<'_>) -> (String, String) {
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, value) in request.headers {
        let name = name.to_ascii_lowercase();
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        match headers.iter_mut().find(|(n, _)| *n == name) {
            Some((_, existing)) => {
                existing.push(',');
                existing.push_str(&value);
            }
            None => headers.push((name, value)),
        }
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let signed = headers
        .iter()
        .map(|(n, _)| n.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut pairs: Vec<(&str, &str)> = request
        .query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    pairs.sort();
    let query = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut canonical = format!("{}\n{}\n{query}\n", request.method, request.path);
    for (name, value) in &headers {
        canonical.push_str(&format!("{name}:{value}\n"));
    }
    canonical.push_str(&format!("\n{signed}\n{}", sha256_hex(request.payload)));
    (canonical, signed)
}

/// The string to sign for a canonical request at `amz_date` (`YYYYMMDDTHHMMSSZ`) in `scope`.
pub(crate) fn string_to_sign(amz_date: &str, scope: &str, canonical: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    )
}

/// The `Authorization` header value for `request`, signed at `amz_date` for `region` and
/// `service`. Deterministic.
pub(crate) fn authorization(
    key: &Key,
    region: &str,
    service: &str,
    amz_date: &str,
    request: &Request<'_>,
) -> String {
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let (canonical, signed) = canonical_request(request);
    let to_sign = string_to_sign(amz_date, &scope, &canonical);
    let k_date = hmac(format!("AWS4{}", key.secret).as_bytes(), date);
    let k_region = hmac(&k_date, region);
    let k_service = hmac(&k_region, service);
    let k_signing = hmac(&k_service, "aws4_request");
    let signature = hex(&hmac(&k_signing, &to_sign));
    format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
        key.id
    )
}

/// The current time as `YYYYMMDDTHHMMSSZ` in UTC.
pub(crate) fn amz_date_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    amz_date(seconds)
}

/// `seconds` since the Unix epoch as `YYYYMMDDTHHMMSSZ` in UTC.
pub(crate) fn amz_date(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "AKIDEXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    struct Vector {
        req: &'static str,
        creq: &'static str,
        sts: &'static str,
        authz: &'static str,
    }

    macro_rules! vector {
        ($name:literal) => {
            (
                $name,
                Vector {
                    req: include_str!(concat!("../tests/fixtures/sigv4/", $name, ".req")),
                    creq: include_str!(concat!("../tests/fixtures/sigv4/", $name, ".creq")),
                    sts: include_str!(concat!("../tests/fixtures/sigv4/", $name, ".sts")),
                    authz: include_str!(concat!("../tests/fixtures/sigv4/", $name, ".authz")),
                },
            )
        };
    }

    struct Parsed {
        method: String,
        path: String,
        query: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    fn parse(req: &str) -> Parsed {
        let (head, body) = req.split_once("\n\n").unwrap_or((req, ""));
        let mut lines = head.lines();
        let mut start = lines.next().unwrap().split(' ');
        let method = start.next().unwrap().to_owned();
        let target = start.next().unwrap();
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let headers = lines
            .filter(|l| !l.is_empty())
            .map(|l| {
                let (n, v) = l.split_once(':').unwrap();
                (n.to_owned(), v.to_owned())
            })
            .collect();
        Parsed {
            method,
            path: path.to_owned(),
            query: query.to_owned(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn matches_the_aws_signature_v4_test_suite() {
        let vectors = [
            vector!("get-vanilla"),
            vector!("post-vanilla"),
            vector!("get-vanilla-query-order-key-case"),
            vector!("post-x-www-form-urlencoded"),
            vector!("post-sts-header-before"),
            vector!("get-header-value-trim"),
        ];
        for (name, v) in vectors {
            let parsed = parse(v.req);
            let request = Request {
                method: &parsed.method,
                path: &parsed.path,
                query: &parsed.query,
                headers: &parsed.headers,
                payload: &parsed.body,
            };
            let (canonical, _) = canonical_request(&request);
            assert_eq!(canonical, v.creq, "{name}: canonical request");
            let scope = "20150830/us-east-1/service/aws4_request";
            assert_eq!(
                string_to_sign("20150830T123600Z", scope, &canonical),
                v.sts,
                "{name}: string to sign"
            );
            let key = Key {
                id: ID.into(),
                secret: SECRET.into(),
                session_token: None,
            };
            assert_eq!(
                authorization(&key, "us-east-1", "service", "20150830T123600Z", &request),
                v.authz,
                "{name}: authorization"
            );
        }
    }

    #[test]
    fn formats_utc_dates() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_440_938_160), "20150830T123600Z");
        assert_eq!(amz_date(951_782_400), "20000229T000000Z");
        assert_eq!(amz_date(4_102_444_799), "20991231T235959Z");
    }
}
