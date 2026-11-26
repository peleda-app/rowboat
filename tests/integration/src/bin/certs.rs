//! Writes a throwaway test CA and one server certificate it signed into the directory given as
//! the only argument: `ca.crt`, `tls.crt` and `tls.key` (PEM). The certificate names
//! `mail.localhost`, `localhost` and `127.0.0.1`, is valid from a day ago for thirty days, and
//! exists only for the containers of the integration stack.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

fn main() {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: rowboat-it-certs <dir>"),
    );
    std::fs::create_dir_all(&dir).expect("certificate directory");
    let now = SystemTime::now();
    let day = Duration::from_secs(86_400);

    let mut ca = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "rowboat integration test CA");
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.not_before = (now - day).into();
    ca.not_after = (now + 30 * day).into();
    let ca_key = KeyPair::generate().expect("CA key");
    let ca_cert = ca.self_signed(&ca_key).expect("CA certificate");
    let issuer = Issuer::new(ca, ca_key);

    let names = ["mail.localhost", "localhost", "127.0.0.1"];
    let mut server =
        CertificateParams::new(names.map(str::to_owned).to_vec()).expect("server names");
    server
        .distinguished_name
        .push(DnType::CommonName, "mail.localhost");
    server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server.not_before = (now - day).into();
    server.not_after = (now + 30 * day).into();
    let key = KeyPair::generate().expect("server key");
    let cert = server.signed_by(&key, &issuer).expect("server certificate");

    std::fs::write(dir.join("ca.crt"), ca_cert.pem()).expect("ca.crt");
    std::fs::write(dir.join("tls.crt"), cert.pem()).expect("tls.crt");
    std::fs::write(dir.join("tls.key"), key.serialize_pem()).expect("tls.key");
}
