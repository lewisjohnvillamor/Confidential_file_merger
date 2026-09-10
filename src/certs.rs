//! Identities (certificate + private key) and the trust store, all on local disk.
//!
//! * An identity is a self-signed X.509 certificate generated here, or a certificate
//!   plus key imported from elsewhere. The private key is stored as PKCS#8 encrypted
//!   with the user's passphrase (PBES2), so the file on disk is useless without it.
//! * The trust store holds other people's public certificates. A signature is reported
//!   as *trusted* when its certificate is one of ours, is in the trust store, or was
//!   issued by a certificate in the trust store.
//!
//! Nothing here touches the network.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use der::asn1::{Ia5String, OctetString};
use der::pem::LineEnding;
use der::{Decode, DecodePem, Encode, EncodePem};
use p256::ecdsa::{DerSignature, SigningKey as EcSigningKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::Keypair;
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder, RequestBuilder};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, KeyUsage, KeyUsages, SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::Certificate;

#[derive(Debug)]
pub struct CertError(pub String);

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CertError {}

fn err<E: fmt::Display>(context: &str) -> impl FnOnce(E) -> CertError + '_ {
    move |e| CertError(format!("{context}: {e}"))
}

/// A private key we can sign with.
pub enum PrivateKey {
    P256(EcSigningKey),
    Rsa(RsaSigningKey<Sha256>),
}

impl PrivateKey {
    fn to_encrypted_pem(&self, passphrase: &str) -> Result<String, CertError> {
        let pem = match self {
            PrivateKey::P256(k) => k.to_pkcs8_encrypted_pem(passphrase, LineEnding::LF),
            PrivateKey::Rsa(k) => k
                .as_ref()
                .to_pkcs8_encrypted_pem(passphrase, LineEnding::LF),
        }
        .map_err(err("could not encrypt the private key"))?;
        Ok(pem.to_string())
    }

    fn from_pem(pem: &str, passphrase: Option<&str>) -> Result<PrivateKey, CertError> {
        let encrypted = pem.contains("ENCRYPTED PRIVATE KEY");
        if encrypted && passphrase.is_none() {
            return Err(CertError(
                "the private key is encrypted; a passphrase is required".into(),
            ));
        }
        // Try P-256 first, then RSA. Both PKCS#8 and traditional PEM forms are accepted.
        let p256_key: Option<p256::SecretKey> = match passphrase {
            Some(pw) if encrypted => p256::SecretKey::from_pkcs8_encrypted_pem(pem, pw).ok(),
            _ => p256::SecretKey::from_pkcs8_pem(pem)
                .ok()
                .or_else(|| p256::SecretKey::from_sec1_pem(pem).ok()),
        };
        if let Some(k) = p256_key {
            return Ok(PrivateKey::P256(EcSigningKey::from(k)));
        }
        let rsa_key: Option<rsa::RsaPrivateKey> = match passphrase {
            Some(pw) if encrypted => rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(pem, pw).ok(),
            _ => rsa::RsaPrivateKey::from_pkcs8_pem(pem).ok().or_else(|| {
                use rsa::pkcs1::DecodeRsaPrivateKey;
                rsa::RsaPrivateKey::from_pkcs1_pem(pem).ok()
            }),
        };
        match rsa_key {
            Some(k) => Ok(PrivateKey::Rsa(RsaSigningKey::<Sha256>::new(k))),
            None if encrypted => Err(CertError(
                "wrong passphrase, or an unsupported key type".into(),
            )),
            None => Err(CertError(
                "unsupported private key (use an ECDSA P-256 or RSA key in PEM form)".into(),
            )),
        }
    }

    fn public_key_der(&self) -> Result<Vec<u8>, CertError> {
        use spki::EncodePublicKey;
        let doc = match self {
            PrivateKey::P256(k) => k.verifying_key().to_public_key_der(),
            PrivateKey::Rsa(k) => k.verifying_key().to_public_key_der(),
        }
        .map_err(err("could not encode the public key"))?;
        Ok(doc.as_bytes().to_vec())
    }
}

/// An unlocked identity, ready to sign.
pub struct Signer {
    pub certificate: Certificate,
    pub key: PrivateKey,
    pub info: CertInfo,
}

/// Human-readable facts about a certificate.
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub common_name: String,
    pub email: Option<String>,
    pub organization: Option<String>,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint: String,
    pub key_algorithm: String,
    pub self_signed: bool,
    pub valid_now: bool,
}

pub fn fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hash.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn cert_info(cert: &Certificate) -> CertInfo {
    let der = cert.to_der().unwrap_or_default();
    let tbs = cert.tbs_certificate();
    let email = tbs
        .subject()
        .email_address()
        .ok()
        .flatten()
        .map(|s| s.to_string())
        .or_else(|| {
            tbs.extensions().as_ref().and_then(|exts| {
                exts.iter()
                    .filter(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME)
                    .find_map(|e| SubjectAltName::from_der(e.extn_value.as_bytes()).ok())
                    .and_then(|san| {
                        san.0.iter().find_map(|g| match g {
                            GeneralName::Rfc822Name(s) => Some(s.to_string()),
                            _ => None,
                        })
                    })
            })
        });
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let not_before = tbs.validity().not_before.to_unix_duration();
    let not_after = tbs.validity().not_after.to_unix_duration();
    let key_algorithm = key_algorithm_name(&tbs.subject_public_key_info().algorithm.oid);
    CertInfo {
        subject: tbs.subject().to_string(),
        issuer: tbs.issuer().to_string(),
        common_name: tbs
            .subject()
            .common_name()
            .ok()
            .flatten()
            .map(String::from)
            .unwrap_or_default(),
        email,
        organization: tbs
            .subject()
            .organization()
            .ok()
            .flatten()
            .map(String::from),
        serial: tbs.serial_number().to_string(),
        not_before: format_time(not_before.as_secs()),
        not_after: format_time(not_after.as_secs()),
        fingerprint: fingerprint(&der),
        key_algorithm: key_algorithm.to_string(),
        self_signed: tbs.subject() == tbs.issuer(),
        valid_now: now >= not_before && now <= not_after,
    }
}

pub fn key_algorithm_name(oid: &const_oid::ObjectIdentifier) -> &'static str {
    if *oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        "ECDSA"
    } else if *oid == const_oid::db::rfc5912::RSA_ENCRYPTION {
        "RSA"
    } else {
        "unknown"
    }
}

/// Unix seconds to `YYYY-MM-DD HH:MM:SS UTC`.
pub fn format_time(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

/// Unix seconds to the PDF date form `D:YYYYMMDDHHmmSSZ`.
pub fn pdf_date(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("D:{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z")
}

/// Days-from-civil inverse (Howard Hinnant's algorithm), no calendar crate needed.
pub fn civil(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

// ---------------------------------------------------------------------------
// Self-signed certificate profile
// ---------------------------------------------------------------------------

struct SelfSignedProfile {
    subject: Name,
    email: Option<String>,
}

impl BuilderProfile for SelfSignedProfile {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::certificate::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions: Vec<Extension> = Vec::new();
        extensions.push(
            (&BasicConstraints {
                ca: false,
                path_len_constraint: None,
            })
                .to_extension(&self.subject, &extensions)?,
        );
        extensions.push(
            (&KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation))
                .to_extension(&self.subject, &extensions)?,
        );
        let ski = Sha256::digest(spk.subject_public_key.raw_bytes());
        extensions.push(
            (&SubjectKeyIdentifier(OctetString::new(&ski[..20])?))
                .to_extension(&self.subject, &extensions)?,
        );
        if let Some(email) = &self.email {
            if let Ok(ia5) = Ia5String::new(email) {
                extensions.push(
                    (&SubjectAltName(vec![GeneralName::Rfc822Name(ia5)]))
                        .to_extension(&self.subject, &extensions)?,
                );
            }
        }
        Ok(extensions)
    }
}

/// Escape a value for use inside an RFC 4514 distinguished-name string.
fn dn_escape(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' | '#') {
            out.push('\\');
        }
        out.push(c);
    }
    out.trim().to_string()
}

fn subject_name(
    name: &str,
    organization: Option<&str>,
    country: Option<&str>,
) -> Result<Name, CertError> {
    let mut parts = vec![format!("CN={}", dn_escape(name))];
    if let Some(o) = organization.map(str::trim).filter(|o| !o.is_empty()) {
        parts.push(format!("O={}", dn_escape(o)));
    }
    if let Some(c) = country.map(str::trim).filter(|c| c.len() == 2) {
        parts.push(format!("C={}", c.to_ascii_uppercase()));
    }
    Name::from_str(&parts.join(",")).map_err(err("invalid name"))
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// What is written to `identities/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentity {
    id: String,
    name: String,
    email: Option<String>,
    organization: Option<String>,
    cert_pem: String,
    key_pem: String,
    created: u64,
    imported: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityInfo {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub organization: Option<String>,
    pub created: String,
    pub imported: bool,
    #[serde(flatten)]
    pub cert: CertInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustedInfo {
    #[serde(flatten)]
    pub cert: CertInfo,
    pub added: String,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Platform config directory, e.g. `~/.config/confidential_file_merger` on Linux,
    /// `~/Library/Application Support/confidential_file_merger` on macOS,
    /// `%APPDATA%\confidential_file_merger` on Windows.
    pub fn default_dir() -> PathBuf {
        if let Some(explicit) = std::env::var_os("CFM_DATA_DIR") {
            return PathBuf::from(explicit);
        }
        if cfg!(target_os = "windows") {
            if let Some(appdata) = std::env::var_os("APPDATA") {
                return PathBuf::from(appdata).join("confidential_file_merger");
            }
        } else if cfg!(target_os = "macos") {
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("confidential_file_merger");
            }
        } else if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("confidential_file_merger");
        } else if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".config")
                .join("confidential_file_merger");
        }
        PathBuf::from(".confidential_file_merger")
    }

    pub fn open(dir: impl AsRef<Path>) -> Result<Store, CertError> {
        let dir = dir.as_ref().to_path_buf();
        for sub in ["identities", "trusted"] {
            std::fs::create_dir_all(dir.join(sub))
                .map_err(err("could not create the data directory"))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(
                dir.join("identities"),
                std::fs::Permissions::from_mode(0o700),
            );
        }
        Ok(Store { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn identity_path(&self, id: &str) -> PathBuf {
        self.dir
            .join("identities")
            .join(format!("{}.json", safe_id(id)))
    }

    fn read_identity(&self, id: &str) -> Result<StoredIdentity, CertError> {
        let bytes = std::fs::read(self.identity_path(id))
            .map_err(|_| CertError(format!("no identity with id {id}")))?;
        serde_json::from_slice(&bytes).map_err(err("identity file is corrupt"))
    }

    fn write_identity(&self, identity: &StoredIdentity) -> Result<(), CertError> {
        let path = self.identity_path(&identity.id);
        let json =
            serde_json::to_vec_pretty(identity).map_err(err("could not serialise identity"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(err("could not create the identity folder"))?;
        }
        std::fs::write(&path, json).map_err(err("could not write identity"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<IdentityInfo> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(self.dir.join("identities")) {
            for entry in entries.flatten() {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    if let Ok(stored) = serde_json::from_slice::<StoredIdentity>(&bytes) {
                        if let Ok(cert) = Certificate::from_pem(stored.cert_pem.as_bytes()) {
                            out.push(IdentityInfo {
                                id: stored.id,
                                name: stored.name,
                                email: stored.email,
                                organization: stored.organization,
                                created: format_time(stored.created),
                                imported: stored.imported,
                                cert: cert_info(&cert),
                            });
                        }
                    }
                }
            }
        }
        out.sort_by(|a, b| a.created.cmp(&b.created));
        out
    }

    pub fn get(&self, id: &str) -> Result<IdentityInfo, CertError> {
        let stored = self.read_identity(id)?;
        let cert = Certificate::from_pem(stored.cert_pem.as_bytes())
            .map_err(err("stored certificate is invalid"))?;
        Ok(IdentityInfo {
            id: stored.id,
            name: stored.name,
            email: stored.email,
            organization: stored.organization,
            created: format_time(stored.created),
            imported: stored.imported,
            cert: cert_info(&cert),
        })
    }

    pub fn cert_pem(&self, id: &str) -> Result<String, CertError> {
        Ok(self.read_identity(id)?.cert_pem)
    }

    pub fn delete(&self, id: &str) -> Result<(), CertError> {
        std::fs::remove_file(self.identity_path(id))
            .map_err(|_| CertError(format!("no identity with id {id}")))
    }

    /// Generate a new ECDSA P-256 key and a self-signed certificate.
    pub fn create(
        &self,
        name: &str,
        email: Option<&str>,
        organization: Option<&str>,
        country: Option<&str>,
        passphrase: &str,
        valid_days: u32,
    ) -> Result<IdentityInfo, CertError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(CertError("a name is required".into()));
        }
        if passphrase.len() < 4 {
            return Err(CertError(
                "the passphrase must be at least 4 characters".into(),
            ));
        }
        let email = email
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(str::to_string);
        #[allow(deprecated)]
        let secret = p256::SecretKey::random(&mut rand::rng());
        let key = PrivateKey::P256(EcSigningKey::from(&secret));
        let cert = self_signed_certificate(
            &key,
            name,
            email.as_deref(),
            organization,
            country,
            valid_days,
        )?;
        self.store_new(name, email, organization, &cert, &key, passphrase, false)
    }

    /// Import an existing certificate and private key (PEM). `key_passphrase` unlocks an
    /// encrypted key; `passphrase` protects the stored copy.
    pub fn import(
        &self,
        cert_pem: &str,
        key_pem: &str,
        key_passphrase: Option<&str>,
        passphrase: &str,
    ) -> Result<IdentityInfo, CertError> {
        if passphrase.len() < 4 {
            return Err(CertError(
                "the passphrase must be at least 4 characters".into(),
            ));
        }
        let cert = Certificate::from_pem(cert_pem.as_bytes())
            .map_err(err("the certificate is not valid PEM"))?;
        let key = PrivateKey::from_pem(key_pem, key_passphrase)?;
        // The key must match the certificate.
        let cert_spki = cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(err("certificate key"))?;
        if cert_spki != key.public_key_der()? {
            return Err(CertError(
                "the private key does not belong to this certificate".into(),
            ));
        }
        let info = cert_info(&cert);
        let name = if info.common_name.is_empty() {
            "Imported identity".to_string()
        } else {
            info.common_name.clone()
        };
        self.store_new(
            &name,
            info.email.clone(),
            info.organization.as_deref(),
            &cert,
            &key,
            passphrase,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn store_new(
        &self,
        name: &str,
        email: Option<String>,
        organization: Option<&str>,
        cert: &Certificate,
        key: &PrivateKey,
        passphrase: &str,
        imported: bool,
    ) -> Result<IdentityInfo, CertError> {
        let der = cert.to_der().map_err(err("certificate"))?;
        let fp = fingerprint(&der);
        let id = fp.replace(':', "").to_ascii_lowercase()[..16].to_string();
        let stored = StoredIdentity {
            id: id.clone(),
            name: name.to_string(),
            email,
            organization: organization
                .map(str::trim)
                .filter(|o| !o.is_empty())
                .map(str::to_string),
            cert_pem: cert.to_pem(LineEnding::LF).map_err(err("certificate"))?,
            key_pem: key.to_encrypted_pem(passphrase)?,
            created: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            imported,
        };
        self.write_identity(&stored)?;
        self.get(&id)
    }

    /// Decrypt the key with the passphrase and return something that can sign.
    pub fn unlock(&self, id: &str, passphrase: &str) -> Result<Signer, CertError> {
        let stored = self.read_identity(id)?;
        let certificate = Certificate::from_pem(stored.cert_pem.as_bytes())
            .map_err(err("stored certificate is invalid"))?;
        let key = PrivateKey::from_pem(&stored.key_pem, Some(passphrase))
            .map_err(|_| CertError("wrong passphrase".into()))?;
        let info = cert_info(&certificate);
        Ok(Signer {
            certificate,
            key,
            info,
        })
    }

    /// A certificate signing request for this identity's key, to hand to a real CA.
    pub fn csr_pem(&self, id: &str, passphrase: &str) -> Result<String, CertError> {
        let signer = self.unlock(id, passphrase)?;
        let subject = signer.certificate.tbs_certificate().subject().clone();
        let mut builder =
            RequestBuilder::new(subject).map_err(err("could not start the request"))?;
        if let Some(email) = &signer.info.email {
            if let Ok(ia5) = Ia5String::new(email) {
                let _ = builder.add_extension(&SubjectAltName(vec![GeneralName::Rfc822Name(ia5)]));
            }
        }
        let pem = match &signer.key {
            PrivateKey::P256(k) => builder
                .build::<_, DerSignature>(k)
                .map_err(err("could not sign the request"))?
                .to_pem(LineEnding::LF),
            PrivateKey::Rsa(k) => builder
                .build::<_, rsa::pkcs1v15::Signature>(k)
                .map_err(err("could not sign the request"))?
                .to_pem(LineEnding::LF),
        }
        .map_err(err("could not encode the request"))?;
        Ok(pem)
    }

    /// Replace the certificate of an identity with one issued by a CA for the same key.
    pub fn install_certificate(
        &self,
        id: &str,
        cert_pem: &str,
        passphrase: &str,
    ) -> Result<IdentityInfo, CertError> {
        let signer = self.unlock(id, passphrase)?;
        let cert = Certificate::from_pem(cert_pem.as_bytes())
            .map_err(err("the certificate is not valid PEM"))?;
        let cert_spki = cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(err("certificate key"))?;
        if cert_spki != signer.key.public_key_der()? {
            return Err(CertError(
                "this certificate was issued for a different key".into(),
            ));
        }
        let mut stored = self.read_identity(id)?;
        stored.cert_pem = cert.to_pem(LineEnding::LF).map_err(err("certificate"))?;
        stored.imported = true;
        self.write_identity(&stored)?;
        self.get(id)
    }

    // ----- trust store -----

    fn trusted_path(&self, fingerprint: &str) -> PathBuf {
        // Only hex survives, so a fingerprint that arrived from an HTTP path cannot
        // escape the folder.
        let name: String = fingerprint
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .take(64)
            .collect::<String>()
            .to_ascii_lowercase();
        self.dir.join("trusted").join(format!("{name}.pem"))
    }

    pub fn trusted(&self) -> Vec<TrustedInfo> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(self.dir.join("trusted")) {
            for entry in entries.flatten() {
                if let Ok(pem) = std::fs::read(entry.path()) {
                    if let Ok(cert) = Certificate::from_pem(&pem) {
                        let added = entry
                            .metadata()
                            .and_then(|m| m.modified())
                            .ok()
                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                            .map(|d| format_time(d.as_secs()))
                            .unwrap_or_default();
                        out.push(TrustedInfo {
                            cert: cert_info(&cert),
                            added,
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| a.cert.subject.cmp(&b.cert.subject));
        out
    }

    pub fn add_trusted(&self, cert_pem: &str) -> Result<TrustedInfo, CertError> {
        let cert = Certificate::from_pem(cert_pem.as_bytes())
            .map_err(err("the certificate is not valid PEM"))?;
        let info = cert_info(&cert);
        let pem = cert.to_pem(LineEnding::LF).map_err(err("certificate"))?;
        let path = self.trusted_path(&info.fingerprint);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(err("could not create the trust folder"))?;
        }
        std::fs::write(&path, pem).map_err(err("could not write the trust store"))?;
        Ok(TrustedInfo {
            cert: info,
            added: format_time(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        })
    }

    pub fn remove_trusted(&self, fingerprint: &str) -> Result<(), CertError> {
        std::fs::remove_file(self.trusted_path(fingerprint))
            .map_err(|_| CertError("no such trusted certificate".into()))
    }

    /// All certificates we trust: our own identities plus the trust store.
    pub fn trust_anchors(&self) -> Vec<Certificate> {
        let mut anchors = Vec::new();
        for id in self.list() {
            if let Ok(pem) = self.cert_pem(&id.id) {
                if let Ok(cert) = Certificate::from_pem(pem.as_bytes()) {
                    anchors.push(cert);
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(self.dir.join("trusted")) {
            for entry in entries.flatten() {
                if let Ok(pem) = std::fs::read(entry.path()) {
                    if let Ok(cert) = Certificate::from_pem(&pem) {
                        anchors.push(cert);
                    }
                }
            }
        }
        anchors
    }
}

/// Identity ids are hex, so stripping everything else keeps a file name inside the folder
/// even when the id came straight from an HTTP path.
fn safe_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(32)
        .collect()
}

fn self_signed_certificate(
    key: &PrivateKey,
    name: &str,
    email: Option<&str>,
    organization: Option<&str>,
    country: Option<&str>,
    valid_days: u32,
) -> Result<Certificate, CertError> {
    let subject = subject_name(name, organization, country)?;
    let profile = SelfSignedProfile {
        subject,
        email: email.map(str::to_string),
    };
    let mut serial_bytes = [0u8; 16];
    rand::fill(&mut serial_bytes);
    serial_bytes[0] &= 0x7F; // keep it positive
    let serial = SerialNumber::new(&serial_bytes).map_err(err("serial number"))?;
    let validity = Validity::from_now(Duration::from_secs(
        u64::from(valid_days.clamp(1, 36_500)) * 86_400,
    ))
    .map_err(err("validity"))?;
    let spki =
        SubjectPublicKeyInfoOwned::from_der(&key.public_key_der()?).map_err(err("public key"))?;
    let builder = CertificateBuilder::new(profile, serial, validity, spki)
        .map_err(err("could not start the certificate"))?;
    match key {
        PrivateKey::P256(k) => builder.build::<_, DerSignature>(k),
        PrivateKey::Rsa(k) => builder.build::<_, rsa::pkcs1v15::Signature>(k),
    }
    .map_err(err("could not sign the certificate"))
}

/// Verify that `cert` was signed by `issuer`'s key (one link of a chain).
pub fn verify_issued_by(cert: &Certificate, issuer: &Certificate) -> bool {
    if cert.tbs_certificate().issuer() != issuer.tbs_certificate().subject() {
        return false;
    }
    let Ok(tbs) = cert.tbs_certificate().to_der() else {
        return false;
    };
    let Some(signature) = cert.signature().as_bytes() else {
        return false;
    };
    verify_signature(
        issuer.tbs_certificate().subject_public_key_info(),
        &cert.signature_algorithm().oid,
        &tbs,
        signature,
    )
}

/// Verify `signature` over `message` with the key in `spki`. Supports ECDSA P-256 and RSA
/// PKCS#1 v1.5, both with SHA-256 (the algorithms this tool produces and the common ones
/// found in the wild). Returns false for anything else.
pub fn verify_signature(
    spki: &SubjectPublicKeyInfoOwned,
    signature_algorithm: &const_oid::ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
) -> bool {
    use signature::Verifier;
    let Ok(spki_der) = spki.to_der() else {
        return false;
    };
    let key_oid = spki.algorithm.oid;
    if key_oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        use p256::pkcs8::DecodePublicKey;
        if *signature_algorithm != const_oid::db::rfc5912::ECDSA_WITH_SHA_256 {
            return false;
        }
        let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der) else {
            return false;
        };
        let Ok(sig) = DerSignature::from_bytes(signature) else {
            return false;
        };
        return key.verify(message, &sig).is_ok();
    }
    if key_oid == const_oid::db::rfc5912::RSA_ENCRYPTION {
        if *signature_algorithm != const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
            return false;
        }
        let Ok(spki_ref) = spki::SubjectPublicKeyInfoRef::from_der(&spki_der) else {
            return false;
        };
        let Ok(public) = rsa::RsaPublicKey::try_from(spki_ref) else {
            return false;
        };
        let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public);
        let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature) else {
            return false;
        };
        return key.verify(message, &sig).is_ok();
    }
    false
}

/// Is this certificate trusted: one of the anchors, or issued by one of them?
pub fn is_trusted(cert: &Certificate, anchors: &[Certificate]) -> bool {
    let Ok(der) = cert.to_der() else {
        return false;
    };
    let fp = fingerprint(&der);
    for anchor in anchors {
        if anchor
            .to_der()
            .map(|d| fingerprint(&d) == fp)
            .unwrap_or(false)
        {
            return true;
        }
        if verify_issued_by(cert, anchor) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> Store {
        let dir = std::env::temp_dir().join(format!("cfm-certs-{}", rand::random::<u64>()));
        Store::open(dir).unwrap()
    }

    #[test]
    fn creates_lists_unlocks_and_deletes_an_identity() {
        let store = temp_store();
        let info = store
            .create(
                "Ana Müller",
                Some("ana@example.org"),
                Some("Acme, Inc."),
                Some("de"),
                "pass1234",
                365,
            )
            .unwrap();
        assert_eq!(info.cert.common_name, "Ana Müller");
        assert_eq!(info.cert.email.as_deref(), Some("ana@example.org"));
        assert!(info.cert.self_signed && info.cert.valid_now);
        assert_eq!(info.cert.key_algorithm, "ECDSA");
        assert!(
            info.cert.subject.contains("O=Acme\\, Inc.")
                || info.cert.subject.contains("Acme, Inc.")
        );
        assert_eq!(store.list().len(), 1);
        assert!(store.unlock(&info.id, "wrong").is_err());
        let signer = store.unlock(&info.id, "pass1234").unwrap();
        assert_eq!(signer.info.key_algorithm, "ECDSA");
        assert!(store
            .cert_pem(&info.id)
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----"));
        // Certificate verifies with its own key: self-signed.
        assert!(verify_issued_by(&signer.certificate, &signer.certificate));
        // CSR can be produced for the same key.
        let csr = store.csr_pem(&info.id, "pass1234").unwrap();
        assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));
        store.delete(&info.id).unwrap();
        assert!(store.list().is_empty());
    }

    #[test]
    fn stored_key_is_encrypted_on_disk() {
        let store = temp_store();
        let info = store
            .create("Bob", None, None, None, "hunter2", 30)
            .unwrap();
        let raw = std::fs::read_to_string(
            store
                .dir()
                .join("identities")
                .join(format!("{}.json", info.id)),
        )
        .unwrap();
        assert!(raw.contains("BEGIN ENCRYPTED PRIVATE KEY"));
        assert!(!raw.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn import_roundtrip_and_key_mismatch_detection() {
        let store = temp_store();
        let a = store.create("A", None, None, None, "pw-a", 30).unwrap();
        let b = store.create("B", None, None, None, "pw-b", 30).unwrap();
        let a_cert = store.cert_pem(&a.id).unwrap();
        // Export A's key as plain PKCS#8 and re-import it under a new passphrase.
        let signer = store.unlock(&a.id, "pw-a").unwrap();
        let PrivateKey::P256(k) = &signer.key else {
            panic!()
        };
        let plain = k.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let imported = store.import(&a_cert, &plain, None, "new-pass").unwrap();
        assert_eq!(imported.cert.fingerprint, a.cert.fingerprint);
        assert!(imported.imported);
        // B's certificate with A's key must be refused.
        let b_cert = store.cert_pem(&b.id).unwrap();
        assert!(store
            .import(&b_cert, &plain, None, "x1234")
            .unwrap_err()
            .0
            .contains("does not belong"));
    }

    #[test]
    fn trust_store_and_chain_check() {
        let store = temp_store();
        let me = store.create("Me", None, None, None, "pw123", 30).unwrap();
        let other = temp_store();
        let them = other.create("Them", None, None, None, "pw123", 30).unwrap();
        let their_cert =
            Certificate::from_pem(other.cert_pem(&them.id).unwrap().as_bytes()).unwrap();
        let my_cert = Certificate::from_pem(store.cert_pem(&me.id).unwrap().as_bytes()).unwrap();
        assert!(is_trusted(&my_cert, &store.trust_anchors()));
        assert!(!is_trusted(&their_cert, &store.trust_anchors()));
        store
            .add_trusted(&other.cert_pem(&them.id).unwrap())
            .unwrap();
        assert_eq!(store.trusted().len(), 1);
        assert!(is_trusted(&their_cert, &store.trust_anchors()));
        store.remove_trusted(&them.cert.fingerprint).unwrap();
        assert!(store.trusted().is_empty());
    }

    #[test]
    fn store_file_names_cannot_escape_the_data_folder() {
        let store = temp_store();
        let outside = store.dir().parent().unwrap().join("victim.pem");
        std::fs::write(&outside, "keep me").unwrap();
        // A fingerprint or id that arrived from an HTTP path must stay inside the folder.
        assert!(store.remove_trusted("../victim").is_err());
        assert!(store.remove_trusted("%2e%2e%2fvictim").is_err());
        assert!(store.delete("../../etc/passwd").is_err());
        assert!(outside.exists(), "a path outside the store was touched");
        assert!(store
            .trusted_path("../victim")
            .starts_with(store.dir().join("trusted")));
        assert!(store
            .identity_path("../victim")
            .starts_with(store.dir().join("identities")));
        std::fs::remove_file(outside).ok();
    }

    #[test]
    fn dates_format_correctly() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_time(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(pdf_date(951_782_400), "D:20000229000000Z");
    }
}
