//! HTTPS trust modes for proxied services (M4b). Key material lives in an owner-only
//! directory beside the configuration and is never printed, exported, or sent anywhere:
//! the local CA key signs on this host, and ACME keys only produce signatures.

pub mod acme;
pub mod manager;

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints,
    PKCS_ECDSA_P256_SHA256,
};

/// Local CA certificates last ten years; service certificates 90 days.
const CA_DAYS: i64 = 3_650;
pub const LEAF_DAYS: i64 = 90;

/// Directory holding keys and certificates for a configuration.
pub fn directory(config: &Path) -> PathBuf {
    config.with_extension("tls")
}

pub fn ca_certificate_path(config: &Path) -> PathBuf {
    directory(config).join("ca.crt")
}

fn ca_key_path(config: &Path) -> PathBuf {
    directory(config).join("ca.key")
}

pub fn certificate_paths(config: &Path, name: &str) -> (PathBuf, PathBuf) {
    let base = directory(config)
        .join("certs")
        .join(name.trim_end_matches('.'));
    (base.with_extension("crt"), base.with_extension("key"))
}

/// Create `path`'s directory as owner-only.
fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write atomically. Secrets are owner-only from creation: temporary files are 0600.
pub fn write_file(path: &Path, contents: &[u8], secret: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    private_directory(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".localname-")
        .suffix(".tmp")
        .tempfile_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    #[cfg(unix)]
    if !secret {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
    }
    #[cfg(not(unix))]
    let _ = secret;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// A zone-constrained CA: browsers and operating systems refuse certificates it signs for
/// any name outside the zone, so trusting it cannot vouch for public sites.
pub struct LocalCa {
    pub certificate_pem: String,
    key_pem: String,
}

impl LocalCa {
    pub fn exists(config: &Path) -> bool {
        ca_certificate_path(config).exists() && ca_key_path(config).exists()
    }

    pub fn create(zone: &str) -> Result<Self> {
        let zone = zone.trim_end_matches('.');
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, format!("localname CA for {zone}"));
        name.push(DnType::OrganizationName, "localname");
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName(zone.to_owned())],
            excluded_subtrees: Vec::new(),
        });
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(CA_DAYS);
        let certificate = params.self_signed(&key)?;
        Ok(Self {
            certificate_pem: certificate.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    pub fn save(&self, config: &Path) -> Result<()> {
        write_file(&ca_key_path(config), self.key_pem.as_bytes(), true)?;
        write_file(
            &ca_certificate_path(config),
            self.certificate_pem.as_bytes(),
            false,
        )
    }

    pub fn load(config: &Path) -> Result<Self> {
        Ok(Self {
            certificate_pem: fs::read_to_string(ca_certificate_path(config))
                .context("failed to read the local CA certificate")?,
            key_pem: fs::read_to_string(ca_key_path(config))
                .context("failed to read the local CA key")?,
        })
    }

    /// Sign a service certificate on this host. Returns (chain PEM, key PEM).
    pub fn issue(&self, name: &str) -> Result<(String, String)> {
        self.issue_for_days(name, LEAF_DAYS)
    }

    /// Sign a certificate valid for `days`; renewal tests use short lifetimes.
    pub fn issue_for_days(&self, name: &str, days: i64) -> Result<(String, String)> {
        let ca_key = KeyPair::from_pem(&self.key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&self.certificate_pem, ca_key)?;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let host = name.trim_end_matches('.');
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(days);
        let certificate = params.signed_by(&key, &issuer)?;
        Ok((
            format!("{}{}", certificate.pem(), self.certificate_pem),
            key.serialize_pem(),
        ))
    }
}

/// Remove all key material for a configuration.
pub fn remove_material(config: &Path) -> Result<()> {
    let directory = directory(config);
    if directory.exists() {
        fs::remove_dir_all(&directory)
            .with_context(|| format!("failed to remove {}", directory.display()))?;
    }
    Ok(())
}

/// Facts about the first certificate in a PEM chain.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_after_unix: i64,
    pub sha256: String,
    pub names: Vec<String>,
}

impl CertificateInfo {
    pub fn remaining(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        u64::try_from(self.not_after_unix)
            .ok()
            .and_then(|end| end.checked_sub(now))
            .map_or(Duration::ZERO, Duration::from_secs)
    }

    pub fn needs_renewal(&self, renew_before_days: u32) -> bool {
        self.remaining() < Duration::from_secs(u64::from(renew_before_days) * 86_400)
    }
}

pub fn inspect(chain_pem: &str) -> Result<CertificateInfo> {
    let der = rustls_pemfile::certs(&mut chain_pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow!("no certificate in PEM"))??;
    inspect_der(&der)
}

pub fn inspect_der(der: &[u8]) -> Result<CertificateInfo> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| anyhow!("invalid certificate: {error}"))?;
    let names = certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(name) => Some((*name).to_owned()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(CertificateInfo {
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        not_after_unix: certificate.validity().not_after.timestamp(),
        sha256: fingerprint(der),
        names,
    })
}

/// SHA-256 fingerprint as colon-separated hex, the form trust dialogs display.
pub fn fingerprint(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Load a certificate chain and key into a rustls signing key.
pub fn certified_key(chain_pem: &str, key_pem: &str) -> Result<rustls::sign::CertifiedKey> {
    let chain = rustls_pemfile::certs(&mut chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() {
        bail!("certificate chain is empty");
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow!("no private key in PEM"))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)?;
    Ok(rustls::sign::CertifiedKey::new(chain, signing))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ca_signs_zone_names_with_constraints() {
        let ca = LocalCa::create("home.arpa.").unwrap();
        let info = inspect(&ca.certificate_pem).unwrap();
        assert!(info.subject.contains("localname CA for home.arpa"));
        assert!(!info.needs_renewal(30));
        let der = rustls_pemfile::certs(&mut ca.certificate_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let constraints = parsed.name_constraints().unwrap().unwrap().value.clone();
        assert_eq!(
            format!("{:?}", constraints.permitted_subtrees.unwrap()[0].base),
            "DNSName(\"home.arpa\")"
        );
        assert!(parsed.is_ca());

        let (chain, key) = ca.issue("photos.home.arpa.").unwrap();
        let leaf = inspect(&chain).unwrap();
        assert_eq!(leaf.names, ["photos.home.arpa"]);
        assert_eq!(leaf.issuer, info.subject);
        assert!(leaf.remaining() > Duration::from_secs(89 * 86_400));
        assert!(leaf.needs_renewal(91));
        certified_key(&chain, &key).unwrap();
        assert_eq!(info.sha256.len(), 95);
    }

    #[test]
    fn secrets_are_owner_only() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        let ca = LocalCa::create("home.arpa.").unwrap();
        ca.save(&config).unwrap();
        assert!(LocalCa::exists(&config));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&ca_key_path(&config)), 0o600);
            assert_eq!(mode(&ca_certificate_path(&config)), 0o644);
            assert_eq!(mode(&self::directory(&config)), 0o700);
        }
        let loaded = LocalCa::load(&config).unwrap();
        assert_eq!(loaded.certificate_pem, ca.certificate_pem);
        remove_material(&config).unwrap();
        assert!(!self::directory(&config).exists());
    }
}
