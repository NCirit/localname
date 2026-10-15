//! `localname https`: explicit HTTPS trust modes for proxied services (M4b).
//! Nothing here changes a trust store without an explicit, confirmed `https trust install`,
//! and no command outputs private key material.

use std::{
    fmt::Write as _,
    io::{BufRead, IsTerminal, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{check_revision, print_result, rollback_command};
use crate::{
    Config, ConfigStore,
    config::{HttpsConfig, HttpsMode, LETS_ENCRYPT},
    control::{self, Request},
    error::{ErrorCode, coded},
    output::{Envelope, OutputFormat},
    tls::{self, LocalCa},
};

#[derive(Debug, Subcommand)]
pub enum HttpsCommand {
    /// Show the changes that enable HTTPS, without making them.
    Plan(PlanArgs),
    /// Enable HTTPS (the service must be stopped; start it afterwards).
    Apply(ApplyArgs),
    /// Show the mode, certificates, and trust state.
    Status,
    /// Connect to each HTTPS service and check its certificate chain.
    Verify(VerifyArgs),
    /// Renew every certificate now (the service must be running).
    Renew,
    /// Print the local CA's public certificate to install on other devices.
    CaCert(CaCertArgs),
    /// Add or remove the local CA in this host's trust store, after confirmation.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    /// Undo `https apply`: restore the previous configuration and delete created keys.
    Rollback(DryRunArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Mode {
    LocalCa,
    AcmeDns01,
}

#[derive(Debug, Args)]
pub struct PlanArgs {
    #[arg(long, value_enum)]
    mode: Mode,
    /// HTTPS addresses (repeatable). Defaults to port 443 on each proxy address.
    #[arg(long)]
    listen: Vec<SocketAddr>,
    /// Services to serve over HTTPS (repeatable). Defaults to every service.
    #[arg(long = "service")]
    services: Vec<String>,
    #[arg(long, default_value_t = 30)]
    renew_before_days: u32,
    /// ACME directory URL (acme-dns01). Defaults to Let's Encrypt.
    #[arg(long)]
    acme_directory: Option<String>,
    /// Contact URI registered with the ACME CA, such as mailto:you@example.com.
    #[arg(long)]
    acme_contact: Option<String>,
    /// PEM roots for a private ACME server's HTTPS endpoint.
    #[arg(long)]
    acme_ca_bundle: Option<PathBuf>,
    /// Program that publishes DNS-01 TXT records: `HOOK set|clear NAME VALUE`.
    #[arg(long)]
    dns01_hook: Option<PathBuf>,
    #[arg(long, default_value_t = 30)]
    dns01_wait_seconds: u64,
    /// Accept the ACME CA's terms of service.
    #[arg(long)]
    agree_tos: bool,
}

#[derive(Debug, Args)]
pub struct ApplyArgs {
    #[command(flatten)]
    plan: PlanArgs,
    #[arg(long)]
    expect_revision: Option<u64>,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// PEM roots to verify against (default: the local CA, or the system's roots for ACME).
    #[arg(long)]
    ca_file: Option<PathBuf>,
    /// Keep retrying for this long while certificates are being issued.
    #[arg(long, default_value_t = 60)]
    timeout_seconds: u64,
}

#[derive(Debug, Args)]
pub struct CaCertArgs {
    /// Write the certificate to this file instead of printing it.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    /// Add the local CA to this host's trust store.
    Install(ConfirmArgs),
    /// Remove the local CA from this host's trust store.
    Remove(ConfirmArgs),
}

#[derive(Debug, Args)]
pub struct ConfirmArgs {
    /// Show the exact change without making it.
    #[arg(long)]
    dry_run: bool,
    /// Confirm the change non-interactively, after reviewing it with --dry-run.
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Args)]
pub struct DryRunArgs {
    #[arg(long)]
    dry_run: bool,
}

#[derive(Clone, Copy)]
enum Stage {
    Plan,
    /// Apply, optionally only at this configuration revision.
    Apply(Option<u64>),
}

/// What `https apply` changed, so rollback can undo exactly that.
#[derive(Debug, Serialize, Deserialize)]
struct HttpsRecord {
    version: u32,
    previous_revision: u64,
    revision: u64,
    created_ca: bool,
    /// The key directory did not exist before apply, so rollback deletes it entirely
    /// (CA, certificates, ACME account).
    #[serde(default)]
    created_key_directory: bool,
}

/// A trust-store change made by `https trust install`.
#[derive(Debug, Serialize, Deserialize)]
struct TrustRecord {
    version: u32,
    store: String,
    location: String,
    sha256: String,
    sha1: String,
}

fn record_path(store: &ConfigStore) -> PathBuf {
    store.path().with_extension("https.json")
}

fn trust_path(store: &ConfigStore) -> PathBuf {
    store.path().with_extension("trust.json")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            Ok(Some(serde_json::from_str(&text).with_context(|| {
                format!("failed to parse {}", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub async fn run(
    output: OutputFormat,
    non_interactive: bool,
    store: &ConfigStore,
    command: HttpsCommand,
) -> Result<()> {
    match command {
        HttpsCommand::Plan(args) => plan(output, store, &args, Stage::Plan),
        HttpsCommand::Apply(args) => plan(
            output,
            store,
            &args.plan,
            Stage::Apply(args.expect_revision),
        ),
        HttpsCommand::Status => status(output, store),
        HttpsCommand::Verify(args) => verify(output, store, &args).await,
        HttpsCommand::Renew => renew(output, store).await,
        HttpsCommand::CaCert(args) => ca_cert(output, store, &args),
        HttpsCommand::Trust { command } => trust(output, non_interactive, store, &command),
        HttpsCommand::Rollback(args) => rollback(output, store, &args),
    }
}

fn candidate(current: &Config, args: &PlanArgs) -> Result<Config> {
    let mut next = current.clone();
    let listen = if args.listen.is_empty() {
        current
            .proxy_listen
            .iter()
            .map(|address| SocketAddr::new(address.ip(), 443))
            .collect()
    } else {
        args.listen.clone()
    };
    next.https = Some(HttpsConfig {
        mode: match args.mode {
            Mode::LocalCa => HttpsMode::LocalCa,
            Mode::AcmeDns01 => HttpsMode::AcmeDns01,
        },
        listen,
        renew_before_days: args.renew_before_days,
        acme_directory: args.acme_directory.clone(),
        acme_contact: args.acme_contact.clone(),
        acme_ca_bundle: args.acme_ca_bundle.clone(),
        acme_terms_agreed: args.agree_tos,
        dns01_hook: args.dns01_hook.clone(),
        dns01_wait_seconds: args.dns01_wait_seconds,
    });
    let selected: Vec<String> = args
        .services
        .iter()
        .map(|name| current.fqdn(name))
        .collect::<Result<_>>()?;
    for name in &selected {
        if !current.services.iter().any(|service| &service.name == name) {
            return Err(coded(
                ErrorCode::InvalidInput,
                format!("invalid service: {name} is not a service"),
            ));
        }
    }
    for service in &mut next.services {
        service.https = selected.is_empty() || selected.contains(&service.name);
    }
    next.validate()?;
    Ok(next)
}

#[allow(clippy::too_many_lines)]
fn plan(output: OutputFormat, store: &ConfigStore, args: &PlanArgs, stage: Stage) -> Result<()> {
    let current = store.load()?;
    if let Stage::Apply(expected) = stage {
        check_revision(expected, current.revision)?;
    }
    let next = candidate(&current, args)?;
    let https = next.https.clone().expect("candidate sets https");
    let names: Vec<String> = next
        .services
        .iter()
        .filter(|service| service.https)
        .map(|service| service.name.trim_end_matches('.').to_owned())
        .collect();
    let path = store.path();
    let create_ca = https.mode == HttpsMode::LocalCa && !LocalCa::exists(path);
    let mut steps = Vec::new();
    match https.mode {
        HttpsMode::LocalCa => {
            if create_ca {
                steps.push(format!(
                    "Create a CA on this host, limited to names under {} (its key stays in {}, readable only by {}).",
                    next.zone.trim_end_matches('.'),
                    tls::directory(path).display(),
                    if cfg!(unix) { "the account that owns the configuration" } else { "your Windows account (profile permissions)" }
                ));
            }
            steps.push(format!(
                "Issue 90-day certificates for {} on this host; renew {} days before expiry.",
                names.join(", "),
                https.renew_before_days
            ));
            steps.push("No trust store is changed. Browsers warn until you trust the CA: `localname https trust install` on this host, and `localname https ca-cert` for other devices.".into());
        }
        HttpsMode::AcmeDns01 => {
            let directory = https
                .acme_directory
                .clone()
                .unwrap_or_else(|| LETS_ENCRYPT.into());
            steps.push(format!(
                "Register with {directory}, accepting its terms of service (--agree-tos)."
            ));
            steps.push(format!(
                "For each of {}, run `{} set _acme-challenge.NAME VALUE`, wait {} s, and remove the record afterwards with `clear`.",
                names.join(", "),
                https.dns01_hook.as_ref().map_or_else(String::new, |hook| hook.display().to_string()),
                https.dns01_wait_seconds
            ));
            steps.push("Certificate keys are generated on this host; only signing requests are sent. No trust store is changed.".into());
        }
    }
    steps.push(format!(
        "Serve HTTPS on {}; plain HTTP requests for these services redirect to HTTPS.",
        https
            .listen
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let mut data = json!({
        "mode": https.mode,
        "listen": https.listen,
        "services": names,
        "creates_ca": create_ca,
        "key_directory": tls::directory(path),
        "trust_store_changes": [],
        "steps": steps,
        "config_path": path,
    });
    let Stage::Apply(expected) = stage else {
        let human = format!(
            "HTTPS plan:\n  {}\nRun `localname https apply` with the same options to make these changes.",
            steps.join("\n  ")
        );
        let mut envelope =
            Envelope::success("https plan", next != current, Some(current.revision), data);
        envelope.next_actions = vec![
            "Stop the service, run `localname https apply` with the same options, then start it."
                .into(),
        ];
        return print_result(output, envelope, || human);
    };
    if control::send_if_running(store, &Request::Status)?.is_some() {
        return Err(coded(
            ErrorCode::Conflict,
            "conflict: enabling HTTPS adds listeners and needs a restart; stop the localname service, run this again, then start it",
        ));
    }
    let _guard = store.acquire_offline_lock()?;
    let created_key_directory = !tls::directory(path).exists();
    if create_ca {
        LocalCa::create(&next.zone)?.save(path)?;
    }
    let committed = store.mutate(expected, |config| {
        config.https.clone_from(&next.https);
        config.services.clone_from(&next.services);
        Ok(())
    });
    let (previous, committed) = match committed {
        Ok(result) => result,
        Err(error) => {
            if created_key_directory {
                let _ = tls::remove_material(path);
            }
            return Err(error);
        }
    };
    let record = HttpsRecord {
        version: 1,
        previous_revision: previous.revision,
        revision: committed.revision,
        created_ca: create_ca,
        created_key_directory,
    };
    tls::write_file(
        &record_path(store),
        serde_json::to_string_pretty(&record)?.as_bytes(),
        false,
    )?;
    data["applied"] = json!(true);
    let mut envelope = Envelope::success("https apply", true, Some(committed.revision), data);
    envelope.verification = Some(json!({"status": "not_running", "scope": "configuration_only"}));
    envelope.rollback =
        Some(super::rollback_command(store.path(), 0).replace(" rollback 0", " https rollback"));
    envelope.next_actions =
        vec!["Start the localname service, then run `localname https verify`.".into()];
    if https.mode == HttpsMode::LocalCa {
        envelope.next_actions.push("Trust the CA where needed: `localname https trust install` (this host) and `localname https ca-cert` (other devices).".into());
    }
    print_result(output, envelope, || {
        "HTTPS configured. Start the service, then run `localname https verify`.".into()
    })
}

fn daemon_certificates(store: &ConfigStore) -> Option<Vec<control::CertStatus>> {
    control::send_if_running(store, &Request::Status)
        .ok()
        .flatten()
        .and_then(|response| response.status)
        .and_then(|status| status.certificates)
}

fn status(output: OutputFormat, store: &ConfigStore) -> Result<()> {
    let config = store.load()?;
    let trust: Option<TrustRecord> = read_json(&trust_path(store))?;
    let certificates = daemon_certificates(store);
    let human = match &config.https {
        None => "HTTPS is off.".to_owned(),
        Some(https) => {
            let mut lines = vec![format!("HTTPS mode {:?} on {:?}", https.mode, https.listen)];
            for certificate in certificates.iter().flatten() {
                lines.push(match (&certificate.certificate, &certificate.last_error) {
                    (_, Some(error)) => format!("✗ {}: {error}", certificate.name),
                    (Some(info), None) => format!(
                        "✓ {} valid for {} more days",
                        certificate.name.trim_end_matches('.'),
                        info.remaining().as_secs() / 86_400
                    ),
                    (None, None) => format!("· {}: not issued yet", certificate.name),
                });
            }
            if let Some(trust) = &trust {
                lines.push(format!(
                    "Local CA trusted in {} ({})",
                    trust.store, trust.location
                ));
            }
            lines.join("\n")
        }
    };
    let data = json!({"https": config.https, "certificates": certificates, "trust": trust});
    print_result(
        output,
        Envelope::success("https status", false, Some(config.revision), data),
        || human,
    )
}

fn roots(
    store: &ConfigStore,
    config: &Config,
    ca_file: Option<&Path>,
) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    let path = match (ca_file, config.https.as_ref().map(|https| https.mode)) {
        (Some(path), _) => Some(path.to_path_buf()),
        (None, Some(HttpsMode::LocalCa)) => Some(tls::ca_certificate_path(store.path())),
        _ => None,
    };
    match path {
        Some(path) => {
            let pem = std::fs::read(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
                roots.add(certificate?)?;
            }
        }
        None => {
            for certificate in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(certificate);
            }
        }
    }
    Ok(roots)
}

/// TLS handshake with SNI `name`, then one HTTP request; returns the leaf and HTTP status.
async fn probe(
    connector: &tokio_rustls::TlsConnector,
    address: SocketAddr,
    name: &str,
) -> Result<(tls::CertificateInfo, String)> {
    let stream = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(address),
    )
    .await??;
    let server = rustls::pki_types::ServerName::try_from(name.to_owned())?;
    let mut stream =
        tokio::time::timeout(Duration::from_secs(5), connector.connect(server, stream)).await??;
    let leaf = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or_else(|| anyhow!("no certificate presented"))?
        .to_vec();
    let info = tls::inspect_der(&leaf)?;
    stream
        .write_all(
            format!("HEAD / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut response = vec![0_u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(70), stream.read(&mut response)).await??;
    let line = String::from_utf8_lossy(&response[..read]);
    let status = line.split_whitespace().nth(1).unwrap_or("?").to_owned();
    Ok((info, status))
}

async fn verify(output: OutputFormat, store: &ConfigStore, args: &VerifyArgs) -> Result<()> {
    let config = store.load()?;
    let https = config.https.clone().ok_or_else(|| {
        coded(
            ErrorCode::InvalidInput,
            "invalid request: HTTPS is not configured",
        )
    })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots(store, &config, args.ca_file.as_deref())?)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let address = https.listen[0];
    let deadline = Instant::now() + Duration::from_secs(args.timeout_seconds);
    let mut results = Vec::new();
    let mut passed = true;
    for service in config.services.iter().filter(|service| service.https) {
        let name = service.name.trim_end_matches('.').to_owned();
        let outcome = loop {
            match probe(&connector, address, &name).await {
                Ok(result) => break Ok(result),
                Err(error) if Instant::now() >= deadline => break Err(error),
                Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        };
        results.push(match outcome {
            Ok((info, http)) => {
                json!({"name": name, "passed": true, "certificate": info, "http_status": http})
            }
            Err(error) => {
                passed = false;
                json!({"name": name, "passed": false, "error": format!("{error:#}")})
            }
        });
    }
    let human = results
        .iter()
        .map(|result| {
            if result["passed"] == true {
                format!(
                    "✓ https://{} — trusted certificate, HTTP {}",
                    result["name"].as_str().unwrap_or(""),
                    result["http_status"].as_str().unwrap_or("?")
                )
            } else {
                format!(
                    "✗ https://{} — {}",
                    result["name"].as_str().unwrap_or(""),
                    result["error"].as_str().unwrap_or("")
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let data = json!({"listen": address, "services": results});
    if !passed {
        return Err(super::ReportedError {
            command: "https verify",
            code: ErrorCode::VerificationFailed,
            message: "verification failed: a service did not present a trusted certificate".into(),
            data,
            verification: Some(json!({"status": "failed", "scope": "https_listener"})),
            next_actions: vec!["Check `localname https status` for issuance errors.".into()],
            rollback: None,
            human,
        }
        .into());
    }
    let mut envelope = Envelope::success("https verify", false, Some(config.revision), data);
    envelope.verification = Some(json!({"status": "passed", "scope": "https_listener"}));
    print_result(output, envelope, || human)
}

async fn renew(output: OutputFormat, store: &ConfigStore) -> Result<()> {
    let before =
        control::send_if_running(store, &Request::RenewCertificates)?.ok_or_else(|| {
            coded(
                ErrorCode::Unavailable,
                "DNS service unavailable: renewal needs the running service",
            )
        })?;
    let previous: Vec<u64> = before
        .status
        .and_then(|status| status.certificates)
        .unwrap_or_default()
        .iter()
        .map(|certificate| certificate.attempts)
        .collect();
    // Renewal runs in the daemon; wait for every certificate's attempt to be recorded.
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let certificates = daemon_certificates(store).unwrap_or_default();
        let done = certificates.len() == previous.len()
            && certificates
                .iter()
                .zip(&previous)
                .all(|(certificate, before)| certificate.attempts > *before);
        if done || Instant::now() > deadline {
            let failed = certificates
                .iter()
                .any(|certificate| certificate.last_error.is_some());
            let data = json!({"certificates": certificates});
            if failed || !done {
                return Err(coded(
                    ErrorCode::VerificationFailed,
                    format!("verification failed: renewal did not complete: {data}"),
                ));
            }
            return print_result(
                output,
                Envelope::success("https renew", true, None, data),
                || "✓ Renewed every certificate.".into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn ca_cert(output: OutputFormat, store: &ConfigStore, args: &CaCertArgs) -> Result<()> {
    let path = tls::ca_certificate_path(store.path());
    let pem = std::fs::read_to_string(&path).map_err(|_| {
        coded(
            ErrorCode::InvalidInput,
            "invalid request: no local CA exists; run `localname https apply --mode local-ca`",
        )
    })?;
    let info = tls::inspect(&pem)?;
    if let Some(out) = &args.out {
        std::fs::write(out, &pem)?;
    }
    let instructions = vec![
        "iOS: open the file, then Settings › General › VPN & Device Management to install it, and Settings › General › About › Certificate Trust Settings to enable full trust.".to_owned(),
        "Android: Settings › Security › Encryption & credentials › Install a certificate › CA certificate.".into(),
        "macOS: open the file in Keychain Access, then set Trust › When using this certificate to Always Trust.".into(),
        "Windows: open the file, Install Certificate › Current User › Trusted Root Certification Authorities.".into(),
        "Firefox uses its own store: Settings › Privacy & Security › Certificates › View Certificates › Authorities › Import.".into(),
    ];
    let data = json!({"path": path, "sha256": info.sha256, "subject": info.subject, "pem": pem, "instructions": instructions});
    let written = args.out.clone();
    print_result(
        output,
        Envelope::success("https ca-cert", false, None, data),
        || match written {
            Some(out) => format!(
                "Wrote {} (SHA-256 {}). Install it on each device; check the fingerprint matches.",
                out.display(),
                info.sha256
            ),
            None => format!("{pem}SHA-256 {}", info.sha256),
        },
    )
}

/// The trust-store change for this platform.
struct TrustChange {
    store: String,
    location: String,
    install: Vec<Vec<String>>,
    remove: Vec<Vec<String>>,
}

impl TrustChange {
    fn new(
        store: String,
        location: String,
        install: Vec<Vec<String>>,
        remove: Vec<Vec<String>>,
    ) -> Self {
        Self {
            store,
            location,
            install,
            remove,
        }
    }
}

/// The trust-store change for this platform.
#[allow(clippy::unnecessary_wraps)]
fn trust_commands(certificate: &Path, zone: &str, sha1: &str) -> Result<TrustChange> {
    let file = certificate.display().to_string();
    let label = format!("localname-{}", zone.trim_end_matches('.'));
    #[cfg(target_os = "linux")]
    {
        let _ = sha1;
        let systems = [
            (
                "/usr/local/share/ca-certificates",
                "crt",
                vec!["update-ca-certificates".to_owned()],
            ),
            (
                "/etc/pki/ca-trust/source/anchors",
                "pem",
                vec!["update-ca-trust".to_owned(), "extract".to_owned()],
            ),
            (
                "/etc/ca-certificates/trust-source/anchors",
                "crt",
                vec!["trust".to_owned(), "extract-compat".to_owned()],
            ),
        ];
        for (directory, extension, refresh) in systems {
            if Path::new(directory).is_dir() {
                let target = format!("{directory}/{label}.{extension}");
                return Ok(TrustChange::new(
                    "system trust store".into(),
                    target.clone(),
                    vec![vec!["cp".into(), file, target.clone()], refresh.clone()],
                    vec![vec!["rm".into(), "-f".into(), target], refresh],
                ));
            }
        }
        Err(coded(
            ErrorCode::Unavailable,
            "unsupported system: no known CA anchor directory; install the certificate manually",
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let keychain = dirs::home_dir()
            .unwrap_or_default()
            .join("Library/Keychains/login.keychain-db")
            .display()
            .to_string();
        let _ = label;
        Ok(TrustChange::new(
            "login keychain".into(),
            keychain.clone(),
            vec![vec![
                "security".into(),
                "add-trusted-cert".into(),
                "-r".into(),
                "trustRoot".into(),
                "-k".into(),
                keychain.clone(),
                file,
            ]],
            vec![vec![
                "security".into(),
                "delete-certificate".into(),
                "-Z".into(),
                sha1.into(),
                keychain,
            ]],
        ))
    }
    #[cfg(windows)]
    {
        let _ = label;
        Ok(TrustChange::new(
            "current user's Trusted Root Certification Authorities".into(),
            "Cert:\\CurrentUser\\Root".into(),
            vec![vec![
                "certutil".into(),
                "-user".into(),
                "-addstore".into(),
                "Root".into(),
                file,
            ]],
            vec![vec![
                "certutil".into(),
                "-user".into(),
                "-delstore".into(),
                "Root".into(),
                sha1.into(),
            ]],
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (file, label, sha1);
        Err(coded(
            ErrorCode::Unavailable,
            "unsupported system: install the certificate manually",
        ))
    }
}

fn confirm(
    output: OutputFormat,
    non_interactive: bool,
    args: &ConfirmArgs,
    summary: &str,
) -> Result<()> {
    if args.yes {
        return Ok(());
    }
    if non_interactive || matches!(output, OutputFormat::Json) || !std::io::stdin().is_terminal() {
        return Err(coded(
            ErrorCode::PermissionRequired,
            "permission required: trust-store changes need confirmation; review with --dry-run, then rerun with --yes",
        ));
    }
    eprint!("{summary}\nType yes to continue: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if answer.trim() == "yes" {
        Ok(())
    } else {
        Err(coded(
            ErrorCode::PermissionRequired,
            "permission required: not confirmed; nothing was changed",
        ))
    }
}

fn run_all(commands: &[Vec<String>]) -> Result<()> {
    for command in commands {
        let status = std::process::Command::new(&command[0])
            .args(&command[1..])
            .status()
            .with_context(|| format!("failed to run {}", command[0]))?;
        if !status.success() {
            return Err(coded(
                if status.code() == Some(5) || cfg!(unix) && !crate::privilege::is_root() {
                    ErrorCode::PermissionRequired
                } else {
                    ErrorCode::Internal
                },
                format!(
                    "`{}` failed ({status}); trust-store changes usually need sudo or an administrator",
                    command.join(" ")
                ),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn trust(
    output: OutputFormat,
    non_interactive: bool,
    store: &ConfigStore,
    command: &TrustCommand,
) -> Result<()> {
    let config = store.load()?;
    let certificate = tls::ca_certificate_path(store.path());
    let pem = std::fs::read_to_string(&certificate).map_err(|_| {
        coded(
            ErrorCode::InvalidInput,
            "invalid request: no local CA exists; trust applies only to mode local-ca",
        )
    })?;
    let info = tls::inspect(&pem)?;
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow!("empty CA certificate"))??;
    let sha1 = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &der)
        .as_ref()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02X}");
            hex
        });
    let TrustChange {
        store: store_name,
        location,
        install,
        remove,
    } = trust_commands(&certificate, &config.zone, &sha1)?;
    let existing: Option<TrustRecord> = read_json(&trust_path(store))?;
    let (installing, commands) = match command {
        TrustCommand::Install(_) => (true, install),
        TrustCommand::Remove(_) => (false, remove),
    };
    let args = match command {
        TrustCommand::Install(args) | TrustCommand::Remove(args) => args,
    };
    let noop = installing == existing.is_some();
    let summary = format!(
        "{} the localname CA ({}, SHA-256 {}) {} the {store_name} at {location}.\nIt can only vouch for names under {}.\nCommands: {}",
        if installing { "Add" } else { "Remove" },
        info.subject,
        info.sha256,
        if installing { "to" } else { "from" },
        config.zone.trim_end_matches('.'),
        commands
            .iter()
            .map(|command| command.join(" "))
            .collect::<Vec<_>>()
            .join(" && ")
    );
    let data: Value = json!({
        "action": if installing { "install" } else { "remove" },
        "store": store_name,
        "location": location,
        "sha256": info.sha256,
        "commands": commands,
        "changed": !noop,
    });
    let label = if installing {
        "https trust install"
    } else {
        "https trust remove"
    };
    if args.dry_run || noop {
        let mut data = data;
        data["preview"] = json!(args.dry_run);
        let human = if noop {
            "Nothing to change.".to_owned()
        } else {
            summary
        };
        return print_result(output, Envelope::success(label, !noop, None, data), || {
            human
        });
    }
    confirm(output, non_interactive, args, &summary)?;
    run_all(&commands)?;
    if installing {
        let record = TrustRecord {
            version: 1,
            store: store_name,
            location,
            sha256: info.sha256,
            sha1,
        };
        tls::write_file(
            &trust_path(store),
            serde_json::to_string_pretty(&record)?.as_bytes(),
            false,
        )?;
    } else {
        std::fs::remove_file(trust_path(store))?;
    }
    let mut envelope = Envelope::success(label, true, None, data);
    if installing {
        envelope.rollback = Some("localname https trust remove".into());
    }
    print_result(output, envelope, || {
        if installing {
            "✓ The localname CA is trusted on this host.".into()
        } else {
            "✓ Removed the localname CA from this host's trust store.".into()
        }
    })
}

fn rollback(output: OutputFormat, store: &ConfigStore, args: &DryRunArgs) -> Result<()> {
    let record: HttpsRecord = read_json(&record_path(store))?.ok_or_else(|| {
        coded(
            ErrorCode::InvalidInput,
            "invalid request: no `https apply` is recorded",
        )
    })?;
    if read_json::<TrustRecord>(&trust_path(store))?.is_some() {
        return Err(coded(
            ErrorCode::Conflict,
            "conflict: the local CA is still trusted on this host; run `localname https trust remove` first",
        ));
    }
    // Undo exactly what HTTPS added; records and services changed since stay as they are.
    let current = store.load()?;
    let deletes = record.created_key_directory || record.created_ca;
    let services: Vec<String> = current
        .services
        .iter()
        .filter(|service| service.https)
        .map(|service| service.name.trim_end_matches('.').to_owned())
        .collect();
    let data = json!({
        "removes_https": current.https.is_some(),
        "services_back_to_http": services,
        "deletes_key_material": deletes,
        "key_directory": tls::directory(store.path()),
    });
    if args.dry_run {
        let human = format!(
            "Would turn HTTPS off ({} back to plain HTTP) and {}.",
            if services.is_empty() {
                "no services".to_owned()
            } else {
                services.join(", ")
            },
            if deletes {
                "delete the keys and certificates it created"
            } else {
                "keep existing key material"
            }
        );
        return print_result(
            output,
            Envelope::success("https rollback", true, Some(current.revision), data),
            || human,
        );
    }
    if control::send_if_running(store, &Request::Status)?.is_some() {
        return Err(coded(
            ErrorCode::Conflict,
            "conflict: stop the localname service before rolling back HTTPS",
        ));
    }
    let guard = store.acquire_offline_lock()?;
    let (previous, next) = store.mutate(None, |config| {
        config.https = None;
        for service in &mut config.services {
            service.https = false;
        }
        Ok(())
    })?;
    drop(guard);
    if deletes {
        tls::remove_material(store.path())?;
    }
    std::fs::remove_file(record_path(store))?;
    let mut envelope = Envelope::success("https rollback", true, Some(next.revision), data);
    envelope.rollback = Some(rollback_command(store.path(), previous.revision));
    print_result(output, envelope, || {
        format!(
            "HTTPS is off as of revision {}; services are served over plain HTTP.",
            next.revision
        )
    })
}
