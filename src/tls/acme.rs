//! ACME DNS-01 issuance for an owned domain. The user's hook publishes and removes the
//! `_acme-challenge` TXT records; localname never holds DNS provider credentials. The
//! certificate key is generated here and only a CSR leaves the host.

use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use hyper::{Request, body::Bytes, header};
use hyper_util::rt::TokioIo;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType,
    HttpClient, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use tracing::{info, warn};

use crate::config::{HttpsConfig, LETS_ENCRYPT};

const HOOK_TIMEOUT: Duration = Duration::from_secs(120);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTPS client for the ACME API on the proxy's HTTP/1.1 stack: one connection per
/// request, trusting the configured bundle or the system's roots.
struct Client {
    connector: tokio_rustls::TlsConnector,
}

impl Client {
    fn new(bundle: Option<&Path>) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        match bundle {
            Some(bundle) => {
                let pem = std::fs::read(bundle)
                    .with_context(|| format!("failed to read {}", bundle.display()))?;
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
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        })
    }
}

type Pending = Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>>;

impl HttpClient for Client {
    fn request(&self, request: Request<BodyWrapper<Bytes>>) -> Pending {
        let connector = self.connector.clone();
        Box::pin(async move {
            let other = |error: anyhow::Error| instant_acme::Error::Other(error.into());
            tokio::time::timeout(REQUEST_TIMEOUT, send(connector, request))
                .await
                .map_err(|_| other(anyhow!("ACME request timed out after 30 s")))?
                .map_err(other)
        })
    }
}

async fn send(
    connector: tokio_rustls::TlsConnector,
    request: Request<BodyWrapper<Bytes>>,
) -> Result<BytesResponse> {
    let (mut parts, body) = request.into_parts();
    if parts.uri.scheme_str() != Some("https") {
        bail!("ACME URLs must use https: {}", parts.uri);
    }
    let host = parts
        .uri
        .host()
        .ok_or_else(|| anyhow!("ACME URL has no host: {}", parts.uri))?
        .to_owned();
    let port = parts.uri.port_u16().unwrap_or(443);
    let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let server = rustls::pki_types::ServerName::try_from(host.trim_matches(['[', ']']).to_owned())?;
    let stream = connector.connect(server, stream).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(connection);
    let authority = if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    };
    parts
        .headers
        .insert(header::HOST, header::HeaderValue::from_str(&authority)?);
    parts.uri = parts
        .uri
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .parse()?;
    let response = sender
        .send_request(Request::from_parts(parts, body))
        .await?;
    Ok(BytesResponse::from(response))
}

fn account_path(config: &Path) -> PathBuf {
    super::directory(config).join("acme-account.json")
}

fn directory_url(https: &HttpsConfig) -> String {
    https
        .acme_directory
        .clone()
        .unwrap_or_else(|| LETS_ENCRYPT.into())
}

async fn account(config: &Path, https: &HttpsConfig) -> Result<Account> {
    let builder = || -> Result<_> {
        Ok(Account::builder_with_http(Box::new(Client::new(
            https.acme_ca_bundle.as_deref(),
        )?)))
    };
    let path = account_path(config);
    let directory = directory_url(https);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let stored: StoredAccount = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        if stored.directory == directory {
            return Ok(builder()?.from_credentials(stored.credentials).await?);
        }
    }
    let contacts: Vec<&str> = https.acme_contact.iter().map(String::as_str).collect();
    let (account, credentials) = builder()?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: https.acme_terms_agreed,
                only_return_existing: false,
            },
            directory.clone(),
            None,
        )
        .await?;
    let stored = StoredAccount {
        directory,
        credentials,
    };
    super::write_file(&path, serde_json::to_string(&stored)?.as_bytes(), true)?;
    info!("registered ACME account");
    Ok(account)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredAccount {
    directory: String,
    credentials: AccountCredentials,
}

/// Run the DNS-01 hook: `HOOK set|clear NAME VALUE`.
async fn hook(https: &HttpsConfig, action: &str, name: &str, value: &str) -> Result<()> {
    let program = https
        .dns01_hook
        .as_ref()
        .ok_or_else(|| anyhow!("dns01_hook is not configured"))?;
    let child = tokio::process::Command::new(program)
        .args([action, name, value])
        .env("LOCALNAME_DNS01_ACTION", action)
        .env("LOCALNAME_DNS01_NAME", name)
        .env("LOCALNAME_DNS01_VALUE", value)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(HOOK_TIMEOUT, child)
        .await
        .map_err(|_| anyhow!("DNS-01 hook {} timed out after 120 s", program.display()))?
        .with_context(|| format!("failed to run DNS-01 hook {}", program.display()))?;
    if !output.status.success() {
        bail!(
            "DNS-01 hook {} {action} failed ({}): {}",
            program.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Obtain a certificate for `name`. Returns (chain PEM, key PEM).
pub async fn issue(config: &Path, https: &HttpsConfig, name: &str) -> Result<(String, String)> {
    let host = name.trim_end_matches('.').to_owned();
    let account = account(config, https).await?;
    let identifiers = [Identifier::Dns(host.clone())];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    let mut published = Vec::new();
    let result = async {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                status => bail!("ACME authorization for {host} is {status:?}"),
            }
            let mut challenge = authorization
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| anyhow!("the ACME server offered no dns-01 challenge for {host}"))?;
            let record = format!("_acme-challenge.{}", challenge.identifier());
            let value = challenge.key_authorization().dns_value();
            hook(https, "set", &record, &value).await?;
            published.push((record, value));
            tokio::time::sleep(Duration::from_secs(https.dns01_wait_seconds)).await;
            challenge.set_ready().await?;
        }
        let retries = RetryPolicy::new().timeout(Duration::from_secs(180));
        let status = order.poll_ready(&retries).await?;
        if status != OrderStatus::Ready {
            bail!("ACME order for {host} ended {status:?} instead of ready; check the DNS-01 hook and propagation");
        }
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(vec![host.clone()])?;
        params.distinguished_name.push(DnType::CommonName, host.as_str());
        let request = params.serialize_request(&key)?;
        order.finalize_csr(request.der()).await?;
        let chain = order.poll_certificate(&retries).await?;
        Ok((chain, key.serialize_pem()))
    }
    .await;
    for (record, value) in published {
        if let Err(error) = hook(https, "clear", &record, &value).await {
            warn!(%error, "DNS-01 cleanup failed");
        }
    }
    result
}
