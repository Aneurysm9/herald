use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;

use crate::config::TlsConfig;

/// Load TLS certificate and key from PEM files and build a [`TlsAcceptor`].
///
/// The certificate file should contain the full chain (leaf certificate followed
/// by any intermediates). The key file should contain a single PKCS#8 or RSA
/// private key in PEM format.
pub(crate) fn load_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    let cert_bytes = std::fs::read(&config.cert_file)
        .with_context(|| format!("reading TLS cert file: {}", config.cert_file))?;
    let key_bytes = std::fs::read(&config.key_file)
        .with_context(|| format!("reading TLS key file: {}", config.key_file))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
        .collect::<Result<_, _>>()
        .context("parsing PEM certificate chain")?;

    anyhow::ensure!(
        !certs.is_empty(),
        "no certificates found in {}",
        config.cert_file
    );

    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .context("parsing PEM private key")?
        .context("no private key found in key file")?;

    let server_config = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("setting TLS protocol versions")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("building TLS server config")?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
