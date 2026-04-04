use std::sync::Arc;

use anyhow::{Context, Result};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use crate::config::TlsConfig;

/// Load TLS certificate and key from PEM files and build a [`TlsAcceptor`].
///
/// The certificate file should contain the full chain (leaf certificate followed
/// by any intermediates). The key file should contain a single PKCS#8 or RSA
/// private key in PEM format.
pub(crate) fn load_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    let certs: Vec<_> = CertificateDer::pem_file_iter(&config.cert_file)
        .with_context(|| format!("reading TLS cert file: {}", config.cert_file))?
        .collect::<Result<_, _>>()
        .context("parsing PEM certificate chain")?;

    anyhow::ensure!(
        !certs.is_empty(),
        "no certificates found in {}",
        config.cert_file
    );

    let key: PrivateKeyDer = PrivateKeyDer::from_pem_file(&config.key_file)
        .with_context(|| format!("reading TLS key file: {}", config.key_file))?;

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
