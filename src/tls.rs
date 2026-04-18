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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TlsConfig;

    /// Write `content` to a temp path unique to this test run and return the path.
    fn write_temp(label: &str, content: &[u8]) -> String {
        let path = format!("/tmp/herald-tls-test-{}-{label}", std::process::id());
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_missing_cert_file_returns_error() {
        let config = TlsConfig {
            cert_file: "/tmp/herald-tls-nonexistent-cert-file-xyz".to_string(),
            key_file: "/tmp/herald-tls-nonexistent-key-file-xyz".to_string(),
        };
        let err = load_tls_acceptor(&config)
            .err()
            .expect("expected an error for missing cert file");
        assert!(
            err.to_string().contains("cert"),
            "error should mention cert file, got: {err}"
        );
    }

    #[test]
    fn test_empty_cert_file_returns_error() {
        let cert_path = write_temp("empty-cert", b"");
        let key_path = format!("/tmp/herald-tls-nonexistent-key-{}", std::process::id());
        let config = TlsConfig {
            cert_file: cert_path.clone(),
            key_file: key_path,
        };
        let err = load_tls_acceptor(&config)
            .err()
            .expect("expected an error for empty cert file")
            .to_string();
        assert!(
            err.contains("no certificates found"),
            "expected 'no certificates found', got: {err}"
        );
        std::fs::remove_file(&cert_path).ok();
    }

    #[test]
    fn test_invalid_pem_cert_returns_error() {
        // A PEM block with invalid base64 in the body causes a parse error.
        let bad_pem = b"-----BEGIN CERTIFICATE-----\n!!!notbase64!!!\n-----END CERTIFICATE-----\n";
        let cert_path = write_temp("invalid-cert", bad_pem);
        let key_path = format!("/tmp/herald-tls-nonexistent-key2-{}", std::process::id());
        let config = TlsConfig {
            cert_file: cert_path.clone(),
            key_file: key_path,
        };
        let err = load_tls_acceptor(&config)
            .err()
            .expect("expected an error for invalid PEM")
            .to_string();
        assert!(
            err.contains("PEM") || err.contains("cert") || err.contains("parse"),
            "expected a PEM/cert/parse error, got: {err}"
        );
        std::fs::remove_file(&cert_path).ok();
    }

    #[test]
    fn test_no_pem_blocks_in_cert_file_returns_error() {
        // A PEM file with no recognisable cert blocks — same "no certificates found" path.
        // Testing the key-missing path would need a real cert (requires rcgen); instead we
        // verify the empty-body path reaches the right error message.
        let no_cert_pem = b"# plain text, no PEM blocks\n";
        let cert_path = write_temp("no-blocks-cert", no_cert_pem);
        let config = TlsConfig {
            cert_file: cert_path.clone(),
            key_file: "/tmp/herald-tls-nonexistent-key3".to_string(),
        };
        let err = load_tls_acceptor(&config)
            .err()
            .expect("expected an error for no cert blocks")
            .to_string();
        assert!(
            err.contains("no certificates found"),
            "expected 'no certificates found', got: {err}"
        );
        std::fs::remove_file(&cert_path).ok();
    }
}
