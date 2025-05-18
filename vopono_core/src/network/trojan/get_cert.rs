use anyhow::Context;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime}; // UnixTime for ServerCertVerifier trait
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>, // The server name we're trying to connect to
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn get_cert(hostname: String, port: u16) -> anyhow::Result<String> {
    let custom_verifier = Arc::new(NoCertificateVerification);

    let crypto_provider = rustls::crypto::ring::default_provider();

    let client_config = ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(custom_verifier)
        .with_no_client_auth();

    let connector = rustls_connector::RustlsConnector::from(Arc::new(client_config));

    let addr = format!("{hostname}:{port}");
    let stream =
        TcpStream::connect(&addr).with_context(|| format!("Failed to connect to {addr}"))?;

    // The `connect` method of `rustls_connector::TlsConnector` will use the
    // `hostname` to set up SNI (Server Name Indication) and for verification
    // (which our custom verifier will ignore).
    let tls_stream = connector
        .connect(&hostname, stream) // `hostname` is passed as `domain`
        .with_context(|| format!("TLS handshake failed with {hostname}"))?;

    let rustls_connection_ref = tls_stream.conn;

    let peer_certs_opt: Option<&[CertificateDer<'_>]> = rustls_connection_ref.peer_certificates();

    let cert_der_ref_opt: Option<&CertificateDer<'_>> =
        peer_certs_opt.and_then(|certs| certs.first());

    let cert_der: Vec<u8> = cert_der_ref_opt
        .ok_or_else(|| anyhow::anyhow!("Server at {hostname} did not present a certificate"))?
        .as_ref() // Convert CertificateDer (which is like &[u8]) to &[u8]
        .to_vec(); // Clone it into a Vec<u8>

    let pem_obj = pem::Pem::new("CERTIFICATE".to_string(), cert_der);
    let pem_string = pem::encode(&pem_obj);

    Ok(pem_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note that these tests require network access and may fail if the network is down or the host is unreachable.
    // TODO: Create mock tests for get_cert to avoid network dependency.
    #[test]
    fn test_get_google_cert() {
        let result = get_cert("google.com".to_string(), 443);
        assert!(
            result.is_ok(),
            "Failed to get certificate: {:?}",
            result.err()
        );
        let pem_string = result.unwrap();

        assert!(
            pem_string.starts_with("-----BEGIN CERTIFICATE-----"),
            "PEM string does not start correctly"
        );
        assert!(
            pem_string.trim_end().ends_with("-----END CERTIFICATE-----"),
            "PEM string does not end correctly"
        ); // trim_end for potential newline
    }

    #[test]
    fn test_get_self_signed_cert() {
        let result = get_cert("self-signed.badssl.com".to_string(), 443);
        assert!(
            result.is_ok(),
            "Failed to get self-signed certificate (check badssl.com or replace with local test): {:?}",
            result.err()
        );
        if let Ok(pem_string) = result {
            assert!(pem_string.starts_with("-----BEGIN CERTIFICATE-----"));
            assert!(pem_string.trim_end().ends_with("-----END CERTIFICATE-----"));
        }
    }

    #[test]
    fn test_get_wrong_host_cert() {
        let result = get_cert("wrong.host.badssl.com".to_string(), 443);
        assert!(
            result.is_ok(),
            "Failed to get certificate from wrong.host.badssl.com (check badssl.com or replace with local test): {:?}",
            result.err()
        );
        if let Ok(pem_string) = result {
            assert!(pem_string.starts_with("-----BEGIN CERTIFICATE-----"));
            assert!(pem_string.trim_end().ends_with("-----END CERTIFICATE-----"));
        }
    }

    #[test]
    fn test_get_example_com_cert() {
        let result = get_cert("example.com".to_string(), 443);
        assert!(
            result.is_ok(),
            "Failed to get certificate: {:?}",
            result.err()
        );
        let pem_string = result.unwrap();

        assert!(pem_string.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem_string.trim_end().ends_with("-----END CERTIFICATE-----"));
    }

    #[test]
    fn test_non_existent_host() {
        // This test expects a connection error or DNS resolution error
        let result = get_cert("nonexistent.invalid.example.com".to_string(), 443);
        assert!(
            result.is_err(),
            "Expected an error for a non-existent host, but got Ok"
        );
    }

    #[test]
    fn test_host_with_no_tls_on_port() {
        // Assuming google.com:80 does not offer TLS
        let result = get_cert("google.com".to_string(), 80);
        assert!(
            result.is_err(),
            "Expected an error for a non-TLS port, but got Ok"
        );
    }
}
