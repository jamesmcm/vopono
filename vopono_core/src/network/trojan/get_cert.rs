use anyhow::Context;
use native_tls::TlsConnector;
use std::net::TcpStream;

pub fn get_cert(hostname: String, port: u16) -> anyhow::Result<String> {
    let mut builder = TlsConnector::builder();

    builder.danger_accept_invalid_certs(true);
    builder.danger_accept_invalid_hostnames(true); // Explicitly for hostname

    let connector = builder
        .build()
        .with_context(|| "Failed to build TLS connector")?;

    let addr = format!("{hostname}:{port}");
    let stream =
        TcpStream::connect(&addr).with_context(|| format!("Failed to connect to {addr}"))?;

    let tls_stream = connector
        .connect(&hostname, stream)
        .with_context(|| format!("TLS handshake failed with {hostname}"))?;

    let cert_der: Vec<u8> = tls_stream
        .peer_certificate()? // Returns Option<Certificate>
        .ok_or_else(|| anyhow::anyhow!("Server at {hostname} did not present a certificate"))?
        .to_der()
        .with_context(|| "Failed to convert certificate to DER format")?;

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
        // The error could be a timeout or a handshake failure.
        // Example: "TLS handshake failed" or "timed out"
        // eprintln!("Error for google.com:80: {:?}", result.err().unwrap());
    }
}
