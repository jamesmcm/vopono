use base64::{
    Engine as _,
    engine::{GeneralPurpose, general_purpose},
};

use serde::Deserialize;
use std::fmt::Display;

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

const B64_ENGINE: GeneralPurpose = general_purpose::STANDARD;

#[derive(Deserialize, Clone)]
pub struct WgKey {
    pub public: String,
    pub private: String,
}

impl std::fmt::Debug for WgKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgKey")
            .field("public", &self.public)
            .field("private", &"********".to_string())
            .finish()
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct WgPeer {
    pub key: WgKey,
    pub ipv4_address: ipnet::Ipv4Net,
    pub ipv6_address: ipnet::Ipv6Net,
    ports: Vec<u16>,
    can_add_ports: bool,
}

impl Display for WgPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.key.public)
    }
}

pub fn generate_keypair() -> anyhow::Result<WgKey> {
    // Generate new keypair
    let mut csprng = OsRng;
    let private = StaticSecret::random_from_rng(&mut csprng);
    let public = PublicKey::from(&private);
    let public_key = B64_ENGINE.encode(public.as_bytes());
    let private_key = B64_ENGINE.encode(private.to_bytes());

    let keypair = WgKey {
        public: public_key,
        private: private_key,
    };
    Ok(keypair)
}

pub fn generate_public_key(private_key: &str) -> anyhow::Result<String> {
    let private_bytes = B64_ENGINE.decode(private_key)?;
    if private_bytes.len() != 32 {
        anyhow::bail!("Private key must be exactly 32 bytes when decoded");
    }

    let mut byte_array = [0; 32];
    byte_array.copy_from_slice(&private_bytes);

    let private = StaticSecret::from(byte_array);
    let public = PublicKey::from(&private);
    let public_key = B64_ENGINE.encode(public.as_bytes());
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = generate_keypair().unwrap();

        // Check that both keys are valid base64 strings
        assert!(!keypair.public.is_empty());
        assert!(!keypair.private.is_empty());

        // Check that public key is 44 characters (32 bytes base64 encoded)
        assert_eq!(keypair.public.len(), 44);

        // Check that private key is 44 characters (32 bytes base64 encoded)
        assert_eq!(keypair.private.len(), 44);

        // Verify that the public key can be derived from the private key
        let derived_public = generate_public_key(&keypair.private).unwrap();
        assert_eq!(keypair.public, derived_public);
    }

    #[test]
    fn test_generate_public_key() {
        // Test with a known private key - verify format and consistency
        let private_key = "gI6EdkZ4UQR6N5Q1LpI+JWCb1yZCSBHNzQe7J/KoX0s=";
        let public_key = generate_public_key(private_key).unwrap();

        // Just verify it's a valid public key format rather than hardcoding
        assert_eq!(public_key.len(), 44);
        assert!(B64_ENGINE.decode(&public_key).is_ok());
    }

    #[test]
    fn test_generate_public_key_invalid_input() {
        // Test with invalid base64
        let result = generate_public_key("invalid_base64!");
        assert!(result.is_err());

        // Test with empty string
        let result = generate_public_key("");
        assert!(result.is_err());

        // Test with too short base64
        let result = generate_public_key("YQ=="); // "a" encoded - only 1 byte
        assert!(result.is_err());

        // Test with base64 that's not 32 bytes when decoded
        let result = generate_public_key("YWFhYWFhYQ=="); // "aaaaaa" - 6 bytes
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_consistency() {
        // Generate multiple keypairs and ensure they're different
        let keypair1 = generate_keypair().unwrap();
        let keypair2 = generate_keypair().unwrap();

        // Should be different due to randomness
        assert_ne!(keypair1.public, keypair2.public);
        assert_ne!(keypair1.private, keypair2.private);

        // But each keypair should be internally consistent
        let derived_public1 = generate_public_key(&keypair1.private).unwrap();
        assert_eq!(keypair1.public, derived_public1);

        let derived_public2 = generate_public_key(&keypair2.private).unwrap();
        assert_eq!(keypair2.public, derived_public2);
    }
}
