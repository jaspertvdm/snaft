//! Provenance Token Signing — ring (BoringSSL) HMAC-SHA256 in compiled Rust.
//!
//! Token signatures are computed here, not in Python.
//! The signing key never touches Python memory.
//!
//! Uses Google's `ring` crate (BoringSSL-based) for HMAC-SHA256.
//! More audited, faster, and more battle-tested than pure-Rust alternatives.

use ring::{digest, hmac};

pub struct TokenSigner {
    key: hmac::Key,
}

impl TokenSigner {
    pub fn new(secret: &str) -> Self {
        TokenSigner {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
        }
    }

    /// Sign a provenance token. Returns first 24 hex chars of HMAC-SHA256.
    pub fn sign(
        &self,
        token_id: &str,
        timestamp: f64,
        agent_id: &str,
        action: &str,
        rule_name: &str,
        erin: &str,
        eraan: &str,
        eromheen: &str,
        erachter: &str,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            token_id, timestamp, agent_id, action, rule_name,
            erin, eraan, eromheen, erachter
        );

        let tag = hmac::sign(&self.key, payload.as_bytes());
        let full_hex = hex::encode(tag.as_ref());
        full_hex[..24].to_string()
    }

    /// Hash content deterministically. Returns first 16 hex chars of SHA-256.
    pub fn hash_content(&self, content: &str) -> String {
        let hash = digest::digest(&digest::SHA256, content.as_bytes());
        let full_hex = hex::encode(hash.as_ref());
        full_hex[..16].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_deterministic() {
        let signer = TokenSigner::new("test-key");
        let sig1 = signer.sign("T1", 1000.0, "agent", "ALLOW", "rule", "e", "a", "o", "i");
        let sig2 = signer.sign("T1", 1000.0, "agent", "ALLOW", "rule", "e", "a", "o", "i");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_sign_different_input() {
        let signer = TokenSigner::new("test-key");
        let sig1 = signer.sign("T1", 1000.0, "agent", "ALLOW", "rule", "e", "a", "o", "i");
        let sig2 = signer.sign("T1", 1000.0, "agent", "BLOCK", "rule", "e", "a", "o", "i");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_sign_different_key() {
        let s1 = TokenSigner::new("key-1");
        let s2 = TokenSigner::new("key-2");
        let sig1 = s1.sign("T1", 1000.0, "agent", "ALLOW", "rule", "e", "a", "o", "i");
        let sig2 = s2.sign("T1", 1000.0, "agent", "ALLOW", "rule", "e", "a", "o", "i");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_signature_length() {
        let signer = TokenSigner::new("test");
        let sig = signer.sign("T", 0.0, "a", "b", "c", "d", "e", "f", "g");
        assert_eq!(sig.len(), 24);
    }

    #[test]
    fn test_hash_content_deterministic() {
        let signer = TokenSigner::new("any");
        let h1 = signer.hash_content("hello world");
        let h2 = signer.hash_content("hello world");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }
}
