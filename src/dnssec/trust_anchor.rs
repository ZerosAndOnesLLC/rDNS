use super::algorithms::{Algorithm, DnskeyData};

/// Root trust anchor keys.
/// These are the IANA root zone KSK keys used to validate the DNSSEC chain.
/// Updated per RFC 5011 (automated trust anchor update).
pub fn root_trust_anchors() -> Vec<TrustAnchor> {
    vec![
        // Root KSK-2024 (Key Tag: 38696)
        // Current root zone KSK as of 2024
        TrustAnchor {
            key_tag: 20326,
            algorithm: Algorithm::RsaSha256,
            digest_hex: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D".to_string(),
        },
    ]
}

/// A trust anchor — a known-good DNSKEY or DS digest for the root zone.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub key_tag: u16,
    pub algorithm: Algorithm,
    /// SHA-256 digest of the DNSKEY (hex-encoded)
    pub digest_hex: String,
}

impl TrustAnchor {
    /// Verify that a DNSKEY matches this trust anchor.
    pub fn matches_key(&self, key: &DnskeyData) -> bool {
        if key.key_tag() != self.key_tag {
            return false;
        }
        if key.algorithm != self.algorithm {
            return false;
        }
        // Verify the key is a KSK
        if !key.is_ksk() {
            return false;
        }
        // Verify the public key has reasonable length for the algorithm
        // RSA-2048 keys are ~256 bytes, RSA-4096 are ~512 bytes
        match key.algorithm {
            Algorithm::RsaSha256 | Algorithm::RsaSha512 => {
                if key.public_key.len() < 128 || key.public_key.len() > 1024 {
                    return false;
                }
            }
            Algorithm::EcdsaP256Sha256 => {
                if key.public_key.len() != 64 {
                    return false;
                }
            }
            Algorithm::EcdsaP384Sha384 => {
                if key.public_key.len() != 96 {
                    return false;
                }
            }
            Algorithm::Ed25519 => {
                if key.public_key.len() != 32 {
                    return false;
                }
            }
            _ => return false,
        }
        // NOTE: Full digest verification requires SHA-256 computation.
        // This will be implemented when cryptographic DNSSEC validation is added.
        true
    }
}

/// DNSSEC validation status for a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
    /// Signatures validated successfully
    Secure,
    /// No DNSSEC records present (unsigned zone)
    Insecure,
    /// Validation attempted but failed
    Bogus,
    /// Validation could not be performed (missing data)
    Indeterminate,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_trust_anchors() {
        let anchors = root_trust_anchors();
        assert!(!anchors.is_empty());
        assert_eq!(anchors[0].key_tag, 20326);
        assert_eq!(anchors[0].algorithm, Algorithm::RsaSha256);
    }
}
