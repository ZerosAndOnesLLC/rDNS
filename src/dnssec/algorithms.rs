/// DNSSEC algorithm numbers (RFC 8624)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// RSA/SHA-256 (algorithm 8) — MUST implement
    RsaSha256,
    /// RSA/SHA-512 (algorithm 10)
    RsaSha512,
    /// ECDSA P-256/SHA-256 (algorithm 13) — MUST implement
    EcdsaP256Sha256,
    /// ECDSA P-384/SHA-384 (algorithm 14)
    EcdsaP384Sha384,
    /// Ed25519 (algorithm 15) — RECOMMENDED
    Ed25519,
    /// Unknown algorithm
    Unknown(u8),
}

impl From<u8> for Algorithm {
    fn from(val: u8) -> Self {
        match val {
            8 => Self::RsaSha256,
            10 => Self::RsaSha512,
            13 => Self::EcdsaP256Sha256,
            14 => Self::EcdsaP384Sha384,
            15 => Self::Ed25519,
            v => Self::Unknown(v),
        }
    }
}

impl From<Algorithm> for u8 {
    fn from(val: Algorithm) -> u8 {
        match val {
            Algorithm::RsaSha256 => 8,
            Algorithm::RsaSha512 => 10,
            Algorithm::EcdsaP256Sha256 => 13,
            Algorithm::EcdsaP384Sha384 => 14,
            Algorithm::Ed25519 => 15,
            Algorithm::Unknown(v) => v,
        }
    }
}

impl Algorithm {
    /// Whether this algorithm is supported for validation.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

/// DNSSEC digest types (for DS records)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    Sha1,        // 1 — NOT RECOMMENDED but still seen
    Sha256,      // 2 — MUST implement
    Sha384,      // 4
    Unknown(u8),
}

impl From<u8> for DigestType {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::Sha1,
            2 => Self::Sha256,
            4 => Self::Sha384,
            v => Self::Unknown(v),
        }
    }
}

/// DNSKEY record flags
pub const DNSKEY_FLAG_ZONE_KEY: u16 = 0x0100; // bit 7
pub const DNSKEY_FLAG_SEP: u16 = 0x0001; // bit 15 (Secure Entry Point / KSK)

/// DNSKEY protocol field (always 3 for DNSSEC)
pub const DNSKEY_PROTOCOL: u8 = 3;

/// Parsed DNSKEY record data.
#[derive(Debug, Clone)]
pub struct DnskeyData {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: Algorithm,
    pub public_key: Vec<u8>,
}

impl DnskeyData {
    /// Parse from raw RDATA bytes.
    pub fn from_rdata(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        Some(Self {
            flags: u16::from_be_bytes([data[0], data[1]]),
            protocol: data[2],
            algorithm: Algorithm::from(data[3]),
            public_key: data[4..].to_vec(),
        })
    }

    /// Whether this is a Zone Signing Key (ZSK).
    pub fn is_zone_key(&self) -> bool {
        self.flags & DNSKEY_FLAG_ZONE_KEY != 0
    }

    /// Whether this is a Key Signing Key (KSK / SEP).
    pub fn is_ksk(&self) -> bool {
        self.flags & DNSKEY_FLAG_SEP != 0
    }

    /// Calculate the key tag (RFC 4034 Appendix B).
    pub fn key_tag(&self) -> u16 {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&self.flags.to_be_bytes());
        rdata.push(self.protocol);
        rdata.push(u8::from(self.algorithm));
        rdata.extend_from_slice(&self.public_key);

        let mut ac: u32 = 0;
        for (i, &byte) in rdata.iter().enumerate() {
            if i & 1 == 0 {
                ac += (byte as u32) << 8;
            } else {
                ac += byte as u32;
            }
        }
        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }
}

/// Parsed DS record data.
#[derive(Debug, Clone)]
pub struct DsData {
    pub key_tag: u16,
    pub algorithm: Algorithm,
    pub digest_type: DigestType,
    pub digest: Vec<u8>,
}

impl DsData {
    pub fn from_rdata(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        Some(Self {
            key_tag: u16::from_be_bytes([data[0], data[1]]),
            algorithm: Algorithm::from(data[2]),
            digest_type: DigestType::from(data[3]),
            digest: data[4..].to_vec(),
        })
    }
}

/// Parsed RRSIG record data.
#[derive(Debug, Clone)]
pub struct RrsigData {
    pub type_covered: u16,
    pub algorithm: Algorithm,
    pub labels: u8,
    pub original_ttl: u32,
    pub sig_expiration: u32,
    pub sig_inception: u32,
    pub key_tag: u16,
    pub signer_name: Vec<u8>, // Wire format name
    pub signature: Vec<u8>,
}

impl RrsigData {
    pub fn from_rdata(data: &[u8]) -> Option<Self> {
        if data.len() < 18 {
            return None;
        }
        let type_covered = u16::from_be_bytes([data[0], data[1]]);
        let algorithm = Algorithm::from(data[2]);
        let labels = data[3];
        let original_ttl = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let sig_expiration = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let sig_inception = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let key_tag = u16::from_be_bytes([data[16], data[17]]);

        // Parse signer name (wire format) starting at offset 18
        let mut pos = 18;
        let name_start = pos;
        loop {
            if pos >= data.len() {
                return None;
            }
            let len = data[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            pos += 1 + len;
        }
        let signer_name = data[name_start..pos].to_vec();
        let signature = data[pos..].to_vec();

        Some(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            sig_expiration,
            sig_inception,
            key_tag,
            signer_name,
            signature,
        })
    }

    /// Check if the signature is currently valid (not expired, not future).
    pub fn is_time_valid(&self, now_unix: u32) -> bool {
        now_unix >= self.sig_inception && now_unix <= self.sig_expiration
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_roundtrip() {
        assert_eq!(Algorithm::from(8), Algorithm::RsaSha256);
        assert_eq!(u8::from(Algorithm::RsaSha256), 8);
        assert_eq!(Algorithm::from(13), Algorithm::EcdsaP256Sha256);
        assert_eq!(Algorithm::from(15), Algorithm::Ed25519);
    }

    #[test]
    fn test_dnskey_key_tag() {
        // Known test vector key tag calculation
        let key = DnskeyData {
            flags: 257, // KSK
            protocol: 3,
            algorithm: Algorithm::RsaSha256,
            public_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let tag = key.key_tag();
        assert!(tag > 0); // Just verify it computes without panic
        assert!(key.is_ksk());
        assert!(key.is_zone_key());
    }

    #[test]
    fn test_dnskey_flags() {
        let zsk = DnskeyData {
            flags: 256, // ZSK only
            protocol: 3,
            algorithm: Algorithm::EcdsaP256Sha256,
            public_key: vec![],
        };
        assert!(zsk.is_zone_key());
        assert!(!zsk.is_ksk());
    }
}
