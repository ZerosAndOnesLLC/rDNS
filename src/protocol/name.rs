/// DNS domain name with support for wire-format encoding/decoding
/// including label compression (RFC 1035 Section 4.1.4).
///
/// Names are stored as lowercase labels for case-insensitive comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName {
    /// Labels in order: ["www", "example", "com"] for "www.example.com."
    labels: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum NameError {
    #[error("unexpected end of name data")]
    UnexpectedEnd,

    #[error("label too long: {0} bytes (max 63)")]
    LabelTooLong(usize),

    #[error("name too long: {0} bytes (max 255)")]
    NameTooLong(usize),

    #[error("compression pointer loop detected")]
    PointerLoop,

    #[error("invalid label type: 0x{0:02x}")]
    InvalidLabelType(u8),
}

/// Maximum pointer follows to prevent infinite loops
const MAX_POINTERS: usize = 16;

impl DnsName {
    /// Create a root name (empty label list, represents ".").
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    /// Create a name from a slice of labels with validation.
    pub fn from_labels(labels: &[String]) -> Result<Self, NameError> {
        let normalized: Vec<String> = labels.iter().map(|l| l.to_ascii_lowercase()).collect();
        for label in &normalized {
            if label.len() > 63 {
                return Err(NameError::LabelTooLong(label.len()));
            }
        }
        let wire_len: usize = normalized.iter().map(|l| 1 + l.len()).sum::<usize>() + 1;
        if wire_len > 255 {
            return Err(NameError::NameTooLong(wire_len));
        }
        Ok(Self { labels: normalized })
    }

    /// Create a name from a dotted string (e.g., "www.example.com" or "www.example.com.").
    pub fn from_str(s: &str) -> Result<Self, NameError> {
        let s = s.strip_suffix('.').unwrap_or(s);
        if s.is_empty() {
            return Ok(Self::root());
        }

        let labels: Vec<String> = s.split('.').map(|l| l.to_ascii_lowercase()).collect();

        // Validate
        for label in &labels {
            if label.len() > 63 {
                return Err(NameError::LabelTooLong(label.len()));
            }
        }

        // Total wire length: sum of (1 + label.len()) + 1 (root)
        let wire_len: usize = labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1;
        if wire_len > 255 {
            return Err(NameError::NameTooLong(wire_len));
        }

        Ok(Self { labels })
    }

    /// Decode a domain name from DNS wire format, handling compression pointers.
    /// Returns the name and the number of bytes consumed from the current position.
    pub fn decode(buf: &[u8], offset: usize) -> Result<(Self, usize), NameError> {
        let mut labels = Vec::new();
        let mut pos = offset;
        let mut bytes_consumed = None; // Track where we first jumped
        let mut pointer_count = 0;
        let mut wire_len: usize = 0; // Track total wire-format name length (C6)

        loop {
            if pos >= buf.len() {
                return Err(NameError::UnexpectedEnd);
            }

            let len_byte = buf[pos];

            // Root label (end of name)
            if len_byte == 0 {
                wire_len += 1; // root label byte
                if bytes_consumed.is_none() {
                    bytes_consumed = Some(pos + 1 - offset);
                }
                break;
            }

            // Compression pointer: top 2 bits are 11
            if len_byte & 0xC0 == 0xC0 {
                if pos + 1 >= buf.len() {
                    return Err(NameError::UnexpectedEnd);
                }
                let ptr = ((len_byte as usize & 0x3F) << 8) | buf[pos + 1] as usize;

                // Prevent forward and self-referencing pointers (RFC 1035 S4.1.4)
                if ptr >= pos {
                    return Err(NameError::PointerLoop);
                }

                if bytes_consumed.is_none() {
                    bytes_consumed = Some(pos + 2 - offset);
                }

                pointer_count += 1;
                if pointer_count > MAX_POINTERS {
                    return Err(NameError::PointerLoop);
                }

                pos = ptr;
                continue;
            }

            // Regular label: top 2 bits are 00
            if len_byte & 0xC0 != 0 {
                return Err(NameError::InvalidLabelType(len_byte));
            }

            let label_len = len_byte as usize;
            let label_start = pos + 1;
            let label_end = label_start + label_len;

            if label_end > buf.len() {
                return Err(NameError::UnexpectedEnd);
            }

            wire_len += 1 + label_len; // length byte + label data

            // DNS labels are octets; use lossy conversion but hex-encode non-UTF8
            // bytes to prevent collisions between different binary labels
            let label = match std::str::from_utf8(&buf[label_start..label_end]) {
                Ok(s) => s.to_ascii_lowercase(),
                Err(_) => {
                    // Hex-encode binary labels to preserve uniqueness
                    buf[label_start..label_end]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>()
                }
            };

            labels.push(label);
            pos = label_end;
        }

        // Validate total wire-format name length (RFC 1035: max 255 bytes)
        if wire_len > 255 {
            return Err(NameError::NameTooLong(wire_len));
        }

        let consumed = bytes_consumed.unwrap_or(pos + 1 - offset);
        Ok((Self { labels }, consumed))
    }

    /// Encode this name in DNS wire format (without compression).
    pub fn encode(&self, buf: &mut Vec<u8>) {
        for label in &self.labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // Root label
    }

    /// Wire-format length of this name (uncompressed).
    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1
    }

    /// Return the dotted string representation (e.g., "www.example.com.").
    pub fn to_dotted(&self) -> String {
        if self.labels.is_empty() {
            return ".".to_string();
        }
        let mut s = self.labels.join(".");
        s.push('.');
        s
    }

    /// Number of labels (not counting root).
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Check if this name is the root.
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Get labels slice.
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Check if this name is a subdomain of (or equal to) the given parent name.
    /// e.g., "www.example.com" is a subdomain of "example.com".
    pub fn is_subdomain_of(&self, parent: &DnsName) -> bool {
        if parent.labels.len() > self.labels.len() {
            return false;
        }
        // Compare from the right (TLD end)
        let offset = self.labels.len() - parent.labels.len();
        self.labels[offset..] == parent.labels[..]
    }
}

impl std::fmt::Display for DnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_dotted())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_from_str() {
        let name = DnsName::from_str("www.example.com").unwrap();
        assert_eq!(name.labels(), &["www", "example", "com"]);
        assert_eq!(name.to_dotted(), "www.example.com.");
    }

    #[test]
    fn test_name_from_str_trailing_dot() {
        let name = DnsName::from_str("www.example.com.").unwrap();
        assert_eq!(name.labels(), &["www", "example", "com"]);
    }

    #[test]
    fn test_root_name() {
        let name = DnsName::from_str(".").unwrap();
        assert!(name.is_root());
        assert_eq!(name.to_dotted(), ".");
    }

    #[test]
    fn test_name_encode_decode_roundtrip() {
        let name = DnsName::from_str("mail.example.org").unwrap();
        let mut buf = Vec::new();
        name.encode(&mut buf);

        let (decoded, consumed) = DnsName::decode(&buf, 0).unwrap();
        assert_eq!(name, decoded);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_name_wire_format() {
        let name = DnsName::from_str("example.com").unwrap();
        let mut buf = Vec::new();
        name.encode(&mut buf);

        // Expected: \x07example\x03com\x00
        assert_eq!(buf, b"\x07example\x03com\x00");
    }

    #[test]
    fn test_name_compression_pointer() {
        // Build a buffer with "example.com" at offset 0, then a pointer at offset 13
        let mut buf = Vec::new();
        let name = DnsName::from_str("example.com").unwrap();
        name.encode(&mut buf); // bytes 0..13

        // Now write "www" + pointer to offset 0
        buf.push(3); // label length
        buf.extend_from_slice(b"www");
        buf.push(0xC0); // compression pointer
        buf.push(0x00); // pointing to offset 0

        let (decoded, consumed) = DnsName::decode(&buf, 13).unwrap();
        assert_eq!(decoded.to_dotted(), "www.example.com.");
        assert_eq!(consumed, 6); // 1+3 (www label) + 2 (pointer)
    }

    #[test]
    fn test_name_case_insensitive() {
        let name = DnsName::from_str("WWW.Example.COM").unwrap();
        assert_eq!(name.labels(), &["www", "example", "com"]);
    }

    #[test]
    fn test_label_too_long() {
        let long_label = "a".repeat(64);
        let name = format!("{}.com", long_label);
        assert!(DnsName::from_str(&name).is_err());
    }
}
