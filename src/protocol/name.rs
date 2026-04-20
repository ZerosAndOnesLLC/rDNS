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

/// Highest byte offset a 14-bit DNS compression pointer can reach. Offsets
/// at or above this must be emitted uncompressed and must not be recorded
/// as compression targets.
pub const MAX_COMPRESSION_OFFSET: u16 = 0x3FFF;

/// Compression state threaded through a single message encode. Maps a
/// lowercased label suffix to the byte offset where that suffix begins
/// in the output buffer. Use `CompressionMap::new()` at the start of
/// every message encode — never reuse across messages.
pub type CompressionMap = std::collections::HashMap<Vec<String>, u16>;

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

        // `unwrap_or_else` so the fallback expression is only evaluated in
        // the no-pointer case — after following a pointer `pos` can be
        // less than `offset`, and eager evaluation of `pos + 1 - offset`
        // would panic with underflow even though the Some branch makes
        // the fallback logically unreachable.
        let consumed = bytes_consumed.unwrap_or_else(|| pos + 1 - offset);
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

    /// Encode this name with RFC 1035 §4.1.4 label compression, consulting
    /// and updating `map`. Suffixes of this name that already appear in
    /// `map` become 2-byte back-pointers; every new prefix-suffix encoded
    /// below offset 0x4000 is recorded for later names to reuse.
    ///
    /// Rules enforced:
    /// - Root label is always emitted as a single 0 byte (never a pointer).
    /// - Pointers use offsets < 0x4000 (14-bit field).
    /// - Suffixes whose starting byte would be ≥ 0x4000 are not recorded,
    ///   so later names never form unreachable pointers.
    pub fn encode_compressed(&self, buf: &mut Vec<u8>, map: &mut CompressionMap) {
        if self.labels.is_empty() {
            buf.push(0);
            return;
        }

        // Find the longest suffix (starting at some label index) that has
        // already been written to the buffer — we'll emit a pointer at
        // that boundary. Scan left-to-right so the first hit is the
        // longest (most labels = longest match).
        let mut match_idx = self.labels.len();
        let mut match_offset: Option<u16> = None;
        for i in 0..self.labels.len() {
            if let Some(&off) = map.get(&self.labels[i..].to_vec()) {
                match_idx = i;
                match_offset = Some(off);
                break;
            }
        }

        // Emit labels[0..match_idx] uncompressed. Each time we're about to
        // write a label at offset `here`, record the suffix rooted there
        // so a later name can compress against it (unless we're past the
        // 14-bit ceiling).
        for i in 0..match_idx {
            let here = buf.len();
            if here <= MAX_COMPRESSION_OFFSET as usize {
                map.insert(self.labels[i..].to_vec(), here as u16);
            }
            let label = &self.labels[i];
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }

        match match_offset {
            Some(off) => {
                let ptr = 0xC000u16 | off;
                buf.extend_from_slice(&ptr.to_be_bytes());
            }
            None => buf.push(0),
        }
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

    #[test]
    fn compress_first_name_is_uncompressed() {
        let name = DnsName::from_str("example.com").unwrap();
        let mut map = CompressionMap::new();
        let mut buf = Vec::new();
        name.encode_compressed(&mut buf, &mut map);
        assert_eq!(buf, b"\x07example\x03com\x00");
        // Suffixes recorded for later reuse.
        assert_eq!(map.get(&vec!["example".to_string(), "com".to_string()]), Some(&0));
        assert_eq!(map.get(&vec!["com".to_string()]), Some(&8));
    }

    #[test]
    fn compress_exact_suffix_match_emits_pointer() {
        let first = DnsName::from_str("example.com").unwrap();
        let second = DnsName::from_str("www.example.com").unwrap();
        let mut map = CompressionMap::new();
        let mut buf = Vec::new();
        first.encode_compressed(&mut buf, &mut map);
        let start = buf.len();
        second.encode_compressed(&mut buf, &mut map);
        // Second name: "\x03www" + pointer(0xC000 | 0)
        assert_eq!(&buf[start..], b"\x03www\xC0\x00");
        // Round-trip both names from the combined buffer.
        let (d1, n1) = DnsName::decode(&buf, 0).unwrap();
        assert_eq!(d1, first);
        let (d2, _) = DnsName::decode(&buf, n1).unwrap();
        assert_eq!(d2, second);
    }

    #[test]
    fn compress_multi_record_shares_canonical_name() {
        // Simulates the youtube shape: one CNAME target followed by many
        // A records that all carry the canonical name. Every repeat name
        // should shrink to a 2-byte pointer.
        let canonical = DnsName::from_str("youtube-ui.l.google.com").unwrap();
        let mut map = CompressionMap::new();
        let mut buf = Vec::new();
        canonical.encode_compressed(&mut buf, &mut map);
        let after_first = buf.len();
        for _ in 0..16 {
            canonical.encode_compressed(&mut buf, &mut map);
        }
        // Each subsequent encode must only grow the buffer by 2 bytes.
        let pointer_bytes = buf.len() - after_first;
        assert_eq!(pointer_bytes, 2 * 16);
        // Round-trip any of the pointers to prove it resolves to the full name.
        let (decoded, _) = DnsName::decode(&buf, after_first).unwrap();
        assert_eq!(decoded, canonical);
    }

    #[test]
    fn compress_root_never_pointers() {
        let root = DnsName::root();
        let mut map = CompressionMap::new();
        let mut buf = Vec::new();
        root.encode_compressed(&mut buf, &mut map);
        root.encode_compressed(&mut buf, &mut map);
        assert_eq!(buf, b"\x00\x00");
    }

    #[test]
    fn compress_partial_suffix_pointer() {
        // Write "a.b.com" first, then "b.com" — the second name should
        // become a pointer into the middle of the first.
        let long = DnsName::from_str("a.b.com").unwrap();
        let short = DnsName::from_str("b.com").unwrap();
        let mut map = CompressionMap::new();
        let mut buf = Vec::new();
        long.encode_compressed(&mut buf, &mut map);
        let start = buf.len();
        short.encode_compressed(&mut buf, &mut map);
        // "b.com" suffix was registered at offset 2 (after "\x01a").
        assert_eq!(&buf[start..], b"\xC0\x02");
        let (decoded, _) = DnsName::decode(&buf, start).unwrap();
        assert_eq!(decoded, short);
    }

    #[test]
    fn compress_does_not_register_offsets_beyond_ceiling() {
        // Pre-fill the buffer past 0x4000 so the first label lands at an
        // un-pointable offset. The name must still encode correctly, but
        // no suffix should be recorded.
        let mut buf = vec![0u8; (MAX_COMPRESSION_OFFSET as usize) + 5];
        let mut map = CompressionMap::new();
        let name = DnsName::from_str("example.com").unwrap();
        let before = buf.len();
        name.encode_compressed(&mut buf, &mut map);
        // Encoded as uncompressed (13 bytes: 7+1 + 3+1 + 1).
        assert_eq!(buf.len() - before, 13);
        // No entries recorded — all positions were ≥ 0x4000.
        assert!(map.is_empty());
    }
}
