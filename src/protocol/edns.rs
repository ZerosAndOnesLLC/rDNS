//! EDNS(0) support (RFC 6891).
//!
//! OPT is a pseudo-RR carried in the additional section. It reuses the normal
//! RR wire layout but repurposes the CLASS and TTL fields:
//!
//! ```text
//!   NAME      .                                (root label, single 0x00)
//!   TYPE      OPT (41)                         (2 bytes)
//!   CLASS     requestor's UDP payload size     (2 bytes)
//!   TTL       ext-rcode(8) | version(8) | DO(1) | Z(15)   (4 bytes)
//!   RDLENGTH  length of RDATA                  (2 bytes)
//!   RDATA     concatenated { code(2), len(2), data } triples
//! ```
//!
//! We strip OPT out of the RR stream at `Message` decode time and store it as
//! `Option<EdnsOpt>` on the message so the rest of the code can ignore the
//! fact that these fields are overloaded.

/// Well-known EDNS option codes. Only codes with a current consumer in the
/// tree are listed; future phases add their own as they wire up typed
/// parsers (TCP keepalive, padding, EDE, …). The allow is scoped to this
/// module because the entries are referenced only in `#[cfg(test)]` today.
#[allow(dead_code)]
pub mod opt_code {
    pub const NSID: u16 = 3;
    pub const CLIENT_SUBNET: u16 = 8;
    pub const COOKIE: u16 = 10;
}

/// A single EDNS option — kept opaque at this layer. Typed wrappers for ECS,
/// cookies, EDE, etc. will consume/produce these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

/// Parsed EDNS(0) pseudo-record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOpt {
    /// Requestor's advertised UDP payload size (the OPT CLASS field).
    pub udp_payload_size: u16,
    /// Upper 8 bits of the extended 12-bit rcode (RFC 6891 §6.1.3). The low
    /// 4 bits live in the message header.
    pub extended_rcode: u8,
    /// EDNS version. Only 0 is defined; anything else should draw BADVERS.
    pub version: u8,
    /// DNSSEC OK bit (RFC 3225).
    pub dnssec_ok: bool,
    /// Remaining 15 bits of the flags field. Reserved, MUST be sent as 0, but
    /// we preserve them on decode so roundtrip doesn't silently mutate input.
    pub z: u16,
    /// OPT options, in wire order.
    pub options: Vec<EdnsOption>,
}

impl Default for EdnsOpt {
    fn default() -> Self {
        Self {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EdnsError {
    #[error("option header truncated at offset {0}")]
    OptionTruncated(usize),
    #[error("option data length {len} exceeds remaining RDATA at offset {offset}")]
    OptionOverflow { offset: usize, len: usize },
}

impl EdnsOpt {
    /// Build an `EdnsOpt` from the raw CLASS and TTL fields of an OPT RR plus
    /// its RDATA. Errors only on malformed option triples; unknown codes pass
    /// through as opaque `EdnsOption`s so we can round-trip future extensions.
    pub fn from_rr_fields(class_field: u16, ttl_field: u32, rdata: &[u8]) -> Result<Self, EdnsError> {
        let extended_rcode = ((ttl_field >> 24) & 0xFF) as u8;
        let version = ((ttl_field >> 16) & 0xFF) as u8;
        let dnssec_ok = (ttl_field & 0x0000_8000) != 0;
        let z = (ttl_field & 0x0000_7FFF) as u16;

        let options = decode_options(rdata)?;

        Ok(Self {
            udp_payload_size: class_field,
            extended_rcode,
            version,
            dnssec_ok,
            z,
            options,
        })
    }

    /// Pack flags into the wire TTL-field layout.
    pub fn ttl_field(&self) -> u32 {
        let mut v: u32 = 0;
        v |= (self.extended_rcode as u32) << 24;
        v |= (self.version as u32) << 16;
        if self.dnssec_ok {
            v |= 0x0000_8000;
        }
        v |= (self.z & 0x7FFF) as u32;
        v
    }

    /// Encode this OPT as a full pseudo-resource-record appended to `buf`.
    /// Emits root name, type=OPT(41), class=payload_size, ttl=flags, rdlen+rdata.
    pub fn encode_rr(&self, buf: &mut Vec<u8>) {
        buf.push(0x00); // root NAME
        buf.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        buf.extend_from_slice(&self.udp_payload_size.to_be_bytes()); // CLASS
        buf.extend_from_slice(&self.ttl_field().to_be_bytes()); // TTL (flags)

        let rdlen_pos = buf.len();
        buf.extend_from_slice(&[0, 0]); // rdlength placeholder
        let rdata_start = buf.len();

        for opt in &self.options {
            buf.extend_from_slice(&opt.code.to_be_bytes());
            let len = opt.data.len().min(u16::MAX as usize);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
            buf.extend_from_slice(&opt.data[..len]);
        }

        let rdata_len = (buf.len() - rdata_start).min(u16::MAX as usize) as u16;
        buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdata_len.to_be_bytes());
    }

    /// True if this OPT requests an EDNS version we don't support. Phase C
    /// uses this to decide when to synthesize a BADVERS response; until then
    /// it only has a test-mode caller.
    #[allow(dead_code)]
    pub fn is_unsupported_version(&self) -> bool {
        self.version != 0
    }
}

fn decode_options(rdata: &[u8]) -> Result<Vec<EdnsOption>, EdnsError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < rdata.len() {
        if pos + 4 > rdata.len() {
            return Err(EdnsError::OptionTruncated(pos));
        }
        let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        let data_start = pos + 4;
        let data_end = data_start + len;
        if data_end > rdata.len() {
            return Err(EdnsError::OptionOverflow { offset: pos, len });
        }
        out.push(EdnsOption {
            code,
            data: rdata[data_start..data_end].to_vec(),
        });
        pos = data_end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_advertises_1232() {
        // DNS Flag Day 2020 convention — stay below common MTU to dodge
        // IP fragmentation. Change requires explicit config.
        assert_eq!(EdnsOpt::default().udp_payload_size, 1232);
    }

    #[test]
    fn ttl_field_packs_extended_rcode_version_do() {
        let opt = EdnsOpt {
            udp_payload_size: 4096,
            extended_rcode: 0x12,
            version: 0x34,
            dnssec_ok: true,
            z: 0,
            options: Vec::new(),
        };
        let ttl = opt.ttl_field();
        assert_eq!(ttl >> 24, 0x12, "extended rcode in high byte");
        assert_eq!((ttl >> 16) & 0xFF, 0x34, "version in next byte");
        assert_eq!(ttl & 0x0000_8000, 0x8000, "DO bit at bit 15 of low half");
    }

    #[test]
    fn from_rr_fields_parses_class_ttl_flags() {
        // CLASS = 4096, extended-rcode=0, version=0, DO=1.
        let ttl = 0x0000_8000;
        let opt = EdnsOpt::from_rr_fields(4096, ttl, &[]).unwrap();
        assert_eq!(opt.udp_payload_size, 4096);
        assert_eq!(opt.extended_rcode, 0);
        assert_eq!(opt.version, 0);
        assert!(opt.dnssec_ok);
        assert!(opt.options.is_empty());
    }

    #[test]
    fn unsupported_version_detected() {
        let opt = EdnsOpt::from_rr_fields(1232, 0x0001_0000, &[]).unwrap();
        assert_eq!(opt.version, 1);
        assert!(opt.is_unsupported_version());
    }

    #[test]
    fn options_roundtrip_opaque() {
        let original = EdnsOpt {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: true,
            z: 0,
            options: vec![
                EdnsOption { code: opt_code::COOKIE, data: b"12345678".to_vec() },
                EdnsOption { code: opt_code::CLIENT_SUBNET, data: vec![0, 1, 24, 0, 192, 0, 2] },
                EdnsOption { code: 0xFFFE, data: vec![0xAA, 0xBB] }, // future/unknown
            ],
        };
        let mut rr = Vec::new();
        original.encode_rr(&mut rr);

        // Strip the RR framing (root name + type + class + ttl + rdlen) by hand
        // to isolate the fields the message-level decoder will supply.
        assert_eq!(rr[0], 0x00, "root name");
        assert_eq!(u16::from_be_bytes([rr[1], rr[2]]), 41u16);
        let class = u16::from_be_bytes([rr[3], rr[4]]);
        let ttl = u32::from_be_bytes([rr[5], rr[6], rr[7], rr[8]]);
        let rdlen = u16::from_be_bytes([rr[9], rr[10]]) as usize;
        let rdata = &rr[11..11 + rdlen];

        let decoded = EdnsOpt::from_rr_fields(class, ttl, rdata).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn empty_rdata_roundtrip() {
        let original = EdnsOpt::default();
        let mut rr = Vec::new();
        original.encode_rr(&mut rr);

        let class = u16::from_be_bytes([rr[3], rr[4]]);
        let ttl = u32::from_be_bytes([rr[5], rr[6], rr[7], rr[8]]);
        let rdlen = u16::from_be_bytes([rr[9], rr[10]]) as usize;
        assert_eq!(rdlen, 0);
        let decoded = EdnsOpt::from_rr_fields(class, ttl, &[]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn truncated_option_header_errors() {
        // 3 bytes — not enough for the 4-byte { code, len } header.
        let err = EdnsOpt::from_rr_fields(1232, 0, &[0x00, 0x0A, 0x00]);
        assert!(matches!(err, Err(EdnsError::OptionTruncated(0))));
    }

    #[test]
    fn option_length_overflow_errors() {
        // code=COOKIE, len=100 but only 2 payload bytes follow.
        let rdata = [0x00, 0x0A, 0x00, 0x64, 0xAA, 0xBB];
        let err = EdnsOpt::from_rr_fields(1232, 0, &rdata);
        assert!(matches!(err, Err(EdnsError::OptionOverflow { .. })));
    }

    #[test]
    fn z_bits_preserved_on_roundtrip() {
        // Caller set a non-zero Z (RFC says MUST be zero on send, but decoding
        // MUST ignore — we preserve them so we never silently mutate).
        let ttl = 0x0000_4321; // DO=0, Z=0x4321
        let opt = EdnsOpt::from_rr_fields(1232, ttl, &[]).unwrap();
        assert_eq!(opt.z, 0x4321);
        assert_eq!(opt.ttl_field() & 0x7FFF, 0x4321);
    }

    #[test]
    fn zero_length_option_roundtrip() {
        // NSID is often a probe: option code present, zero-length data.
        let original = EdnsOpt {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![EdnsOption { code: opt_code::NSID, data: Vec::new() }],
        };
        let mut rr = Vec::new();
        original.encode_rr(&mut rr);
        let class = u16::from_be_bytes([rr[3], rr[4]]);
        let ttl = u32::from_be_bytes([rr[5], rr[6], rr[7], rr[8]]);
        let rdlen = u16::from_be_bytes([rr[9], rr[10]]) as usize;
        let rdata = &rr[11..11 + rdlen];
        let decoded = EdnsOpt::from_rr_fields(class, ttl, rdata).unwrap();
        assert_eq!(decoded, original);
    }
}
