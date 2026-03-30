use super::{Opcode, Rcode};

/// DNS message header (RFC 1035 Section 4.1.1)
/// 12 bytes, always present in every DNS message.
///
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub qr: bool,         // Query (false) or Response (true)
    pub opcode: Opcode,
    pub aa: bool,         // Authoritative Answer
    pub tc: bool,         // Truncated
    pub rd: bool,         // Recursion Desired
    pub ra: bool,         // Recursion Available
    pub ad: bool,         // Authenticated Data (DNSSEC, RFC 4035)
    pub cd: bool,         // Checking Disabled (DNSSEC, RFC 4035)
    pub rcode: Rcode,
    pub qd_count: u16,    // Question count
    pub an_count: u16,    // Answer count
    pub ns_count: u16,    // Authority count
    pub ar_count: u16,    // Additional count
}

pub const HEADER_SIZE: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error("buffer too short: need {HEADER_SIZE} bytes, got {0}")]
    TooShort(usize),
}

impl Header {
    /// Decode a DNS header from the first 12 bytes of a buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, HeaderError> {
        if buf.len() < HEADER_SIZE {
            return Err(HeaderError::TooShort(buf.len()));
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);

        let qr = (flags >> 15) & 1 == 1;
        let opcode = Opcode::from(((flags >> 11) & 0xF) as u8);
        let aa = (flags >> 10) & 1 == 1;
        let tc = (flags >> 9) & 1 == 1;
        let rd = (flags >> 8) & 1 == 1;
        let ra = (flags >> 7) & 1 == 1;
        // bit 6 is Z (reserved)
        let ad = (flags >> 5) & 1 == 1;
        let cd = (flags >> 4) & 1 == 1;
        let rcode = Rcode::from((flags & 0xF) as u8);

        let qd_count = u16::from_be_bytes([buf[4], buf[5]]);
        let an_count = u16::from_be_bytes([buf[6], buf[7]]);
        let ns_count = u16::from_be_bytes([buf[8], buf[9]]);
        let ar_count = u16::from_be_bytes([buf[10], buf[11]]);

        Ok(Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            ad,
            cd,
            rcode,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        })
    }

    /// Encode the header into 12 bytes.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.id.to_be_bytes());

        let mut flags: u16 = 0;
        if self.qr {
            flags |= 1 << 15;
        }
        flags |= (u8::from(self.opcode) as u16 & 0xF) << 11;
        if self.aa {
            flags |= 1 << 10;
        }
        if self.tc {
            flags |= 1 << 9;
        }
        if self.rd {
            flags |= 1 << 8;
        }
        if self.ra {
            flags |= 1 << 7;
        }
        if self.ad {
            flags |= 1 << 5;
        }
        if self.cd {
            flags |= 1 << 4;
        }
        flags |= u8::from(self.rcode) as u16 & 0xF;

        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&self.qd_count.to_be_bytes());
        buf.extend_from_slice(&self.an_count.to_be_bytes());
        buf.extend_from_slice(&self.ns_count.to_be_bytes());
        buf.extend_from_slice(&self.ar_count.to_be_bytes());
    }

    /// Create a SERVFAIL response header for the given query header.
    pub fn servfail_response(query: &Header) -> Self {
        Self {
            id: query.id,
            qr: true,
            opcode: query.opcode,
            aa: false,
            tc: false,
            rd: query.rd,
            ra: true,
            ad: false,
            cd: false,
            rcode: Rcode::ServFail,
            qd_count: query.qd_count,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = Header {
            id: 0xABCD,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };

        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_SIZE);

        let decoded = Header::decode(&buf).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_header_all_flags() {
        let header = Header {
            id: 0x1234,
            qr: true,
            opcode: Opcode::Query,
            aa: true,
            tc: true,
            rd: true,
            ra: true,
            ad: true,
            cd: true,
            rcode: Rcode::NxDomain,
            qd_count: 1,
            an_count: 2,
            ns_count: 3,
            ar_count: 4,
        };

        let mut buf = Vec::new();
        header.encode(&mut buf);
        let decoded = Header::decode(&buf).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_header_too_short() {
        let buf = [0u8; 6];
        assert!(Header::decode(&buf).is_err());
    }

    #[test]
    fn test_servfail_response() {
        let query = Header {
            id: 0x9999,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };

        let resp = Header::servfail_response(&query);
        assert_eq!(resp.id, 0x9999);
        assert!(resp.qr);
        assert!(resp.rd);
        assert!(resp.ra);
        assert_eq!(resp.rcode, Rcode::ServFail);
        assert_eq!(resp.qd_count, 1);
    }
}
