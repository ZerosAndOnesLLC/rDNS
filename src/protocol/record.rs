use super::name::DnsName;
use super::rdata::RData;

/// DNS record types (RFC 1035 + extensions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,        // 1 - IPv4 address
    NS,       // 2 - Name server
    CNAME,    // 5 - Canonical name
    SOA,      // 6 - Start of authority
    PTR,      // 12 - Pointer
    MX,       // 15 - Mail exchange
    TXT,      // 16 - Text
    AAAA,     // 28 - IPv6 address
    SRV,      // 33 - Service locator
    OPT,      // 41 - EDNS(0) pseudo-record
    DS,       // 43 - Delegation signer (DNSSEC)
    RRSIG,    // 46 - DNSSEC signature
    NSEC,     // 47 - Next secure (DNSSEC)
    DNSKEY,   // 48 - DNS key (DNSSEC)
    NSEC3,    // 50 - NSEC3 (DNSSEC)
    SVCB,     // 64 - Service binding (RFC 9460)
    HTTPS,    // 65 - HTTPS service binding (RFC 9460)
    CAA,      // 257 - Certification authority authorization
    Unknown(u16),
}

impl From<u16> for RecordType {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            12 => Self::PTR,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            33 => Self::SRV,
            41 => Self::OPT,
            43 => Self::DS,
            46 => Self::RRSIG,
            47 => Self::NSEC,
            48 => Self::DNSKEY,
            50 => Self::NSEC3,
            64 => Self::SVCB,
            65 => Self::HTTPS,
            257 => Self::CAA,
            v => Self::Unknown(v),
        }
    }
}

impl From<RecordType> for u16 {
    fn from(val: RecordType) -> u16 {
        match val {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::OPT => 41,
            RecordType::DS => 43,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
            RecordType::SVCB => 64,
            RecordType::HTTPS => 65,
            RecordType::CAA => 257,
            RecordType::Unknown(v) => v,
        }
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::NS => write!(f, "NS"),
            Self::CNAME => write!(f, "CNAME"),
            Self::SOA => write!(f, "SOA"),
            Self::PTR => write!(f, "PTR"),
            Self::MX => write!(f, "MX"),
            Self::TXT => write!(f, "TXT"),
            Self::AAAA => write!(f, "AAAA"),
            Self::SRV => write!(f, "SRV"),
            Self::OPT => write!(f, "OPT"),
            Self::DS => write!(f, "DS"),
            Self::RRSIG => write!(f, "RRSIG"),
            Self::NSEC => write!(f, "NSEC"),
            Self::DNSKEY => write!(f, "DNSKEY"),
            Self::NSEC3 => write!(f, "NSEC3"),
            Self::SVCB => write!(f, "SVCB"),
            Self::HTTPS => write!(f, "HTTPS"),
            Self::CAA => write!(f, "CAA"),
            Self::Unknown(v) => write!(f, "TYPE{}", v),
        }
    }
}

/// DNS record classes (RFC 1035)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordClass {
    IN,    // 1 - Internet
    CH,    // 3 - Chaos
    HS,    // 4 - Hesiod
    ANY,   // 255 - Any (query only)
    Unknown(u16),
}

impl From<u16> for RecordClass {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::IN,
            3 => Self::CH,
            4 => Self::HS,
            255 => Self::ANY,
            v => Self::Unknown(v),
        }
    }
}

impl From<RecordClass> for u16 {
    fn from(val: RecordClass) -> u16 {
        match val {
            RecordClass::IN => 1,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::ANY => 255,
            RecordClass::Unknown(v) => v,
        }
    }
}

/// A DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: DnsName,
    pub rtype: RecordType,
    pub rclass: RecordClass,
    pub ttl: u32,
    pub rdata: RData,
}

/// A DNS question entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: DnsName,
    pub qtype: RecordType,
    pub qclass: RecordClass,
}

impl Question {
    /// Decode a question from wire format.
    pub fn decode(buf: &[u8], offset: usize) -> Result<(Self, usize), QuestionError> {
        let (name, name_len) = DnsName::decode(buf, offset)
            .map_err(QuestionError::Name)?;

        let pos = offset + name_len;
        if pos + 4 > buf.len() {
            return Err(QuestionError::TooShort);
        }

        let qtype = RecordType::from(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        let qclass = RecordClass::from(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));

        Ok((Self { name, qtype, qclass }, name_len + 4))
    }

    /// Encode this question in wire format.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.name.encode(buf);
        buf.extend_from_slice(&u16::from(self.qtype).to_be_bytes());
        buf.extend_from_slice(&u16::from(self.qclass).to_be_bytes());
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuestionError {
    #[error("name decode error: {0}")]
    Name(#[from] super::name::NameError),

    #[error("question section too short")]
    TooShort,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("name decode error: {0}")]
    Name(#[from] super::name::NameError),

    #[error("record too short")]
    TooShort,

    #[error("rdata decode error: {0}")]
    RData(#[from] super::rdata::RDataError),
}

impl ResourceRecord {
    /// Decode a resource record from wire format.
    pub fn decode(buf: &[u8], offset: usize) -> Result<(Self, usize), RecordError> {
        let (name, name_len) = DnsName::decode(buf, offset)?;

        let pos = offset + name_len;
        if pos + 10 > buf.len() {
            return Err(RecordError::TooShort);
        }

        let rtype = RecordType::from(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        let rclass = RecordClass::from(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;

        let rdata_start = pos + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > buf.len() {
            return Err(RecordError::TooShort);
        }

        let rdata = RData::decode(rtype, buf, rdata_start, rdlength)?;

        Ok((
            Self {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            name_len + 10 + rdlength,
        ))
    }

    /// Encode this resource record in wire format.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.name.encode(buf);
        buf.extend_from_slice(&u16::from(self.rtype).to_be_bytes());
        buf.extend_from_slice(&u16::from(self.rclass).to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());

        // Encode rdata to a temp buffer to get the length
        let mut rdata_buf = Vec::new();
        self.rdata.encode(&mut rdata_buf);
        let rdlen = rdata_buf.len().min(65535);
        buf.extend_from_slice(&(rdlen as u16).to_be_bytes());
        buf.extend_from_slice(&rdata_buf[..rdlen]);
    }
}
