use super::name::DnsName;
use super::record::RecordType;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parsed RDATA for supported record types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(DnsName),
    CNAME(DnsName),
    PTR(DnsName),
    MX { preference: u16, exchange: DnsName },
    SOA(SoaData),
    TXT(Vec<Vec<u8>>),
    SRV(SrvData),
    CAA(CaaData),
    /// Fallback for unsupported or DNSSEC types — stores raw bytes
    Raw { type_code: u16, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaData {
    pub mname: DnsName,
    pub rname: DnsName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvData {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: DnsName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaaData {
    pub flags: u8,
    pub tag: String,
    pub value: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum RDataError {
    #[error("rdata too short for {0}")]
    TooShort(&'static str),

    #[error("name decode error in rdata: {0}")]
    Name(#[from] super::name::NameError),

    #[error("invalid rdata: {0}")]
    Invalid(String),
}

impl RData {
    /// Decode RDATA from wire format given the record type.
    pub fn decode(
        rtype: RecordType,
        buf: &[u8],
        offset: usize,
        rdlength: usize,
    ) -> Result<Self, RDataError> {
        let rdata_end = offset + rdlength;

        // Bounds guard: ensure rdata region does not extend beyond the buffer
        if rdata_end > buf.len() {
            return Err(RDataError::TooShort("rdata extends beyond buffer"));
        }

        match rtype {
            RecordType::A => {
                if rdlength != 4 {
                    return Err(RDataError::TooShort("A"));
                }
                let addr = Ipv4Addr::new(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
                Ok(Self::A(addr))
            }

            RecordType::AAAA => {
                if rdlength != 16 {
                    return Err(RDataError::TooShort("AAAA"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[offset..offset + 16]);
                Ok(Self::AAAA(Ipv6Addr::from(octets)))
            }

            RecordType::NS => {
                let (name, _) = DnsName::decode(buf, offset)?;
                Ok(Self::NS(name))
            }

            RecordType::CNAME => {
                let (name, _) = DnsName::decode(buf, offset)?;
                Ok(Self::CNAME(name))
            }

            RecordType::PTR => {
                let (name, _) = DnsName::decode(buf, offset)?;
                Ok(Self::PTR(name))
            }

            RecordType::MX => {
                if rdlength < 3 {
                    return Err(RDataError::TooShort("MX"));
                }
                let preference = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                let (exchange, _) = DnsName::decode(buf, offset + 2)?;
                Ok(Self::MX { preference, exchange })
            }

            RecordType::SOA => {
                let (mname, mname_len) = DnsName::decode(buf, offset)?;
                let (rname, rname_len) = DnsName::decode(buf, offset + mname_len)?;
                let pos = offset + mname_len + rname_len;
                if pos + 20 > rdata_end {
                    return Err(RDataError::TooShort("SOA"));
                }
                let serial = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
                let refresh = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
                let retry = u32::from_be_bytes([buf[pos + 8], buf[pos + 9], buf[pos + 10], buf[pos + 11]]);
                let expire = u32::from_be_bytes([buf[pos + 12], buf[pos + 13], buf[pos + 14], buf[pos + 15]]);
                let minimum = u32::from_be_bytes([buf[pos + 16], buf[pos + 17], buf[pos + 18], buf[pos + 19]]);
                Ok(Self::SOA(SoaData {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }))
            }

            RecordType::TXT => {
                let mut strings = Vec::new();
                let mut pos = offset;
                while pos < rdata_end {
                    if pos >= buf.len() {
                        return Err(RDataError::TooShort("TXT"));
                    }
                    let str_len = buf[pos] as usize;
                    pos += 1;
                    if pos + str_len > rdata_end {
                        return Err(RDataError::TooShort("TXT"));
                    }
                    strings.push(buf[pos..pos + str_len].to_vec());
                    pos += str_len;
                }
                Ok(Self::TXT(strings))
            }

            RecordType::SRV => {
                if rdlength < 7 {
                    return Err(RDataError::TooShort("SRV"));
                }
                let priority = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                let weight = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                let port = u16::from_be_bytes([buf[offset + 4], buf[offset + 5]]);
                let (target, _) = DnsName::decode(buf, offset + 6)?;
                Ok(Self::SRV(SrvData { priority, weight, port, target }))
            }

            RecordType::CAA => {
                if rdlength < 2 {
                    return Err(RDataError::TooShort("CAA"));
                }
                let flags = buf[offset];
                let tag_len = buf[offset + 1] as usize;
                if offset + 2 + tag_len > rdata_end {
                    return Err(RDataError::TooShort("CAA"));
                }
                let tag = std::str::from_utf8(&buf[offset + 2..offset + 2 + tag_len])
                    .map_err(|e| RDataError::Invalid(format!("CAA tag not UTF-8: {}", e)))?
                    .to_string();
                let value = buf[offset + 2 + tag_len..rdata_end].to_vec();
                Ok(Self::CAA(CaaData { flags, tag, value }))
            }

            // For DNSSEC and unknown types, store raw bytes
            _ => {
                let data = buf[offset..rdata_end].to_vec();
                Ok(Self::Raw {
                    type_code: u16::from(rtype),
                    data,
                })
            }
        }
    }

    /// Encode this RDATA to wire format.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::A(addr) => {
                buf.extend_from_slice(&addr.octets());
            }
            Self::AAAA(addr) => {
                buf.extend_from_slice(&addr.octets());
            }
            Self::NS(name) | Self::CNAME(name) | Self::PTR(name) => {
                name.encode(buf);
            }
            Self::MX { preference, exchange } => {
                buf.extend_from_slice(&preference.to_be_bytes());
                exchange.encode(buf);
            }
            Self::SOA(soa) => {
                soa.mname.encode(buf);
                soa.rname.encode(buf);
                buf.extend_from_slice(&soa.serial.to_be_bytes());
                buf.extend_from_slice(&soa.refresh.to_be_bytes());
                buf.extend_from_slice(&soa.retry.to_be_bytes());
                buf.extend_from_slice(&soa.expire.to_be_bytes());
                buf.extend_from_slice(&soa.minimum.to_be_bytes());
            }
            Self::TXT(strings) => {
                for s in strings {
                    // DNS TXT strings are limited to 255 bytes each; split longer ones
                    for chunk in s.chunks(255) {
                        buf.push(chunk.len() as u8);
                        buf.extend_from_slice(chunk);
                    }
                }
            }
            Self::SRV(srv) => {
                buf.extend_from_slice(&srv.priority.to_be_bytes());
                buf.extend_from_slice(&srv.weight.to_be_bytes());
                buf.extend_from_slice(&srv.port.to_be_bytes());
                srv.target.encode(buf);
            }
            Self::CAA(caa) => {
                buf.push(caa.flags);
                buf.push(caa.tag.len().min(255) as u8);
                buf.extend_from_slice(caa.tag.as_bytes());
                buf.extend_from_slice(&caa.value);
            }
            Self::Raw { data, .. } => {
                buf.extend_from_slice(data);
            }
        }
    }
}
