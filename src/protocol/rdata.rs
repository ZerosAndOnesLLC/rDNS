use super::name::{CompressionMap, DnsName};
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
    /// RFC 1035 HINFO (cpu, os). Also used for RFC 8482 ANY responses.
    HINFO { cpu: Vec<u8>, os: Vec<u8> },
    /// RFC 9460 SVCB — also reused by HTTPS which differs only in type code.
    SVCB(SvcbData),
    HTTPS(SvcbData),
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

/// RFC 9460 SVCB/HTTPS rdata. TargetName is uncompressed on the wire.
/// SvcParams is kept as an opaque blob so we can round-trip unknown/future
/// parameter keys without losing data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcbData {
    pub priority: u16,
    pub target: DnsName,
    pub params: Vec<u8>,
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
                let (name, consumed) = DnsName::decode(buf, offset)?;
                if consumed > rdlength {
                    return Err(RDataError::TooShort("NS"));
                }
                Ok(Self::NS(name))
            }

            RecordType::CNAME => {
                let (name, consumed) = DnsName::decode(buf, offset)?;
                if consumed > rdlength {
                    return Err(RDataError::TooShort("CNAME"));
                }
                Ok(Self::CNAME(name))
            }

            RecordType::PTR => {
                let (name, consumed) = DnsName::decode(buf, offset)?;
                if consumed > rdlength {
                    return Err(RDataError::TooShort("PTR"));
                }
                Ok(Self::PTR(name))
            }

            RecordType::MX => {
                if rdlength < 3 {
                    return Err(RDataError::TooShort("MX"));
                }
                let preference = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                let (exchange, consumed) = DnsName::decode(buf, offset + 2)?;
                if 2 + consumed > rdlength {
                    return Err(RDataError::TooShort("MX"));
                }
                Ok(Self::MX { preference, exchange })
            }

            RecordType::SOA => {
                let (mname, mname_len) = DnsName::decode(buf, offset)?;
                if mname_len > rdlength {
                    return Err(RDataError::TooShort("SOA mname"));
                }
                let (rname, rname_len) = DnsName::decode(buf, offset + mname_len)?;
                if mname_len + rname_len > rdlength {
                    return Err(RDataError::TooShort("SOA rname"));
                }
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
                let (target, consumed) = DnsName::decode(buf, offset + 6)?;
                if 6 + consumed > rdlength {
                    return Err(RDataError::TooShort("SRV"));
                }
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

            RecordType::HINFO => {
                // Two length-prefixed character-strings: cpu, os.
                if rdlength < 1 {
                    return Err(RDataError::TooShort("HINFO"));
                }
                let cpu_len = buf[offset] as usize;
                let cpu_end = offset + 1 + cpu_len;
                if cpu_end > rdata_end {
                    return Err(RDataError::TooShort("HINFO cpu"));
                }
                let cpu = buf[offset + 1..cpu_end].to_vec();
                if cpu_end >= rdata_end {
                    return Err(RDataError::TooShort("HINFO os"));
                }
                let os_len = buf[cpu_end] as usize;
                let os_end = cpu_end + 1 + os_len;
                if os_end > rdata_end {
                    return Err(RDataError::TooShort("HINFO os"));
                }
                let os = buf[cpu_end + 1..os_end].to_vec();
                Ok(Self::HINFO { cpu, os })
            }

            RecordType::SVCB | RecordType::HTTPS => {
                if rdlength < 3 {
                    return Err(RDataError::TooShort("SVCB/HTTPS"));
                }
                let priority = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                let (target, consumed) = DnsName::decode(buf, offset + 2)?;
                if 2 + consumed > rdlength {
                    return Err(RDataError::TooShort("SVCB/HTTPS target"));
                }
                let params_start = offset + 2 + consumed;
                let params = buf[params_start..rdata_end].to_vec();
                let data = SvcbData { priority, target, params };
                Ok(match rtype {
                    RecordType::HTTPS => Self::HTTPS(data),
                    _ => Self::SVCB(data),
                })
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
                    // DNS TXT strings are limited to 255 bytes; truncate if longer
                    let len = s.len().min(255);
                    buf.push(len as u8);
                    buf.extend_from_slice(&s[..len]);
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
            Self::HINFO { cpu, os } => {
                let cl = cpu.len().min(255);
                buf.push(cl as u8);
                buf.extend_from_slice(&cpu[..cl]);
                let ol = os.len().min(255);
                buf.push(ol as u8);
                buf.extend_from_slice(&os[..ol]);
            }
            Self::SVCB(svcb) | Self::HTTPS(svcb) => {
                buf.extend_from_slice(&svcb.priority.to_be_bytes());
                svcb.target.encode(buf);
                buf.extend_from_slice(&svcb.params);
            }
            Self::Raw { data, .. } => {
                buf.extend_from_slice(data);
            }
        }
    }

    /// Compression-aware encode. Names inside rdata for the types listed
    /// in RFC 3597 §4 (NS, CNAME, PTR, MX.exchange, SOA.mname, SOA.rname)
    /// participate in message-wide compression; everything else encodes
    /// the same bytes as `encode`. SRV/SVCB/HTTPS target names stay
    /// uncompressed per RFC 2782 / RFC 9460 §2.2.
    pub fn encode_compressed(&self, buf: &mut Vec<u8>, map: &mut CompressionMap) {
        match self {
            Self::NS(name) | Self::CNAME(name) | Self::PTR(name) => {
                name.encode_compressed(buf, map);
            }
            Self::MX { preference, exchange } => {
                buf.extend_from_slice(&preference.to_be_bytes());
                exchange.encode_compressed(buf, map);
            }
            Self::SOA(soa) => {
                soa.mname.encode_compressed(buf, map);
                soa.rname.encode_compressed(buf, map);
                buf.extend_from_slice(&soa.serial.to_be_bytes());
                buf.extend_from_slice(&soa.refresh.to_be_bytes());
                buf.extend_from_slice(&soa.retry.to_be_bytes());
                buf.extend_from_slice(&soa.expire.to_be_bytes());
                buf.extend_from_slice(&soa.minimum.to_be_bytes());
            }
            // All other types encode identically to the non-compressed path.
            _ => self.encode(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::name::DnsName;

    fn roundtrip(rtype: RecordType, rdata: &RData) -> RData {
        let mut buf = Vec::new();
        rdata.encode(&mut buf);
        RData::decode(rtype, &buf, 0, buf.len()).expect("decode")
    }

    #[test]
    fn https_alias_mode_roundtrip() {
        let rdata = RData::HTTPS(SvcbData {
            priority: 0,
            target: DnsName::from_str("svc.example.com").unwrap(),
            params: Vec::new(),
        });
        assert_eq!(roundtrip(RecordType::HTTPS, &rdata), rdata);
    }

    #[test]
    fn https_service_mode_with_params_roundtrip() {
        // SvcParamKey=1 (alpn), value length 9, "h2"+"http/1.1" length-prefixed
        let params = vec![
            0x00, 0x01, // key: alpn
            0x00, 0x09, // value length: 9
            0x02, b'h', b'2',
            0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        let rdata = RData::HTTPS(SvcbData {
            priority: 1,
            target: DnsName::root(),
            params,
        });
        assert_eq!(roundtrip(RecordType::HTTPS, &rdata), rdata);
    }

    #[test]
    fn svcb_roundtrip() {
        let rdata = RData::SVCB(SvcbData {
            priority: 5,
            target: DnsName::from_str("backend.example.com").unwrap(),
            params: vec![0x00, 0x03, 0x00, 0x02, 0x01, 0xBB], // port=443
        });
        assert_eq!(roundtrip(RecordType::SVCB, &rdata), rdata);
    }

    #[test]
    fn https_truncated_rdata_errors() {
        // Only the priority field, no target, no params.
        let buf = [0x00, 0x01];
        let err = RData::decode(RecordType::HTTPS, &buf, 0, buf.len());
        assert!(err.is_err(), "expected truncated HTTPS to error, got {:?}", err);
    }

    #[test]
    fn hinfo_roundtrip() {
        let rdata = RData::HINFO {
            cpu: b"RFC8482".to_vec(),
            os: Vec::new(),
        };
        assert_eq!(roundtrip(RecordType::HINFO, &rdata), rdata);

        let rdata2 = RData::HINFO {
            cpu: b"amd64".to_vec(),
            os: b"linux".to_vec(),
        };
        assert_eq!(roundtrip(RecordType::HINFO, &rdata2), rdata2);
    }

    #[test]
    fn hinfo_truncated_errors() {
        // cpu_len=5 but only 2 bytes follow
        let buf = [0x05, b'a', b'b'];
        assert!(RData::decode(RecordType::HINFO, &buf, 0, buf.len()).is_err());
    }

    #[test]
    fn https_too_short_for_priority_errors() {
        let buf = [0x00];
        let err = RData::decode(RecordType::HTTPS, &buf, 0, buf.len());
        assert!(err.is_err());
    }

    // ---- Phase 3: comprehensive per-type round-trip coverage ----

    #[test]
    fn a_roundtrip() {
        let rdata = RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(roundtrip(RecordType::A, &rdata), rdata);
    }

    #[test]
    fn aaaa_roundtrip() {
        let rdata = RData::AAAA("2001:db8::1".parse().unwrap());
        assert_eq!(roundtrip(RecordType::AAAA, &rdata), rdata);
    }

    #[test]
    fn ns_roundtrip() {
        let rdata = RData::NS(DnsName::from_str("ns1.example.com").unwrap());
        assert_eq!(roundtrip(RecordType::NS, &rdata), rdata);
    }

    #[test]
    fn cname_roundtrip() {
        let rdata = RData::CNAME(DnsName::from_str("target.example.com").unwrap());
        assert_eq!(roundtrip(RecordType::CNAME, &rdata), rdata);
    }

    #[test]
    fn ptr_roundtrip() {
        let rdata = RData::PTR(DnsName::from_str("host.example.com").unwrap());
        assert_eq!(roundtrip(RecordType::PTR, &rdata), rdata);
    }

    #[test]
    fn mx_roundtrip() {
        let rdata = RData::MX {
            preference: 10,
            exchange: DnsName::from_str("mail.example.com").unwrap(),
        };
        assert_eq!(roundtrip(RecordType::MX, &rdata), rdata);
    }

    #[test]
    fn soa_roundtrip() {
        let rdata = RData::SOA(SoaData {
            mname: DnsName::from_str("ns1.example.com").unwrap(),
            rname: DnsName::from_str("admin.example.com").unwrap(),
            serial: 2024010101,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 300,
        });
        assert_eq!(roundtrip(RecordType::SOA, &rdata), rdata);
    }

    #[test]
    fn txt_single_string_roundtrip() {
        let rdata = RData::TXT(vec![b"hello world".to_vec()]);
        assert_eq!(roundtrip(RecordType::TXT, &rdata), rdata);
    }

    #[test]
    fn txt_multi_string_roundtrip() {
        let rdata = RData::TXT(vec![
            b"v=spf1".to_vec(),
            b"ip4:192.0.2.0/24".to_vec(),
            b"-all".to_vec(),
        ]);
        assert_eq!(roundtrip(RecordType::TXT, &rdata), rdata);
    }

    #[test]
    fn txt_empty_string_roundtrip() {
        let rdata = RData::TXT(vec![Vec::new()]);
        assert_eq!(roundtrip(RecordType::TXT, &rdata), rdata);
    }

    #[test]
    fn txt_max_length_string_roundtrip() {
        let rdata = RData::TXT(vec![vec![b'x'; 255]]);
        assert_eq!(roundtrip(RecordType::TXT, &rdata), rdata);
    }

    #[test]
    fn srv_roundtrip() {
        let rdata = RData::SRV(SrvData {
            priority: 10,
            weight: 60,
            port: 5060,
            target: DnsName::from_str("sipserver.example.com").unwrap(),
        });
        assert_eq!(roundtrip(RecordType::SRV, &rdata), rdata);
    }

    #[test]
    fn caa_roundtrip() {
        let rdata = RData::CAA(CaaData {
            flags: 0,
            tag: "issue".to_string(),
            value: b"letsencrypt.org".to_vec(),
        });
        assert_eq!(roundtrip(RecordType::CAA, &rdata), rdata);
    }

    #[test]
    fn dnssec_types_raw_roundtrip() {
        // DS, DNSKEY, RRSIG, NSEC, NSEC3 all fall through to RData::Raw.
        // We just need to prove the bytes come back untouched.
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78];
        for rtype in [
            RecordType::DS,
            RecordType::DNSKEY,
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType::NSEC3,
        ] {
            let decoded = RData::decode(rtype, &payload, 0, payload.len()).expect("decode");
            let mut encoded = Vec::new();
            decoded.encode(&mut encoded);
            assert_eq!(encoded, payload, "{:?} round-trip", rtype);
        }
    }

    // ---- Malformed-input assertions: must return Err, never panic ----

    #[test]
    fn a_wrong_length_errors() {
        assert!(RData::decode(RecordType::A, &[1, 2, 3], 0, 3).is_err());
        assert!(RData::decode(RecordType::A, &[1, 2, 3, 4, 5], 0, 5).is_err());
    }

    #[test]
    fn aaaa_wrong_length_errors() {
        assert!(RData::decode(RecordType::AAAA, &[0u8; 15], 0, 15).is_err());
        assert!(RData::decode(RecordType::AAAA, &[0u8; 17], 0, 17).is_err());
    }

    #[test]
    fn mx_too_short_errors() {
        // rdlength 1 is not enough for a preference (2 bytes) + name.
        assert!(RData::decode(RecordType::MX, &[0x00], 0, 1).is_err());
    }

    #[test]
    fn srv_too_short_errors() {
        assert!(RData::decode(RecordType::SRV, &[0u8; 4], 0, 4).is_err());
    }

    #[test]
    fn caa_tag_len_overflow_errors() {
        // flags=0, tag_len=10 but only 3 bytes of rdata follow.
        let buf = [0x00, 0x0A, b'a', b'b', b'c'];
        assert!(RData::decode(RecordType::CAA, &buf, 0, buf.len()).is_err());
    }

    #[test]
    fn txt_string_len_overflow_errors() {
        // string_len=10 but only 3 payload bytes.
        let buf = [0x0A, b'a', b'b', b'c'];
        assert!(RData::decode(RecordType::TXT, &buf, 0, buf.len()).is_err());
    }

    #[test]
    fn rdata_end_past_buffer_errors() {
        // Claiming rdlength 100 with a 4-byte buffer must be rejected, not panic.
        let buf = [0u8; 4];
        assert!(RData::decode(RecordType::A, &buf, 0, 100).is_err());
    }

    #[test]
    fn cname_name_past_end_errors() {
        // label says 10 bytes but only 3 follow.
        let buf = [0x0A, b'a', b'b', b'c'];
        assert!(RData::decode(RecordType::CNAME, &buf, 0, buf.len()).is_err());
    }
}
