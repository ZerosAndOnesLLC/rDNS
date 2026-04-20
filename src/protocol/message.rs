use super::edns::{EdnsError, EdnsOpt};
use super::header::{Header, HeaderError, HEADER_SIZE};
use super::rdata::RData;
use super::record::{Question, QuestionError, RecordError, RecordType, ResourceRecord};

/// A complete DNS message (query or response).
///
/// EDNS(0) OPT is kept out of `additional` and parked on `edns` so the rest
/// of the codebase doesn't have to constantly filter the additional section
/// for the pseudo-record. On `encode()` we stitch the OPT back in as the
/// last additional record and recompute all section counts from the vec
/// lengths — callers don't need to hand-maintain `header.*_count`.
#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
    pub edns: Option<EdnsOpt>,
}

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("header error: {0}")]
    Header(#[from] HeaderError),

    #[error("question error: {0}")]
    Question(#[from] QuestionError),

    #[error("record error: {0}")]
    Record(#[from] RecordError),

    #[error("edns error: {0}")]
    Edns(#[from] EdnsError),

    /// RFC 6891 §6.1.1: more than one OPT RR is a protocol violation — the
    /// server MUST respond FORMERR.
    #[error("multiple OPT records in message")]
    MultipleOpt,
}

impl Message {
    /// Decode a DNS message from wire format.
    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        let mut header = Header::decode(buf)?;

        let mut offset = HEADER_SIZE;

        // Cap preallocation to prevent memory abuse from malicious packets
        // claiming huge section counts with minimal data.
        const MAX_PREALLOC: usize = 64;

        // Decode questions
        let mut questions = Vec::with_capacity((header.qd_count as usize).min(MAX_PREALLOC));
        for _ in 0..header.qd_count {
            let (q, consumed) = Question::decode(buf, offset)?;
            offset += consumed;
            questions.push(q);
        }

        // Decode answers
        let mut answers = Vec::with_capacity((header.an_count as usize).min(MAX_PREALLOC));
        for _ in 0..header.an_count {
            let (rr, consumed) = ResourceRecord::decode(buf, offset)?;
            offset += consumed;
            answers.push(rr);
        }

        // Decode authority
        let mut authority = Vec::with_capacity((header.ns_count as usize).min(MAX_PREALLOC));
        for _ in 0..header.ns_count {
            let (rr, consumed) = ResourceRecord::decode(buf, offset)?;
            offset += consumed;
            authority.push(rr);
        }

        // Decode additional. OPT is intercepted here and parked on `edns`;
        // only non-OPT records end up in `additional`.
        let mut additional = Vec::with_capacity((header.ar_count as usize).min(MAX_PREALLOC));
        let mut edns: Option<EdnsOpt> = None;
        for _ in 0..header.ar_count {
            let (rr, consumed) = ResourceRecord::decode(buf, offset)?;
            offset += consumed;

            if rr.rtype == RecordType::OPT {
                if edns.is_some() {
                    return Err(MessageError::MultipleOpt);
                }
                let rdata_bytes: &[u8] = match &rr.rdata {
                    RData::Raw { data, .. } => data.as_slice(),
                    _ => &[],
                };
                let parsed = EdnsOpt::from_rr_fields(
                    u16::from(rr.rclass),
                    rr.ttl,
                    rdata_bytes,
                )?;
                edns = Some(parsed);
            } else {
                additional.push(rr);
            }
        }

        // Reconcile section counts with the extracted OPT so the invariant
        // `ar_count == additional.len() + edns.is_some() as u16` holds.
        header.ar_count = (additional.len() + edns.as_ref().map_or(0, |_| 1)) as u16;

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
            edns,
        })
    }

    /// Encode this message to wire format with RFC 1035 §4.1.4 label
    /// compression. A fresh compression map is created per encode — never
    /// reused across messages. Section counts in the emitted header are
    /// computed from the vec lengths and the EDNS presence; callers do
    /// not need to keep `header.*_count` in sync with `answers`,
    /// `authority`, `additional`, `edns`.
    pub fn encode(&self) -> Vec<u8> {
        let mut header = self.header.clone();
        header.qd_count = self.questions.len() as u16;
        header.an_count = self.answers.len() as u16;
        header.ns_count = self.authority.len() as u16;
        let opt_present = self.edns.is_some() as u16;
        header.ar_count = self.additional.len() as u16 + opt_present;

        let mut buf = Vec::with_capacity(512);
        header.encode(&mut buf);

        let mut map = super::name::CompressionMap::new();
        for q in &self.questions {
            q.encode_compressed(&mut buf, &mut map);
        }
        for rr in &self.answers {
            rr.encode_compressed(&mut buf, &mut map);
        }
        for rr in &self.authority {
            rr.encode_compressed(&mut buf, &mut map);
        }
        for rr in &self.additional {
            rr.encode_compressed(&mut buf, &mut map);
        }
        // OPT is always owner-name "." with no compressible rdata — encode
        // it directly without consulting the map.
        if let Some(opt) = &self.edns {
            opt.encode_rr(&mut buf);
        }

        buf
    }

    /// Build a SERVFAIL response for a given query. If the query carried OPT,
    /// the response also carries OPT (RFC 6891 §7: a responder that receives
    /// an EDNS query MUST respond with an EDNS response). Extended rcode is
    /// left at 0 — the low nibble of the header already encodes SERVFAIL.
    pub fn servfail(query: &Message) -> Self {
        let edns = query.edns.as_ref().map(|_| EdnsOpt::default());
        Self {
            header: Header::servfail_response(&query.header),
            questions: query.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns,
        }
    }

    /// Build a FORMERR response for a malformed query.
    pub fn formerr(id: u16) -> Self {
        use super::opcode::Opcode;
        use super::rcode::Rcode;

        Self {
            header: Header {
                id,
                qr: true,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: false,
                ra: true,
                ad: false,
                cd: false,
                rcode: Rcode::FormErr,
                qd_count: 0,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::edns::{opt_code, EdnsOption};
    use crate::protocol::name::DnsName;
    use crate::protocol::opcode::Opcode;
    use crate::protocol::rcode::Rcode;
    use crate::protocol::record::{RecordClass, RecordType};

    fn query_header(id: u16, qd: u16) -> Header {
        Header {
            id,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
            qd_count: qd,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    fn example_question() -> Question {
        Question {
            name: DnsName::from_str("example.com").unwrap(),
            qtype: RecordType::A,
            qclass: RecordClass::IN,
        }
    }

    #[test]
    fn roundtrip_without_edns() {
        let msg = Message {
            header: query_header(0x1234, 1),
            questions: vec![example_question()],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: None,
        };
        let bytes = msg.encode();
        let decoded = Message::decode(&bytes).unwrap();
        assert!(decoded.edns.is_none());
        assert_eq!(decoded.header.ar_count, 0);
        assert_eq!(decoded.questions.len(), 1);
    }

    #[test]
    fn roundtrip_with_edns_minimal() {
        let msg = Message {
            header: query_header(0xABCD, 1),
            questions: vec![example_question()],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: Some(EdnsOpt {
                udp_payload_size: 4096,
                extended_rcode: 0,
                version: 0,
                dnssec_ok: true,
                z: 0,
                options: Vec::new(),
            }),
        };
        let bytes = msg.encode();
        let decoded = Message::decode(&bytes).unwrap();
        let e = decoded.edns.expect("edns preserved on roundtrip");
        assert_eq!(e.udp_payload_size, 4096);
        assert!(e.dnssec_ok);
        assert!(decoded.additional.is_empty());
        assert_eq!(decoded.header.ar_count, 1, "ar_count includes OPT");
    }

    #[test]
    fn roundtrip_with_edns_and_options() {
        let msg = Message {
            header: query_header(1, 1),
            questions: vec![example_question()],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: Some(EdnsOpt {
                udp_payload_size: 1232,
                extended_rcode: 0,
                version: 0,
                dnssec_ok: false,
                z: 0,
                options: vec![
                    EdnsOption { code: opt_code::COOKIE, data: b"clientcki".to_vec() },
                    EdnsOption { code: opt_code::NSID, data: Vec::new() },
                ],
            }),
        };
        let bytes = msg.encode();
        let decoded = Message::decode(&bytes).unwrap();
        let e = decoded.edns.expect("edns preserved");
        assert_eq!(e.options.len(), 2);
        assert_eq!(e.options[0].code, opt_code::COOKIE);
        assert_eq!(e.options[0].data, b"clientcki");
        assert_eq!(e.options[1].code, opt_code::NSID);
        assert!(e.options[1].data.is_empty());
    }

    #[test]
    fn additional_non_opt_records_preserved_alongside_edns() {
        // An A record as additional + an OPT: decode must split them, encode
        // must re-interleave them in wire order (additional first, then OPT).
        let a_rr = ResourceRecord {
            name: DnsName::from_str("glue.example.com").unwrap(),
            rtype: RecordType::A,
            rclass: RecordClass::IN,
            ttl: 300,
            rdata: RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        };
        let msg = Message {
            header: query_header(42, 1),
            questions: vec![example_question()],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: vec![a_rr.clone()],
            edns: Some(EdnsOpt::default()),
        };
        let bytes = msg.encode();
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(decoded.additional.len(), 1);
        assert_eq!(decoded.additional[0], a_rr);
        assert!(decoded.edns.is_some());
        assert_eq!(decoded.header.ar_count, 2);
    }

    #[test]
    fn multiple_opt_records_rejected() {
        // Hand-craft a wire buffer with two OPT records in additional — must
        // error, not silently take the last one.
        let mut msg = Message {
            header: query_header(1, 1),
            questions: vec![example_question()],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: Some(EdnsOpt::default()),
        };
        // Encode once, then append a second OPT manually and bump ar_count.
        let mut bytes = msg.encode();
        // Bump wire ar_count to 2.
        let ar = u16::from_be_bytes([bytes[10], bytes[11]]) + 1;
        bytes[10..12].copy_from_slice(&ar.to_be_bytes());
        // Append another OPT.
        let extra = EdnsOpt::default();
        extra.encode_rr(&mut bytes);

        let err = Message::decode(&bytes);
        assert!(matches!(err, Err(MessageError::MultipleOpt)));

        // Sanity: adjust the original to keep the test independent of field
        // order above — msg is consumed by encode(), just reference it.
        msg.header.ar_count = 1;
    }

    #[test]
    fn servfail_preserves_opt_presence() {
        let query = Message {
            header: query_header(7, 1),
            questions: vec![example_question()],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: Some(EdnsOpt {
                udp_payload_size: 4096,
                extended_rcode: 0,
                version: 0,
                dnssec_ok: true,
                z: 0,
                options: Vec::new(),
            }),
        };
        let resp = Message::servfail(&query);
        assert!(resp.edns.is_some(), "OPT-on-query implies OPT-on-response");
        // Server advertises its own (default) size, not the client's.
        assert_eq!(resp.edns.as_ref().unwrap().udp_payload_size, 1232);

        // And inverse: query without OPT → response without OPT.
        let plain_query = Message {
            header: query_header(8, 1),
            questions: vec![example_question()],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: None,
        };
        let resp_plain = Message::servfail(&plain_query);
        assert!(resp_plain.edns.is_none());
    }

    /// Regression: the LG-TV / YouTube report — `www.youtube.com` returns
    /// a CNAME to `youtube-ui.l.google.com` plus 16 A records under that
    /// canonical name. Without compression the encoded response was
    /// ~700 bytes and got TC-truncated on legacy UDP. With compression
    /// every repeat name shrinks to a 2-byte pointer, so the whole
    /// response fits well under the RFC 1035 512-byte UDP ceiling.
    #[test]
    fn encode_youtube_shape_fits_in_legacy_udp() {
        use crate::protocol::name::DnsName;
        use crate::protocol::rdata::RData;
        use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
        use std::net::Ipv4Addr;

        let qname = DnsName::from_str("www.youtube.com").unwrap();
        let canonical = DnsName::from_str("youtube-ui.l.google.com").unwrap();

        let mut answers = vec![ResourceRecord {
            name: qname.clone(),
            rtype: RecordType::CNAME,
            rclass: RecordClass::IN,
            ttl: 118,
            rdata: RData::CNAME(canonical.clone()),
        }];
        for i in 0..16 {
            answers.push(ResourceRecord {
                name: canonical.clone(),
                rtype: RecordType::A,
                rclass: RecordClass::IN,
                ttl: 118,
                rdata: RData::A(Ipv4Addr::new(142, 250, 100 + (i as u8 % 10), 1 + i as u8)),
            });
        }

        let msg = Message {
            header: query_header(0x1234, 1),
            questions: vec![Question {
                name: qname,
                qtype: RecordType::A,
                qclass: RecordClass::IN,
            }],
            answers,
            authority: Vec::new(),
            additional: Vec::new(),
            edns: None,
        };

        let wire = msg.encode();
        assert!(
            wire.len() <= 512,
            "compressed youtube response should fit in legacy UDP, got {} bytes",
            wire.len()
        );

        // And round-trips cleanly through the decoder.
        let decoded = Message::decode(&wire).unwrap();
        assert_eq!(decoded.answers.len(), 17);
    }

    #[test]
    fn encode_recomputes_section_counts() {
        // Caller passes mismatched counts; encode must ignore them and use
        // the actual vec lengths + OPT presence.
        let mut bogus_header = query_header(99, 0);
        bogus_header.an_count = 42;
        bogus_header.ar_count = 99;
        let msg = Message {
            header: bogus_header,
            questions: vec![example_question()],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: Some(EdnsOpt::default()),
        };
        let bytes = msg.encode();
        let hdr = Header::decode(&bytes).unwrap();
        assert_eq!(hdr.qd_count, 1);
        assert_eq!(hdr.an_count, 0);
        assert_eq!(hdr.ar_count, 1, "just the OPT");
    }
}
