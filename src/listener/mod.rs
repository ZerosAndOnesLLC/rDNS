pub mod tcp;
pub mod tls;
pub mod udp;

use crate::auth::engine::{AuthEngine, AuthResult};
use crate::cache::entry::CacheKey;
use crate::cache::CacheStore;
use crate::protocol::header::{Header, HEADER_SIZE};
use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::rcode::Rcode;
use crate::protocol::record::{RecordClass, RecordType};
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;

/// Fast-path: extract query name and type from raw wire format without full decode.
/// Returns (name, qtype, qclass, id, rd_flag) or None if parse fails.
fn parse_query_fast(buf: &[u8]) -> Option<(DnsName, RecordType, RecordClass, u16, bool)> {
    if buf.len() < HEADER_SIZE + 5 {
        return None;
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags >> 15) & 1 == 1;
    if qr {
        return None; // This is a response, not a query
    }
    let rd = (flags >> 8) & 1 == 1;
    let qd_count = u16::from_be_bytes([buf[4], buf[5]]);
    if qd_count != 1 {
        return None; // Multi-question queries are rare, fall back to full parse
    }

    let (name, name_len) = DnsName::decode(buf, HEADER_SIZE).ok()?;
    let pos = HEADER_SIZE + name_len;
    if pos + 4 > buf.len() {
        return None;
    }

    let qtype = RecordType::from(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
    let qclass = RecordClass::from(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));

    Some((name, qtype, qclass, id, rd))
}

/// Build a cached response directly into wire format, avoiding full Message construction.
fn build_cached_response_fast(
    entry: &crate::cache::entry::CacheEntry,
    id: u16,
    rd: bool,
    qname: &DnsName,
    qtype: RecordType,
    qclass: RecordClass,
) -> Vec<u8> {
    let rcode = if entry.negative { Rcode::NxDomain } else { Rcode::NoError };
    let remaining_ttl = entry.remaining_ttl();

    let header = Header {
        id,
        qr: true,
        opcode: crate::protocol::Opcode::from(0),
        aa: false,
        tc: false,
        rd,
        ra: true,
        ad: false,
        cd: false,
        rcode,
        qd_count: 1,
        an_count: entry.answers.len() as u16,
        ns_count: entry.authority.len() as u16,
        ar_count: entry.additional.len() as u16,
    };

    // Pre-calculate approximate size
    let mut buf = Vec::with_capacity(512);
    header.encode(&mut buf);

    // Encode question
    qname.encode(&mut buf);
    buf.extend_from_slice(&u16::from(qtype).to_be_bytes());
    buf.extend_from_slice(&u16::from(qclass).to_be_bytes());

    // Encode answer records with adjusted TTL
    encode_records_with_ttl(&mut buf, &entry.answers, remaining_ttl);
    encode_records_with_ttl(&mut buf, &entry.authority, remaining_ttl);
    encode_records_with_ttl(&mut buf, &entry.additional, remaining_ttl);

    buf
}

/// Encode resource records with an overridden TTL, directly into the buffer.
fn encode_records_with_ttl(
    buf: &mut Vec<u8>,
    records: &[crate::protocol::record::ResourceRecord],
    ttl: u32,
) {
    for rr in records {
        rr.name.encode(buf);
        buf.extend_from_slice(&u16::from(rr.rtype).to_be_bytes());
        buf.extend_from_slice(&u16::from(rr.rclass).to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());

        // Encode rdata with length prefix
        let rdata_len_pos = buf.len();
        buf.extend_from_slice(&[0, 0]); // placeholder for rdlength
        let rdata_start = buf.len();
        rr.rdata.encode(buf);
        let rdata_len = (buf.len() - rdata_start) as u16;
        buf[rdata_len_pos..rdata_len_pos + 2].copy_from_slice(&rdata_len.to_be_bytes());
    }
}

/// Process an incoming DNS query and produce a response.
/// Uses fast-path for cache hits to minimize allocations.
async fn handle_query(
    buf: &[u8],
    cache: &CacheStore,
    resolver: &Option<Resolver>,
    auth: &Option<AuthEngine>,
    rpz: &RpzEngine,
) -> Vec<u8> {
    // Fast path: parse just the question from wire format
    if let Some((name, qtype, qclass, id, rd)) = parse_query_fast(buf) {
        // RPZ check
        if let Some(action) = rpz.check(&name) {
            // Need full decode for RPZ response building
            if let Ok(query) = Message::decode(buf) {
                if let Some(response) = rpz.apply_action(&action, &query) {
                    return response.encode();
                }
            }
        }

        // Authoritative check
        if let Some(auth_engine) = auth {
            match auth_engine.query(&name, qtype, qclass) {
                AuthResult::Answer(mut response) => {
                    response.header.id = id;
                    response.header.rd = rd;
                    return response.encode();
                }
                AuthResult::NotAuthoritative => {}
            }
        }

        // Resolver (checks cache internally first)
        if let Some(resolver) = resolver {
            let mut response = resolver.resolve(&name, qtype, qclass).await;
            response.header.id = id;
            response.header.rd = rd;
            return response.encode();
        }

        // Direct cache lookup (no resolver mode)
        let key = CacheKey::new(name.clone(), qtype, qclass);
        if let Some(entry) = cache.lookup(&key) {
            return build_cached_response_fast(&entry, id, rd, &name, qtype, qclass);
        }

        // SERVFAIL
        return build_servfail_fast(id, rd, &name, qtype, qclass);
    }

    // Slow path: full decode for malformed/multi-question queries
    match Message::decode(buf) {
        Ok(query) => Message::servfail(&query).encode(),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse query");
            let id = if buf.len() >= 2 {
                u16::from_be_bytes([buf[0], buf[1]])
            } else {
                0
            };
            Message::formerr(id).encode()
        }
    }
}

fn build_servfail_fast(id: u16, rd: bool, name: &DnsName, qtype: RecordType, qclass: RecordClass) -> Vec<u8> {
    let header = Header {
        id,
        qr: true,
        opcode: crate::protocol::Opcode::from(0),
        aa: false,
        tc: false,
        rd,
        ra: true,
        ad: false,
        cd: false,
        rcode: Rcode::ServFail,
        qd_count: 1,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
    };

    let mut buf = Vec::with_capacity(64);
    header.encode(&mut buf);
    name.encode(&mut buf);
    buf.extend_from_slice(&u16::from(qtype).to_be_bytes());
    buf.extend_from_slice(&u16::from(qclass).to_be_bytes());
    buf
}
