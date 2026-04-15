pub mod tcp;
pub mod tls;
pub mod udp;
#[allow(dead_code)]
pub mod udp_batch;

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
    let rcode = if entry.negative { entry.negative_rcode } else { Rcode::NoError };
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

/// Build a REFUSED response for clients not allowed to use recursion.
fn build_refused_fast(id: u16, rd: bool, name: &DnsName, qtype: RecordType, qclass: RecordClass) -> Vec<u8> {
    let header = Header {
        id,
        qr: true,
        opcode: crate::protocol::Opcode::from(0),
        aa: false,
        tc: false,
        rd,
        ra: false,
        ad: false,
        cd: false,
        rcode: Rcode::Refused,
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

/// Process an incoming DNS query and produce a response.
/// Uses fast-path for cache hits to minimize allocations.
/// `recursion_allowed` controls whether the source IP is permitted to use the resolver.
pub(crate) async fn handle_query(
    buf: &[u8],
    cache: &CacheStore,
    resolver: &Option<Resolver>,
    auth: &Option<AuthEngine>,
    rpz: &RpzEngine,
    recursion_allowed: bool,
) -> Vec<u8> {
    // Fast path: parse just the question from wire format
    if let Some((name, qtype, qclass, id, rd)) = parse_query_fast(buf) {
        // RPZ check
        if let Some(action) = rpz.check(&name) {
            // Drop action: return empty response (caller must not send anything)
            if action == crate::rpz::policy::PolicyAction::Drop {
                return Vec::new();
            }
            // Need full decode for RPZ response building
            if let Ok(query) = Message::decode(buf) {
                if let Some(response) = rpz.apply_action(&action, &query) {
                    return response.encode();
                }
            }
        }

        // Authoritative check (always allowed regardless of ACL)
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

        // Resolver (checks cache internally first) — only if source is allowed
        if let Some(resolver) = resolver {
            if recursion_allowed {
                let mut response = resolver.resolve(&name, qtype, qclass).await;
                response.header.id = id;
                response.header.rd = rd;
                return response.encode();
            } else {
                // Client wants recursion but is not allowed — return REFUSED
                return build_refused_fast(id, rd, &name, qtype, qclass);
            }
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

/// Maximum UDP response size per RFC 1035 (without EDNS0).
const MAX_UDP_PAYLOAD: usize = 512;

/// Truncate a UDP response if it exceeds MAX_UDP_PAYLOAD.
/// Sets the TC (truncation) bit and strips answer/authority/additional sections.
fn truncate_udp_response(response: &mut Vec<u8>) {
    if response.len() <= MAX_UDP_PAYLOAD {
        return;
    }
    // Set TC bit in the header flags (byte 2, bit 1 of the high nibble)
    if response.len() >= HEADER_SIZE {
        response[2] |= 0x02; // TC bit is bit 9 of flags = byte 2, bit 1

        // Zero out answer, authority, additional counts (keep question count)
        // AN count at bytes 6-7, NS count at 8-9, AR count at 10-11
        response[6] = 0;
        response[7] = 0;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;
    }
    // Keep only header + question section.
    // Question section starts at byte 12 and we need to find its end.
    let mut pos = HEADER_SIZE;
    // Walk the question name labels
    while pos < response.len() {
        let len = response[pos] as usize;
        if len == 0 {
            pos += 1; // root label
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2; // compression pointer
            break;
        }
        pos += 1 + len;
    }
    pos += 4; // QTYPE (2) + QCLASS (2)
    response.truncate(pos.min(response.len()));
}

/// Validate that a byte slice is either empty (a Drop response) or a
/// syntactically valid DNS reply: parseable header with QR=1 and an
/// rcode in the well-known set. Used by the fuzz-lite tests.
#[cfg(test)]
pub(crate) fn is_valid_response(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    if buf.len() < HEADER_SIZE {
        return false;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags >> 15) & 1 == 1;
    let rcode = (flags & 0x000F) as u8;
    qr && matches!(rcode, 0 | 1 | 2 | 3 | 4 | 5)
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

#[cfg(test)]
mod fuzz_lite_tests {
    //! Phase 6: prove `handle_query` cannot panic on malformed input.

    use super::*;
    use crate::cache::CacheStore;
    use crate::rpz::RpzEngine;
    use std::time::Duration;

    fn empty_components() -> (
        CacheStore,
        Option<crate::resolver::Resolver>,
        Option<crate::auth::engine::AuthEngine>,
        RpzEngine,
    ) {
        let cache = CacheStore::new(1000, 60, 86400, 60);
        (cache, None, None, RpzEngine::new())
    }

    async fn drive(buf: &[u8]) -> Vec<u8> {
        let (cache, resolver, auth, rpz) = empty_components();
        let fut = handle_query(buf, &cache, &resolver, &auth, &rpz, true);
        // 100 ms ceiling: with no resolver/auth this must return synchronously.
        tokio::time::timeout(Duration::from_millis(100), fut)
            .await
            .expect("handle_query must return within 100ms for None resolver/auth")
    }

    #[tokio::test]
    async fn empty_input_does_not_panic() {
        let r = drive(&[]).await;
        assert!(is_valid_response(&r));
    }

    #[tokio::test]
    async fn shorter_than_header_does_not_panic() {
        for len in [1usize, 5, 11] {
            let buf = vec![0xABu8; len];
            let r = drive(&buf).await;
            assert!(is_valid_response(&r), "len {} produced invalid response", len);
        }
    }

    #[tokio::test]
    async fn header_only_with_zero_two_max_qdcount() {
        for qd in [0u16, 2, 65535] {
            let mut buf = vec![0u8; HEADER_SIZE];
            buf[0] = 0xAA;
            buf[1] = 0xBB;
            buf[4..6].copy_from_slice(&qd.to_be_bytes());
            let r = drive(&buf).await;
            assert!(is_valid_response(&r), "qd_count {} produced invalid response", qd);
        }
    }

    #[tokio::test]
    async fn dangling_compression_pointer_does_not_panic() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[5] = 1;
        buf.extend_from_slice(&[0xC0, 0xC8]); // pointer to offset 200, past end
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let r = drive(&buf).await;
        assert!(is_valid_response(&r));
    }

    #[tokio::test]
    async fn pointer_to_self_does_not_panic() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[5] = 1;
        buf.extend_from_slice(&[0xC0, HEADER_SIZE as u8]);
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let r = drive(&buf).await;
        assert!(is_valid_response(&r));
    }

    #[tokio::test]
    async fn random_payloads_never_panic() {
        // Deterministic LCG so the test is reproducible without an extra dep.
        let mut state: u64 = 0xDEADBEEFCAFEBABE;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        for _ in 0..100 {
            let len = (next() as usize % 4093) + 4;
            let mut buf = vec![0u8; len];
            for chunk in buf.chunks_mut(4) {
                let v = next();
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b = (v >> (i * 8)) as u8;
                }
            }
            let r = drive(&buf).await;
            assert!(is_valid_response(&r), "random payload produced invalid response");
        }
    }

    #[tokio::test]
    async fn unknown_qtype_does_not_panic() {
        for qtype in [0u16, 65535, 64, 65, 100, 200, 999] {
            let mut buf = vec![0u8; HEADER_SIZE];
            buf[5] = 1;
            buf.extend_from_slice(&[1, b'x', 0]);
            buf.extend_from_slice(&qtype.to_be_bytes());
            buf.extend_from_slice(&1u16.to_be_bytes());
            let r = drive(&buf).await;
            assert!(is_valid_response(&r), "qtype {} produced invalid response", qtype);
        }
    }

    #[tokio::test]
    async fn unknown_qclass_does_not_panic() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[5] = 1;
        buf.extend_from_slice(&[1, b'x', 0]);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&42u16.to_be_bytes());
        let r = drive(&buf).await;
        assert!(is_valid_response(&r));
    }

    #[tokio::test]
    async fn truncated_question_does_not_panic() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[5] = 1;
        buf.extend_from_slice(&[1, b'x', 0]);
        let r = drive(&buf).await;
        assert!(is_valid_response(&r));
    }
}
