pub mod tcp;
pub mod tls;
pub mod udp;
#[allow(dead_code)]
pub mod udp_batch;

use crate::auth::engine::{AuthEngine, AuthResult};
use crate::cache::entry::CacheKey;
use crate::cache::CacheStore;
use crate::protocol::edns::{self, EdnsOpt, MIN_UDP_PAYLOAD_SIZE};
use crate::protocol::header::{Header, HEADER_SIZE};
use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::rcode::Rcode;
use crate::protocol::record::{RecordClass, RecordType};
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Global flag driving per-query logging. Set once at startup from
/// `[logging].query_log`. Checked on the hot path, so keep this branch
/// predictable and allocation-free when disabled.
static QUERY_LOG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Optional operator-configurable ceiling on a single query's resolution.
/// 0 = unset → listeners fall back to their per-transport defaults. Set
/// once at startup; read once per query via `Ordering::Relaxed` — cheaper
/// than reloading config on every packet.
static QUERY_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);

pub fn set_query_log_enabled(enabled: bool) {
    QUERY_LOG_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn set_query_timeout_ms(ms: u64) {
    QUERY_TIMEOUT_MS.store(ms, Ordering::Relaxed);
}

/// Resolve the effective query timeout for a listener, honoring the
/// operator override when set and otherwise returning the transport
/// default. Called once per query — branch-light and allocation-free.
#[inline]
pub(crate) fn effective_query_timeout(default: Duration) -> Duration {
    let override_ms = QUERY_TIMEOUT_MS.load(Ordering::Relaxed);
    if override_ms == 0 {
        default
    } else {
        Duration::from_millis(override_ms)
    }
}

#[inline]
fn query_log_enabled() -> bool {
    QUERY_LOG_ENABLED.load(Ordering::Relaxed)
}

/// Emit one INFO line per resolved query, when `[logging].query_log = true`.
/// Extracts qname/qtype from the raw query and rcode from the first 4 bytes
/// of the response (header flags low nibble). Silent on malformed packets —
/// the listener's FORMERR path already logs those separately at debug.
pub(crate) fn log_query(src: SocketAddr, query: &[u8], response: &[u8], transport: &'static str) {
    if !query_log_enabled() {
        return;
    }
    let Some((name, qtype, _qclass, _id, _rd)) = parse_query_fast(query) else {
        return;
    };
    let rcode = if response.len() >= 4 { response[3] & 0x0F } else { 0 };
    tracing::info!(
        target: "rdns::query",
        %src,
        qname = %name,
        qtype = %qtype,
        rcode = rcode,
        transport = transport,
        "query"
    );
}

/// Maximum UDP response size when the client did not advertise EDNS0 —
/// RFC 1035 §2.3.4.
const LEGACY_UDP_LIMIT: usize = 512;

/// RFC 6891 §9: BADVERS is extended RCODE 16. Low 4 bits (0) go in the
/// header rcode; high 8 bits (1) go in the OPT TTL's extended-rcode byte.
const BADVERS_EXTENDED_RCODE_HI: u8 = 1;

/// Extract the client's OPT pseudo-record from a raw DNS query, if any.
///
/// Walks the question and RR sections just enough to locate records in
/// additional and picks out the first OPT. Queries in the wild nearly
/// always have qd=1, an=ns=0, and ar∈{0,1} so the walk is short. Malformed
/// packets yield `None` and the caller treats the query as non-EDNS — the
/// listener's normal FORMERR / SERVFAIL paths take over if the packet is
/// actually broken.
pub(crate) fn parse_edns_from_query(buf: &[u8]) -> Option<EdnsOpt> {
    if buf.len() < HEADER_SIZE {
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    let an = u16::from_be_bytes([buf[6], buf[7]]);
    let ns = u16::from_be_bytes([buf[8], buf[9]]);
    let ar = u16::from_be_bytes([buf[10], buf[11]]);
    if ar == 0 {
        return None;
    }

    let mut offset = HEADER_SIZE;
    for _ in 0..qd {
        let (_, consumed) = DnsName::decode(buf, offset).ok()?;
        offset = offset.checked_add(consumed)?.checked_add(4)?; // qtype + qclass
    }
    for _ in 0..(an as u32 + ns as u32) {
        let (_, consumed) = DnsName::decode(buf, offset).ok()?;
        offset = offset.checked_add(consumed)?;
        if offset.checked_add(10)? > buf.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset = offset.checked_add(10)?.checked_add(rdlen)?;
    }
    for _ in 0..ar {
        let (_, consumed) = DnsName::decode(buf, offset).ok()?;
        offset = offset.checked_add(consumed)?;
        if offset.checked_add(10)? > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let class = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        let rdata_start = offset + 10;
        let rdata_end = rdata_start.checked_add(rdlen)?;
        if rdata_end > buf.len() {
            return None;
        }
        if rtype == u16::from(RecordType::OPT) {
            return EdnsOpt::from_rr_fields(class, ttl, &buf[rdata_start..rdata_end]).ok();
        }
        offset = rdata_end;
    }
    None
}

/// Effective UDP response size for this query: honor the client's EDNS
/// advertisement, clamped into [MIN_UDP_PAYLOAD_SIZE, server runtime size].
/// No EDNS ⇒ RFC 1035 legacy 512 B ceiling.
pub(crate) fn effective_udp_response_size(client_edns: Option<&EdnsOpt>) -> usize {
    match client_edns {
        Some(opt) => opt
            .udp_payload_size
            .max(MIN_UDP_PAYLOAD_SIZE)
            .min(edns::runtime().udp_payload_size) as usize,
        None => LEGACY_UDP_LIMIT,
    }
}

/// The OPT record we attach to a response. Emitted only when the query
/// carried OPT — RFC 6891 §6.1.1 forbids introducing an OPT the client
/// did not ask for.
pub(crate) fn server_edns_opt() -> EdnsOpt {
    EdnsOpt {
        udp_payload_size: edns::runtime().udp_payload_size,
        extended_rcode: 0,
        version: 0,
        // We don't yet validate DNSSEC; don't claim AD/DO capability.
        dnssec_ok: false,
        z: 0,
        options: Vec::new(),
    }
}

/// Append `opt` as a pseudo-RR to `buf` and increment the header's AR count.
/// Used by fast-path builders that produce raw wire bytes directly.
fn append_opt_and_bump_ar(buf: &mut Vec<u8>, opt: &EdnsOpt) {
    opt.encode_rr(buf);
    if buf.len() >= HEADER_SIZE {
        let ar = u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
        buf[10..12].copy_from_slice(&ar.to_be_bytes());
    }
}

/// Fast-path: extract query name and type from raw wire format without full decode.
/// Returns (name, qtype, qclass, id, rd_flag) or None if parse fails.
pub(crate) fn parse_query_fast(buf: &[u8]) -> Option<(DnsName, RecordType, RecordClass, u16, bool)> {
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
/// When `client_edns` is `Some`, appends our server OPT as the final
/// additional record and bumps ar_count accordingly (RFC 6891 §6.1.1).
fn build_cached_response_fast(
    entry: &crate::cache::entry::CacheEntry,
    id: u16,
    rd: bool,
    qname: &DnsName,
    qtype: RecordType,
    qclass: RecordClass,
    client_edns: Option<&EdnsOpt>,
) -> Vec<u8> {
    let rcode = if entry.negative { entry.negative_rcode } else { Rcode::NoError };
    let remaining_ttl = entry.remaining_ttl();
    let extra_ar = if client_edns.is_some() { 1 } else { 0 };

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
        ar_count: entry.additional.len() as u16 + extra_ar,
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

    if client_edns.is_some() {
        server_edns_opt().encode_rr(&mut buf);
    }

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
fn build_refused_fast(
    id: u16,
    rd: bool,
    name: &DnsName,
    qtype: RecordType,
    qclass: RecordClass,
    client_edns: Option<&EdnsOpt>,
) -> Vec<u8> {
    let extra_ar = if client_edns.is_some() { 1 } else { 0 };
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
        ar_count: extra_ar,
    };

    let mut buf = Vec::with_capacity(64);
    header.encode(&mut buf);
    name.encode(&mut buf);
    buf.extend_from_slice(&u16::from(qtype).to_be_bytes());
    buf.extend_from_slice(&u16::from(qclass).to_be_bytes());
    if client_edns.is_some() {
        server_edns_opt().encode_rr(&mut buf);
    }
    buf
}

/// Build a BADVERS response (RFC 6891 §6.1.3) for a query carrying an EDNS
/// version we do not support. Header rcode stays NoError (low 4 bits of
/// extended rcode 16 are 0); OPT TTL carries the extended-rcode high byte
/// = 1 and advertises our highest supported VERSION (0). The client will
/// retry with that lower version.
fn build_badvers_fast(
    id: u16,
    name: &DnsName,
    qtype: RecordType,
    qclass: RecordClass,
) -> Vec<u8> {
    let header = Header {
        id,
        qr: true,
        opcode: crate::protocol::Opcode::from(0),
        aa: false,
        tc: false,
        rd: false,
        ra: false,
        ad: false,
        cd: false,
        rcode: Rcode::NoError,
        qd_count: 1,
        an_count: 0,
        ns_count: 0,
        ar_count: 1,
    };
    let mut buf = Vec::with_capacity(64);
    header.encode(&mut buf);
    name.encode(&mut buf);
    buf.extend_from_slice(&u16::from(qtype).to_be_bytes());
    buf.extend_from_slice(&u16::from(qclass).to_be_bytes());
    let opt = EdnsOpt {
        udp_payload_size: edns::runtime().udp_payload_size,
        extended_rcode: BADVERS_EXTENDED_RCODE_HI,
        version: 0,
        dnssec_ok: false,
        z: 0,
        options: Vec::new(),
    };
    opt.encode_rr(&mut buf);
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
    let client_edns = parse_edns_from_query(buf);

    // BADVERS short-circuit (RFC 6891 §6.1.3): an EDNS version we don't
    // implement is answered only with an OPT that advertises our highest
    // supported version, nothing else.
    if let Some(opt) = &client_edns {
        if opt.is_unsupported_version() {
            if let Some((name, qtype, qclass, id, _rd)) = parse_query_fast(buf) {
                return build_badvers_fast(id, &name, qtype, qclass);
            }
            // Fall through to FORMERR if we can't even parse the question.
        }
    }

    let client_edns_ref = client_edns.as_ref();

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
                if let Some(mut response) = rpz.apply_action(&action, &query) {
                    if client_edns.is_some() {
                        response.edns = Some(server_edns_opt());
                    }
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
                    if client_edns.is_some() {
                        response.edns = Some(server_edns_opt());
                    }
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
                if client_edns.is_some() {
                    response.edns = Some(server_edns_opt());
                }
                return response.encode();
            } else {
                // Client wants recursion but is not allowed — return REFUSED
                return build_refused_fast(id, rd, &name, qtype, qclass, client_edns_ref);
            }
        }

        // Direct cache lookup (no resolver mode)
        let key = CacheKey::new(name.clone(), qtype, qclass);
        if let Some(entry) = cache.lookup(&key) {
            return build_cached_response_fast(&entry, id, rd, &name, qtype, qclass, client_edns_ref);
        }

        // SERVFAIL
        return build_servfail_fast(id, rd, &name, qtype, qclass, client_edns_ref);
    }

    // Slow path: full decode for malformed/multi-question queries
    match Message::decode(buf) {
        Ok(query) => Message::servfail(&query).encode(),
        Err(e) => {
            // DEBUG-level: every malformed UDP packet (including unsolicited
            // noise from scanners, mis-routed traffic, and deliberate floods)
            // lands here. WARN was a log-DoS: one attacker flooding garbage
            // could trivially fill disks / overwhelm syslog. A well-formed
            // FORMERR response still goes back to the sender.
            tracing::debug!(error = %e, "Failed to parse query");
            let id = if buf.len() >= 2 {
                u16::from_be_bytes([buf[0], buf[1]])
            } else {
                0
            };
            Message::formerr(id).encode()
        }
    }
}

/// Truncate a UDP response if it exceeds the effective size negotiated with
/// the client. If `server_opt` is `Some`, an OPT is re-appended after the
/// stripped question section so the client still learns our advertised
/// payload size (RFC 6891 §7 recommends keeping OPT on truncated replies).
pub(crate) fn truncate_udp_response(
    response: &mut Vec<u8>,
    effective_size: usize,
    server_opt: Option<&EdnsOpt>,
) {
    if response.len() <= effective_size {
        return;
    }
    // Set TC bit in the header flags (byte 2, bit 1 of the high nibble)
    if response.len() >= HEADER_SIZE {
        response[2] |= 0x02; // TC bit is bit 9 of flags = byte 2, bit 1

        // Zero out answer, authority, additional counts (keep question count)
        // AN count at bytes 6-7, NS count at 8-9, AR count at 10-11
        response[6..12].fill(0);
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

    // Re-append our OPT if the client advertised EDNS. An OPT with no
    // options is ~11 bytes and always fits inside the 512 B floor, so
    // this cannot push the response back over `effective_size`.
    if let Some(opt) = server_opt {
        append_opt_and_bump_ar(response, opt);
    }
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

/// Classify an error from `TcpListener::accept()` as recoverable.
///
/// A transient error means the listening socket itself is still healthy —
/// a client aborted mid-handshake, the process was interrupted by a signal,
/// or we are briefly out of file descriptors. The accept loop must continue
/// on these, or a single probe can permanently disable TCP DNS (see #72).
///
/// Fatal errors (e.g. `EBADF`, `EINVAL`) indicate the listener socket is
/// broken and the loop should surface the error to its supervisor.
pub(crate) fn is_transient_accept_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        err.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
            | ErrorKind::TimedOut
    ) {
        return true;
    }
    if let Some(code) = err.raw_os_error() {
        return code == libc::ECONNABORTED
            || code == libc::ECONNRESET
            || code == libc::EINTR
            || code == libc::EMFILE
            || code == libc::ENFILE
            || code == libc::EPROTO
            || code == libc::ETIMEDOUT;
    }
    false
}

/// Per-process / per-system fd exhaustion. The accept loop should back off
/// briefly instead of hot-spinning, since every call will fail until some
/// existing connection closes.
pub(crate) fn is_resource_exhaustion(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
}

fn build_servfail_fast(
    id: u16,
    rd: bool,
    name: &DnsName,
    qtype: RecordType,
    qclass: RecordClass,
    client_edns: Option<&EdnsOpt>,
) -> Vec<u8> {
    let extra_ar = if client_edns.is_some() { 1 } else { 0 };
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
        ar_count: extra_ar,
    };

    let mut buf = Vec::with_capacity(64);
    header.encode(&mut buf);
    name.encode(&mut buf);
    buf.extend_from_slice(&u16::from(qtype).to_be_bytes());
    buf.extend_from_slice(&u16::from(qclass).to_be_bytes());
    if client_edns.is_some() {
        server_edns_opt().encode_rr(&mut buf);
    }
    buf
}

#[cfg(test)]
mod accept_error_tests {
    //! Regression tests for #72: a single transient accept() error must not
    //! permanently kill the TCP / DoT listener.

    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn econnaborted_is_transient() {
        // The exact error observed in production (FreeBSD errno 53).
        let err = Error::from_raw_os_error(libc::ECONNABORTED);
        assert!(is_transient_accept_error(&err));
        assert!(!is_resource_exhaustion(&err));
    }

    #[test]
    fn connection_reset_is_transient() {
        let err = Error::from_raw_os_error(libc::ECONNRESET);
        assert!(is_transient_accept_error(&err));
    }

    #[test]
    fn interrupted_is_transient() {
        let err = Error::from(ErrorKind::Interrupted);
        assert!(is_transient_accept_error(&err));
        let err_raw = Error::from_raw_os_error(libc::EINTR);
        assert!(is_transient_accept_error(&err_raw));
    }

    #[test]
    fn timed_out_is_transient() {
        let err = Error::from(ErrorKind::TimedOut);
        assert!(is_transient_accept_error(&err));
    }

    #[test]
    fn eproto_is_transient() {
        let err = Error::from_raw_os_error(libc::EPROTO);
        assert!(is_transient_accept_error(&err));
    }

    #[test]
    fn emfile_is_transient_and_exhaustion() {
        let err = Error::from_raw_os_error(libc::EMFILE);
        assert!(is_transient_accept_error(&err));
        assert!(is_resource_exhaustion(&err));
    }

    #[test]
    fn enfile_is_transient_and_exhaustion() {
        let err = Error::from_raw_os_error(libc::ENFILE);
        assert!(is_transient_accept_error(&err));
        assert!(is_resource_exhaustion(&err));
    }

    #[test]
    fn permission_denied_is_fatal() {
        let err = Error::from(ErrorKind::PermissionDenied);
        assert!(!is_transient_accept_error(&err));
    }

    #[test]
    fn bad_fd_is_fatal() {
        // EBADF indicates the listener socket itself is broken.
        let err = Error::from_raw_os_error(libc::EBADF);
        assert!(!is_transient_accept_error(&err));
    }

    #[test]
    fn invalid_input_is_fatal() {
        let err = Error::from(ErrorKind::InvalidInput);
        assert!(!is_transient_accept_error(&err));
    }
}

#[cfg(test)]
mod edns_listener_tests {
    //! Phase C: EDNS(0) buffer-size negotiation, BADVERS, OPT on responses.

    use super::*;
    use crate::protocol::edns::{EdnsOpt, EdnsOption};
    use crate::rpz::RpzEngine;

    fn build_query_with_opt(id: u16, qname: &str, opt: &EdnsOpt) -> Vec<u8> {
        let header = Header {
            id,
            qr: false,
            opcode: crate::protocol::opcode::Opcode::Query,
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
            ar_count: 1,
        };
        let mut buf = Vec::with_capacity(64);
        header.encode(&mut buf);
        DnsName::from_str(qname).unwrap().encode(&mut buf);
        buf.extend_from_slice(&u16::from(RecordType::A).to_be_bytes());
        buf.extend_from_slice(&u16::from(RecordClass::IN).to_be_bytes());
        opt.encode_rr(&mut buf);
        buf
    }

    fn build_query_without_opt(id: u16, qname: &str) -> Vec<u8> {
        let header = Header {
            id,
            qr: false,
            opcode: crate::protocol::opcode::Opcode::Query,
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
        let mut buf = Vec::with_capacity(64);
        header.encode(&mut buf);
        DnsName::from_str(qname).unwrap().encode(&mut buf);
        buf.extend_from_slice(&u16::from(RecordType::A).to_be_bytes());
        buf.extend_from_slice(&u16::from(RecordClass::IN).to_be_bytes());
        buf
    }

    #[test]
    fn parse_edns_extracts_client_opt() {
        let expected = EdnsOpt {
            udp_payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: true,
            z: 0,
            options: vec![EdnsOption { code: 10, data: b"cookie12".to_vec() }],
        };
        let wire = build_query_with_opt(0xAB, "example.com", &expected);
        let got = parse_edns_from_query(&wire).expect("must find OPT");
        assert_eq!(got, expected);
    }

    #[test]
    fn parse_edns_returns_none_without_opt() {
        let wire = build_query_without_opt(1, "example.com");
        assert!(parse_edns_from_query(&wire).is_none());
    }

    #[test]
    fn effective_size_honors_client_advertisement() {
        let runtime_size = edns::runtime().udp_payload_size;
        let mut opt = EdnsOpt::default();
        opt.udp_payload_size = 4096;
        // Clamped to the server's configured runtime size.
        assert_eq!(
            effective_udp_response_size(Some(&opt)),
            runtime_size as usize
        );

        opt.udp_payload_size = 768;
        assert_eq!(effective_udp_response_size(Some(&opt)), 768);

        // Buggy client advertises below the 512 floor.
        opt.udp_payload_size = 200;
        assert_eq!(effective_udp_response_size(Some(&opt)), MIN_UDP_PAYLOAD_SIZE as usize);
    }

    #[test]
    fn effective_size_falls_back_to_legacy_without_edns() {
        assert_eq!(effective_udp_response_size(None), LEGACY_UDP_LIMIT);
    }

    #[tokio::test]
    async fn badvers_returned_for_unsupported_version() {
        // EDNS version 1 — we only implement 0.
        let opt = EdnsOpt {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 1,
            dnssec_ok: false,
            z: 0,
            options: Vec::new(),
        };
        let wire = build_query_with_opt(0x1234, "example.com", &opt);

        let cache = CacheStore::new(1000, 60, 86400, 60);
        let rpz = RpzEngine::new();
        let resp = handle_query(&wire, &cache, &None, &None, &rpz, true).await;

        // Header id preserved
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x1234);
        // QR=1
        assert!(resp[2] & 0x80 != 0);
        // Low 4 bits of rcode = 0 (BADVERS extended-rcode is 16; low nibble is 0)
        assert_eq!(resp[3] & 0x0F, 0);
        // Decode to verify the OPT carries the BADVERS extended-rcode.
        let decoded = Message::decode(&resp).unwrap();
        let reply_opt = decoded.edns.expect("BADVERS reply must carry OPT");
        assert_eq!(reply_opt.extended_rcode, BADVERS_EXTENDED_RCODE_HI);
        assert_eq!(reply_opt.version, 0, "we advertise our highest supported");
    }

    #[tokio::test]
    async fn response_includes_opt_when_client_sent_opt() {
        // SERVFAIL path (no resolver / auth / cache entry) must still carry
        // OPT back because the client asked in EDNS.
        let opt = EdnsOpt {
            udp_payload_size: 2048,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: Vec::new(),
        };
        let wire = build_query_with_opt(0x55AA, "example.com", &opt);

        let cache = CacheStore::new(1000, 60, 86400, 60);
        let rpz = RpzEngine::new();
        let resp = handle_query(&wire, &cache, &None, &None, &rpz, true).await;

        let decoded = Message::decode(&resp).unwrap();
        assert_eq!(decoded.header.rcode, Rcode::ServFail);
        assert!(decoded.edns.is_some(), "OPT-on-query implies OPT-on-response");
        assert_eq!(
            decoded.edns.unwrap().udp_payload_size,
            edns::runtime().udp_payload_size,
            "server advertises its own policy, not the client's"
        );
    }

    #[tokio::test]
    async fn response_omits_opt_when_client_did_not_send_opt() {
        let wire = build_query_without_opt(0x33, "example.com");

        let cache = CacheStore::new(1000, 60, 86400, 60);
        let rpz = RpzEngine::new();
        let resp = handle_query(&wire, &cache, &None, &None, &rpz, true).await;

        let decoded = Message::decode(&resp).unwrap();
        assert!(decoded.edns.is_none(), "must not introduce OPT the client didn't ask for");
    }

    #[test]
    fn truncate_preserves_opt_when_client_had_edns() {
        // Build a synthetic large response: question + enough garbage answers
        // to exceed 512 B. Truncation must strip the answers, set TC, and
        // re-append our OPT so the client still learns the server's size.
        let header = Header {
            id: 1,
            qr: true,
            opcode: crate::protocol::opcode::Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
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
        DnsName::from_str("example.com").unwrap().encode(&mut buf);
        buf.extend_from_slice(&u16::from(RecordType::A).to_be_bytes());
        buf.extend_from_slice(&u16::from(RecordClass::IN).to_be_bytes());
        // Pad past the 512 B ceiling.
        buf.extend(std::iter::repeat(0u8).take(600));

        let server_opt = server_edns_opt();
        truncate_udp_response(&mut buf, LEGACY_UDP_LIMIT, Some(&server_opt));

        // TC set
        assert!(buf[2] & 0x02 != 0, "TC bit must be set");
        // Fits inside the effective size.
        assert!(buf.len() <= LEGACY_UDP_LIMIT);
        // Reparse — question preserved, OPT re-appended.
        let decoded = Message::decode(&buf).unwrap();
        assert_eq!(decoded.questions.len(), 1);
        assert!(decoded.edns.is_some(), "OPT must survive truncation");
    }

    #[test]
    fn truncate_is_noop_when_response_fits() {
        let mut buf = vec![0u8; 100];
        // Valid-enough header bytes
        buf[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        buf[2] = 0x80; // qr=1
        buf[3] = 0;
        let before = buf.clone();
        truncate_udp_response(&mut buf, 512, None);
        assert_eq!(buf, before, "fit = no-op");
    }
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
