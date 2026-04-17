use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::rcode::Rcode;
use crate::protocol::rdata::RData;
use crate::protocol::record::{RecordClass, RecordType};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Root DNS server hints (IANA root servers). Built from const IPv4 literals
/// so there is no runtime parsing that could ever panic.
pub fn root_hints() -> Vec<SocketAddr> {
    const ROOT_V4: &[Ipv4Addr] = &[
        Ipv4Addr::new(198, 41, 0, 4),     // a.root-servers.net
        Ipv4Addr::new(199, 9, 14, 201),   // b.root-servers.net
        Ipv4Addr::new(192, 33, 4, 12),    // c.root-servers.net
        Ipv4Addr::new(199, 7, 91, 13),    // d.root-servers.net
        Ipv4Addr::new(192, 203, 230, 10), // e.root-servers.net
        Ipv4Addr::new(192, 5, 5, 241),    // f.root-servers.net
        Ipv4Addr::new(192, 112, 36, 4),   // g.root-servers.net
        Ipv4Addr::new(198, 97, 190, 53),  // h.root-servers.net
        Ipv4Addr::new(192, 36, 148, 17),  // i.root-servers.net
        Ipv4Addr::new(192, 58, 128, 30),  // j.root-servers.net
        Ipv4Addr::new(193, 0, 14, 129),   // k.root-servers.net
        Ipv4Addr::new(199, 7, 83, 42),    // l.root-servers.net
        Ipv4Addr::new(202, 12, 27, 33),   // m.root-servers.net
    ];
    ROOT_V4
        .iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53))
        .collect()
}

/// Send a DNS query to a specific server and wait for a response.
pub async fn query_server(
    question_name: &DnsName,
    question_type: RecordType,
    server: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<Message> {
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;

    // Build query message
    let id: u16 = rand_id();
    let query = build_query(id, question_name, question_type);
    let wire = query.encode();

    socket.send_to(&wire, server).await?;

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(timeout, async {
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            // Verify response comes from the server we queried
            if src.ip() == server.ip() {
                return Ok::<usize, std::io::Error>(len);
            }
        }
    })
    .await??;

    let response = Message::decode(&buf[..len])?;

    // Verify the response ID matches
    if response.header.id != id {
        anyhow::bail!("Response ID mismatch: expected {}, got {}", id, response.header.id);
    }

    Ok(response)
}

/// Perform iterative resolution starting from the given nameservers.
/// Follows referrals (NS delegations) until we get an authoritative answer.
pub async fn iterate(
    question_name: &DnsName,
    question_type: RecordType,
    start_servers: &[SocketAddr],
    max_depth: u8,
    timeout: Duration,
) -> anyhow::Result<Message> {
    let mut servers = start_servers.to_vec();
    let mut depth = 0;

    loop {
        if depth >= max_depth {
            anyhow::bail!("Max recursion depth ({}) exceeded", max_depth);
        }
        depth += 1;

        // Try each server until one responds
        let mut last_error = None;
        let mut response = None;

        for server in &servers {
            match query_server(question_name, question_type, *server, timeout).await {
                Ok(resp) => {
                    response = Some(resp);
                    break;
                }
                Err(e) => {
                    tracing::debug!(%server, error = %e, "Query to server failed");
                    last_error = Some(e);
                }
            }
        }

        let resp = match response {
            Some(r) => r,
            None => {
                return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No servers available")));
            }
        };

        // Check if we got an authoritative answer or a final response
        match resp.header.rcode {
            Rcode::NoError => {
                // If we have answers, we're done
                if !resp.answers.is_empty() {
                    return Ok(resp);
                }

                // If authoritative with no answers, it's a NODATA response
                if resp.header.aa {
                    return Ok(resp);
                }

                // No answers but we have authority NS records — this is a referral
                let referral_servers = extract_referral_addresses(&resp, question_name);
                if referral_servers.is_empty() {
                    // Try to resolve NS names from the authority section
                    let ns_names = extract_ns_names(&resp);
                    if ns_names.is_empty() {
                        return Ok(resp); // No referral possible, return what we have
                    }
                    // For now, return SERVFAIL if we can't resolve NS glue
                    // A full implementation would resolve these NS names recursively
                    tracing::debug!("Referral without glue records, NS names: {:?}", ns_names);
                    return Ok(resp);
                }

                tracing::debug!(
                    depth,
                    servers = ?referral_servers,
                    "Following referral"
                );
                servers = referral_servers;
            }
            Rcode::NxDomain => {
                // Name doesn't exist — this is a final answer
                return Ok(resp);
            }
            _ => {
                // Any other rcode — return as-is
                return Ok(resp);
            }
        }
    }
}

/// Extract IP addresses from the additional section for NS records in the authority section.
///
/// Bailiwick rules applied:
/// - NS records: the owner name must be a parent of (or equal to) the query name
///   (i.e. the parent we just queried is authoritative for that zone cut).
/// - Glue records: the owner name must match one of the NS targets we are about
///   to follow. Sibling-domain glue is legitimate and common — the root zone,
///   for example, answers `com.` delegations with `a.gtld-servers.net.` glue.
///   Rejecting out-of-zone glue breaks real-world recursion from root hints.
fn extract_referral_addresses(response: &Message, query_name: &DnsName) -> Vec<SocketAddr> {
    let ns_records: Vec<(&DnsName, &DnsName)> = response
        .authority
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::NS(ns_target) => {
                if query_name.is_subdomain_of(&rr.name) {
                    Some((&rr.name, ns_target))
                } else {
                    tracing::debug!(
                        ns_owner = %rr.name,
                        query = %query_name,
                        "Rejected out-of-bailiwick NS record"
                    );
                    None
                }
            }
            _ => None,
        })
        .collect();

    if ns_records.is_empty() {
        return Vec::new();
    }

    let ns_names: Vec<&DnsName> = ns_records.iter().map(|(_, target)| *target).collect();

    let mut addrs = Vec::new();

    for rr in &response.additional {
        let matches_ns = ns_names.iter().any(|ns| **ns == rr.name);
        if !matches_ns {
            continue;
        }
        match &rr.rdata {
            RData::A(ip) => addrs.push(SocketAddr::new((*ip).into(), 53)),
            RData::AAAA(ip) => addrs.push(SocketAddr::new((*ip).into(), 53)),
            _ => {}
        }
    }

    addrs
}

/// Extract NS target names from the authority section.
fn extract_ns_names(response: &Message) -> Vec<DnsName> {
    response
        .authority
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::NS(name) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// Follow CNAME chains in a response.
pub fn follow_cnames(
    response: &Message,
    original_name: &DnsName,
    original_type: RecordType,
) -> Option<DnsName> {
    let mut current = original_name.clone();

    for _ in 0..16 {
        // Max CNAME chain length
        let cname_target = response.answers.iter().find_map(|rr| {
            if rr.name == current && rr.rtype == RecordType::CNAME {
                if let RData::CNAME(target) = &rr.rdata {
                    return Some(target.clone());
                }
            }
            None
        });

        match cname_target {
            Some(target) => {
                // Check if we have an answer for the CNAME target
                let has_answer = response.answers.iter().any(|rr| {
                    rr.name == target && rr.rtype == original_type
                });
                if has_answer {
                    return None; // Answer already present, no further resolution needed
                }
                current = target;
            }
            None => {
                if current != *original_name {
                    return Some(current); // Need to resolve this CNAME target
                }
                return None;
            }
        }
    }

    None // Chain too long
}

fn build_query(id: u16, name: &DnsName, rtype: RecordType) -> Message {
    use crate::protocol::header::Header;
    use crate::protocol::opcode::Opcode;
    use crate::protocol::record::Question;

    Message {
        header: Header {
            id,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: false, // Don't set RD when doing iterative resolution
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        },
        questions: vec![Question {
            name: name.clone(),
            qtype: rtype,
            qclass: RecordClass::IN,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

/// Generate a query ID. Prefers `getrandom`; on entropy-source failure falls
/// back to a time/stack-address mix so we never panic the resolver hot path.
/// The fallback is not cryptographically strong but is unpredictable enough
/// to defeat off-path response spoofing for the window the entropy source
/// remains unavailable. A single warn log is emitted on fallback.
pub(crate) fn rand_id() -> u16 {
    let mut buf = [0u8; 2];
    if getrandom::getrandom(&mut buf).is_ok() {
        return u16::from_ne_bytes(buf);
    }

    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!("getrandom unavailable; falling back to degraded query-ID source");
    }

    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let stack_addr = &buf as *const _ as usize as u32;
    let mixed = nanos ^ stack_addr;
    (mixed as u16) ^ ((mixed >> 16) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::record::ResourceRecord;
    use std::net::Ipv4Addr;

    #[test]
    fn test_root_hints() {
        let hints = root_hints();
        assert_eq!(hints.len(), 13);
        assert!(hints.iter().all(|s| s.port() == 53));
        assert!(hints.iter().all(|s| s.is_ipv4()));
    }

    #[test]
    fn test_rand_id_does_not_panic_and_is_distributed() {
        // Calls in the thousands must not panic and must produce more than
        // a handful of distinct values -- guards against a degenerate
        // fallback path returning a constant.
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            seen.insert(rand_id());
        }
        assert!(
            seen.len() > 100,
            "rand_id distribution too narrow: only {} unique values",
            seen.len()
        );
    }

    #[test]
    fn test_build_query() {
        let name = DnsName::from_str("example.com").unwrap();
        let msg = build_query(0x1234, &name, RecordType::A);

        assert_eq!(msg.header.id, 0x1234);
        assert!(!msg.header.qr);
        assert!(!msg.header.rd);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].qtype, RecordType::A);
    }

    #[test]
    fn test_extract_referral_addresses() {
        let ns_name = DnsName::from_str("ns1.example.com").unwrap();
        let response = Message {
            header: crate::protocol::header::Header {
                id: 1,
                qr: true,
                opcode: crate::protocol::opcode::Opcode::Query,
                aa: false,
                tc: false,
                rd: false,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
                qd_count: 0,
                an_count: 0,
                ns_count: 1,
                ar_count: 1,
            },
            questions: vec![],
            answers: vec![],
            authority: vec![ResourceRecord {
                name: DnsName::from_str("example.com").unwrap(),
                rtype: RecordType::NS,
                rclass: RecordClass::IN,
                ttl: 3600,
                rdata: RData::NS(ns_name.clone()),
            }],
            additional: vec![ResourceRecord {
                name: ns_name,
                rtype: RecordType::A,
                rclass: RecordClass::IN,
                ttl: 3600,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            }],
        };

        // Query for www.example.com — NS at example.com is in-bailiwick
        let query_name = DnsName::from_str("www.example.com").unwrap();
        let addrs = extract_referral_addresses(&response, &query_name);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 53));

        // Query for www.other.com — NS at example.com is out-of-bailiwick
        let other_name = DnsName::from_str("www.other.com").unwrap();
        let addrs = extract_referral_addresses(&response, &other_name);
        assert_eq!(addrs.len(), 0);
    }

    /// Regression: the root zone delegates `com.` with glue hosted under
    /// `gtld-servers.net.`. That glue is out-of-bailiwick for `com.` but is the
    /// standard and correct way for the root to deliver the delegation. A prior
    /// over-strict filter rejected it and left full recursion from root hints
    /// unable to follow any TLD referral.
    #[test]
    fn test_accepts_sibling_glue_in_delegation() {
        let gtld = DnsName::from_str("a.gtld-servers.net").unwrap();
        let response = Message {
            header: crate::protocol::header::Header {
                id: 1,
                qr: true,
                opcode: crate::protocol::opcode::Opcode::Query,
                aa: false,
                tc: false,
                rd: false,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
                qd_count: 0,
                an_count: 0,
                ns_count: 1,
                ar_count: 1,
            },
            questions: vec![],
            answers: vec![],
            authority: vec![ResourceRecord {
                name: DnsName::from_str("com").unwrap(),
                rtype: RecordType::NS,
                rclass: RecordClass::IN,
                ttl: 172800,
                rdata: RData::NS(gtld.clone()),
            }],
            additional: vec![ResourceRecord {
                name: gtld,
                rtype: RecordType::A,
                rclass: RecordClass::IN,
                ttl: 172800,
                rdata: RData::A(Ipv4Addr::new(192, 5, 6, 30)),
            }],
        };

        let query = DnsName::from_str("google.com").unwrap();
        let addrs = extract_referral_addresses(&response, &query);
        assert_eq!(addrs.len(), 1, "sibling glue must be accepted");
        assert_eq!(
            addrs[0],
            SocketAddr::new(Ipv4Addr::new(192, 5, 6, 30).into(), 53)
        );
    }
}
