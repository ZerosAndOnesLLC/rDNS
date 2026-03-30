pub mod tcp;
pub mod udp;

use crate::cache::entry::CacheKey;
use crate::cache::CacheStore;
use crate::protocol::rcode::Rcode;
use crate::protocol::{Header, Message};

/// Process an incoming DNS query and produce a response.
/// Checks cache first, returns SERVFAIL on cache miss (until resolver is implemented).
fn handle_query(buf: &[u8], cache: &CacheStore) -> Vec<u8> {
    match Message::decode(buf) {
        Ok(query) => {
            tracing::debug!(
                id = query.header.id,
                questions = query.header.qd_count,
                "Received query"
            );

            // Check cache for the first question
            if let Some(q) = query.questions.first() {
                let key = CacheKey::new(q.name.clone(), q.qtype, q.qclass);
                if let Some(entry) = cache.lookup(&key) {
                    tracing::debug!(name = %q.name, rtype = %q.qtype, "Cache hit");
                    let response = Message {
                        header: Header {
                            id: query.header.id,
                            qr: true,
                            opcode: query.header.opcode,
                            aa: false,
                            tc: false,
                            rd: query.header.rd,
                            ra: true,
                            ad: false,
                            cd: false,
                            rcode: if entry.negative { Rcode::NxDomain } else { Rcode::NoError },
                            qd_count: query.header.qd_count,
                            an_count: entry.answers.len() as u16,
                            ns_count: entry.authority.len() as u16,
                            ar_count: entry.additional.len() as u16,
                        },
                        questions: query.questions.clone(),
                        answers: entry.answers_with_adjusted_ttl(),
                        authority: entry.authority_with_adjusted_ttl(),
                        additional: entry.additional_with_adjusted_ttl(),
                    };
                    return response.encode();
                }
                tracing::debug!(name = %q.name, rtype = %q.qtype, "Cache miss");
            }

            // No cache hit — return SERVFAIL until resolver is implemented
            let response = Message::servfail(&query);
            response.encode()
        }
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
