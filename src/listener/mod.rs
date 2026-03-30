pub mod tcp;
pub mod tls;
pub mod udp;

use crate::auth::engine::{AuthEngine, AuthResult};
use crate::cache::entry::CacheKey;
use crate::cache::CacheStore;
use crate::protocol::rcode::Rcode;
use crate::protocol::{Header, Message};
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;

/// Process an incoming DNS query and produce a response.
/// Query flow: RPZ check -> Authoritative -> Resolver -> Cache -> SERVFAIL
async fn handle_query(
    buf: &[u8],
    cache: &CacheStore,
    resolver: &Option<Resolver>,
    auth: &Option<AuthEngine>,
    rpz: &RpzEngine,
) -> Vec<u8> {
    match Message::decode(buf) {
        Ok(query) => {
            tracing::debug!(
                id = query.header.id,
                questions = query.header.qd_count,
                "Received query"
            );

            if let Some(q) = query.questions.first() {
                // RPZ check first — block/redirect before any resolution
                if let Some(action) = rpz.check(&q.name) {
                    tracing::debug!(name = %q.name, action = ?action, "RPZ match");
                    if let Some(response) = rpz.apply_action(&action, &query) {
                        return response.encode();
                    }
                    // Passthru — continue normal resolution
                }

                // Try authoritative engine
                if let Some(auth_engine) = auth {
                    match auth_engine.query(&q.name, q.qtype, q.qclass) {
                        AuthResult::Answer(mut response) => {
                            response.header.id = query.header.id;
                            response.header.rd = query.header.rd;
                            return response.encode();
                        }
                        AuthResult::NotAuthoritative => {}
                    }
                }

                // Try resolver
                if let Some(resolver) = resolver {
                    let mut response = resolver.resolve(&q.name, q.qtype, q.qclass).await;
                    response.header.id = query.header.id;
                    response.header.rd = query.header.rd;
                    return response.encode();
                }

                // No resolver — check cache directly
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
                            ra: false,
                            ad: false,
                            cd: false,
                            rcode: if entry.negative {
                                Rcode::NxDomain
                            } else {
                                Rcode::NoError
                            },
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
            }

            Message::servfail(&query).encode()
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
