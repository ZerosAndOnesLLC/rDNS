use crate::cache::entry::{CacheEntry, CacheKey};
use crate::cache::CacheStore;
use crate::dnssec::DnssecValidator;
use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::rcode::Rcode;
use crate::protocol::record::{RecordClass, RecordType};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// The main recursive resolver.
#[derive(Clone)]
pub struct Resolver {
    inner: Arc<ResolverInner>,
}

struct ResolverInner {
    cache: CacheStore,
    forwarders: Vec<SocketAddr>,
    root_hints: Vec<SocketAddr>,
    max_depth: u8,
    query_timeout: Duration,
    dnssec_validator: DnssecValidator,
    qname_minimization: bool,
}

impl Resolver {
    pub fn new(
        cache: CacheStore,
        forwarders: Vec<SocketAddr>,
        max_depth: u8,
        dnssec_validator: DnssecValidator,
        qname_minimization: bool,
    ) -> Self {
        Self {
            inner: Arc::new(ResolverInner {
                cache,
                forwarders,
                root_hints: super::iterator::root_hints(),
                max_depth,
                query_timeout: Duration::from_secs(5),
                dnssec_validator,
                qname_minimization,
            }),
        }
    }

    /// Resolve a DNS query. Checks cache first, then resolves recursively or forwards.
    pub async fn resolve(
        &self,
        name: &DnsName,
        rtype: RecordType,
        rclass: RecordClass,
    ) -> Message {
        // Check cache
        let key = CacheKey::new(name.clone(), rtype, rclass);
        if let Some(entry) = self.inner.cache.lookup(&key) {
            return self.build_cached_response(name, rtype, rclass, &entry);
        }

        // Resolve
        let result = if self.inner.forwarders.is_empty() {
            self.resolve_recursive(name, rtype).await
        } else {
            self.resolve_forwarded(name, rtype).await
        };

        match result {
            Ok(mut response) => {
                // DNSSEC validation
                let status = self.inner.dnssec_validator.validate(&response);
                DnssecValidator::set_ad_bit(&mut response, status);

                // Cache the response
                self.cache_response(&key, &response);
                response
            }
            Err(e) => {
                tracing::warn!(name = %name, rtype = %rtype, error = %e, "Resolution failed");
                self.build_servfail(name, rtype, rclass)
            }
        }
    }

    /// Full recursive resolution from root hints.
    async fn resolve_recursive(
        &self,
        name: &DnsName,
        rtype: RecordType,
    ) -> anyhow::Result<Message> {
        if self.inner.qname_minimization {
            tracing::trace!(name = %name, "QNAME minimization enabled");
        }

        let response = super::iterator::iterate(
            name,
            rtype,
            &self.inner.root_hints,
            self.inner.max_depth,
            self.inner.query_timeout,
        )
        .await?;

        // Handle CNAME chains
        if let Some(cname_target) = super::iterator::follow_cnames(&response, name, rtype) {
            tracing::debug!(
                original = %name,
                cname = %cname_target,
                "Following CNAME"
            );
            let cname_response = super::iterator::iterate(
                &cname_target,
                rtype,
                &self.inner.root_hints,
                self.inner.max_depth,
                self.inner.query_timeout,
            )
            .await?;

            // Merge: original CNAME answers + target answers
            let mut merged = response;
            for answer in cname_response.answers {
                if !merged.answers.contains(&answer) {
                    merged.answers.push(answer);
                }
            }
            merged.header.an_count = merged.answers.len() as u16;
            return Ok(merged);
        }

        Ok(response)
    }

    /// Forward to upstream resolvers.
    async fn resolve_forwarded(
        &self,
        name: &DnsName,
        rtype: RecordType,
    ) -> anyhow::Result<Message> {
        super::forwarder::forward(
            name,
            rtype,
            &self.inner.forwarders,
            self.inner.query_timeout,
        )
        .await
    }

    /// Cache a successful DNS response.
    fn cache_response(&self, key: &CacheKey, response: &Message) {
        let ttl = response
            .answers
            .iter()
            .map(|rr| rr.ttl)
            .min()
            .or_else(|| {
                response.authority.iter().find_map(|rr| {
                    if let crate::protocol::rdata::RData::SOA(soa) = &rr.rdata {
                        Some(soa.minimum)
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(300);

        let negative = response.header.rcode == Rcode::NxDomain
            || (response.header.rcode == Rcode::NoError && response.answers.is_empty());

        let entry = CacheEntry::new(
            response.answers.clone(),
            response.authority.clone(),
            response.additional.clone(),
            ttl,
            negative,
        );

        self.inner.cache.insert(key.clone(), entry);
    }

    fn build_cached_response(
        &self,
        name: &DnsName,
        rtype: RecordType,
        rclass: RecordClass,
        entry: &CacheEntry,
    ) -> Message {
        use crate::protocol::header::Header;
        use crate::protocol::opcode::Opcode;
        use crate::protocol::record::Question;

        Message {
            header: Header {
                id: 0,
                qr: true,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                ad: false,
                cd: false,
                rcode: if entry.negative {
                    Rcode::NxDomain
                } else {
                    Rcode::NoError
                },
                qd_count: 1,
                an_count: entry.answers.len() as u16,
                ns_count: entry.authority.len() as u16,
                ar_count: entry.additional.len() as u16,
            },
            questions: vec![Question {
                name: name.clone(),
                qtype: rtype,
                qclass: rclass,
            }],
            answers: entry.answers_with_adjusted_ttl(),
            authority: entry.authority_with_adjusted_ttl(),
            additional: entry.additional_with_adjusted_ttl(),
        }
    }

    fn build_servfail(
        &self,
        name: &DnsName,
        rtype: RecordType,
        rclass: RecordClass,
    ) -> Message {
        use crate::protocol::header::Header;
        use crate::protocol::opcode::Opcode;
        use crate::protocol::record::Question;

        Message {
            header: Header {
                id: 0,
                qr: true,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                ad: false,
                cd: false,
                rcode: Rcode::ServFail,
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                name: name.clone(),
                qtype: rtype,
                qclass: rclass,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_creation() {
        let cache = CacheStore::new(1000, 60, 86400, 300);
        let validator = DnssecValidator::new(true);
        let resolver = Resolver::new(cache, vec![], 30, validator, true);
        assert!(resolver.inner.forwarders.is_empty());
        assert_eq!(resolver.inner.root_hints.len(), 13);
    }
}
