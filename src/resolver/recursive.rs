use crate::cache::entry::{CacheEntry, CacheKey};
use crate::cache::CacheStore;
use crate::config::ForwardZoneConfig;
use crate::dnssec::DnssecValidator;
use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::rcode::Rcode;
use crate::protocol::record::{RecordClass, RecordType};
use crate::resolver::forwarder::ForwarderPool;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

/// A parsed forward zone: domain suffix → upstream servers.
struct ForwardZone {
    /// Domain suffix to match (lowercase, with trailing dot).
    suffix: String,
    /// Upstream DNS servers for this zone.
    servers: Vec<SocketAddr>,
}

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
    /// Lazily initialized forwarder pool (one per first forwarder)
    forwarder_pool: OnceCell<ForwarderPool>,
    /// Per-domain forwarding rules (longest suffix match wins).
    forward_zones: Vec<ForwardZone>,
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
                forwarder_pool: OnceCell::new(),
                forward_zones: Vec::new(),
            }),
        }
    }

    /// Create a resolver with per-domain forward zones.
    pub fn with_forward_zones(
        cache: CacheStore,
        forwarders: Vec<SocketAddr>,
        max_depth: u8,
        dnssec_validator: DnssecValidator,
        qname_minimization: bool,
        zones: &[ForwardZoneConfig],
    ) -> Self {
        let forward_zones: Vec<ForwardZone> = zones
            .iter()
            .filter_map(|z| {
                let servers: Vec<SocketAddr> = z
                    .forwarders
                    .iter()
                    .filter_map(|s| {
                        if s.contains(':') {
                            s.parse().ok()
                        } else {
                            format!("{}:53", s).parse().ok()
                        }
                    })
                    .collect();
                if servers.is_empty() {
                    return None;
                }
                let mut suffix = z.name.to_lowercase();
                if !suffix.ends_with('.') {
                    suffix.push('.');
                }
                Some(ForwardZone { suffix, servers })
            })
            .collect();

        if !forward_zones.is_empty() {
            tracing::info!(count = forward_zones.len(), "Forward zones configured");
        }

        Self {
            inner: Arc::new(ResolverInner {
                cache,
                forwarders,
                root_hints: super::iterator::root_hints(),
                max_depth,
                query_timeout: Duration::from_secs(5),
                dnssec_validator,
                qname_minimization,
                forwarder_pool: OnceCell::new(),
                forward_zones,
            }),
        }
    }

    /// Find the best matching forward zone for a query name (longest suffix wins).
    fn match_forward_zone(&self, name: &DnsName) -> Option<&[SocketAddr]> {
        let qname = name.to_dotted().to_lowercase();
        let mut best: Option<(usize, &[SocketAddr])> = None;
        for fz in &self.inner.forward_zones {
            if qname.ends_with(&fz.suffix) || qname.trim_end_matches('.') == fz.suffix.trim_end_matches('.') {
                let len = fz.suffix.len();
                if best.map_or(true, |(bl, _)| len > bl) {
                    best = Some((len, &fz.servers));
                }
            }
        }
        best.map(|(_, servers)| servers)
    }

    /// Get or create the forwarder pool for the primary forwarder.
    async fn get_forwarder_pool(&self) -> Option<&ForwarderPool> {
        let server = self.inner.forwarders.first()?;
        let server = *server;
        // Try to initialize the pool; if it already failed, return None
        // and let the caller fall back to single-shot forwarding.
        if self.inner.forwarder_pool.get().is_none() {
            match ForwarderPool::new(server).await {
                Ok(pool) => {
                    let _ = self.inner.forwarder_pool.set(pool);
                    tracing::info!(%server, "Forwarder connection pool initialized");
                }
                Err(e) => {
                    tracing::error!(%server, error = %e, "Failed to create forwarder pool, using single-shot");
                    return None;
                }
            }
        }
        self.inner.forwarder_pool.get()
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

        // Resolve: check per-domain forward zones first, then global forwarders, then recursive
        let result = if let Some(zone_servers) = self.match_forward_zone(name) {
            tracing::debug!(name = %name, servers = ?zone_servers, "Using forward zone");
            super::forwarder::forward(name, rtype, zone_servers, self.inner.query_timeout).await
        } else if self.inner.forwarders.is_empty() {
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

    /// Forward to upstream resolvers using the connection pool.
    async fn resolve_forwarded(
        &self,
        name: &DnsName,
        rtype: RecordType,
    ) -> anyhow::Result<Message> {
        // Try the pooled forwarder first (much faster under concurrency)
        if let Some(pool) = self.get_forwarder_pool().await {
            match pool.query(name, rtype, self.inner.query_timeout).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!(error = %e, "Pooled forwarder failed, falling back");
                }
            }
        }

        // Fallback to single-shot forwarding
        super::forwarder::forward(
            name,
            rtype,
            &self.inner.forwarders,
            self.inner.query_timeout,
        )
        .await
    }

    /// Cache a successful DNS response with bailiwick validation.
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

        let negative_rcode = if response.header.rcode == Rcode::NxDomain {
            Rcode::NxDomain
        } else {
            Rcode::NoError // NODATA or positive
        };

        // Bailiwick validation: only cache records that are in-bailiwick
        // for the queried name's zone OR are part of the legitimate CNAME
        // chain starting from the query name.
        //
        // Without the CNAME-chain allowance the cache would drop the chained
        // A/AAAA record (whose owner is the CNAME's target, not the query
        // name) and only keep the CNAME itself. On the next lookup the
        // resolver returns CNAME-only and clients like pkg(8) / libfetch
        // decide there's no address — the symptom we just chased on the
        // build VM ("Address family for host not supported" from
        // pkg.FreeBSD.org despite a perfectly fine upstream reply).
        let query_name = &key.name;
        let chain_names: std::collections::HashSet<DnsName> = {
            let mut set = std::collections::HashSet::new();
            set.insert(query_name.clone());
            // Walk to a fixed point — answers may be in any order so a single
            // pass isn't enough. Bounded by the answer count, so cheap.
            loop {
                let mut grew = false;
                for rr in &response.answers {
                    if !set.contains(&rr.name) { continue; }
                    if let crate::protocol::rdata::RData::CNAME(target) = &rr.rdata {
                        if set.insert(target.clone()) { grew = true; }
                    }
                }
                if !grew { break; }
            }
            set
        };
        let answers: Vec<_> = response
            .answers
            .iter()
            .filter(|rr| chain_names.contains(&rr.name) || is_in_bailiwick(&rr.name, query_name))
            .cloned()
            .collect();
        let authority: Vec<_> = response
            .authority
            .iter()
            .filter(|rr| is_in_bailiwick_authority(&rr.name, query_name))
            .cloned()
            .collect();
        let additional: Vec<_> = response
            .additional
            .iter()
            .filter(|rr| {
                // Additional records should be glue for NS names in the authority section
                authority.iter().any(|auth| {
                    if let crate::protocol::rdata::RData::NS(ns_name) = &auth.rdata {
                        rr.name == *ns_name
                    } else {
                        false
                    }
                }) || is_in_bailiwick(&rr.name, query_name)
            })
            .cloned()
            .collect();

        let entry = CacheEntry::new(answers, authority, additional, ttl, negative, negative_rcode);

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
                    entry.negative_rcode
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
            edns: None,
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
            edns: None,
        }
    }
}

/// Check if a record name is in-bailiwick for the query.
/// A record is in-bailiwick if it's the query name itself, or a parent/ancestor of it.
fn is_in_bailiwick(record_name: &DnsName, query_name: &DnsName) -> bool {
    // Answer records should match the query name (or be in a CNAME chain)
    record_name == query_name || query_name.is_subdomain_of(record_name)
}

/// Check if an authority record name is in-bailiwick.
/// Authority records should be for a parent zone of the query name.
fn is_in_bailiwick_authority(record_name: &DnsName, query_name: &DnsName) -> bool {
    query_name.is_subdomain_of(record_name) || record_name == query_name
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

    /// Regression: cache_response was filtering out CNAME-target records via
    /// the bailiwick check, leaving only the CNAME in cache. Subsequent
    /// lookups returned CNAME-only and clients (pkg(8) / libfetch) treated
    /// the host as having no address.
    #[test]
    fn test_cache_response_keeps_cname_chain() {
        use crate::cache::entry::CacheKey;
        use crate::protocol::header::Header;
        use crate::protocol::message::Message;
        use crate::protocol::opcode::Opcode;
        use crate::protocol::rdata::RData;
        use crate::protocol::record::{Question, RecordClass, RecordType, ResourceRecord};
        use std::net::Ipv4Addr;

        let cache = CacheStore::new(1000, 60, 86400, 300);
        let validator = DnssecValidator::new(false);
        let resolver = Resolver::new(cache.clone(), vec![], 30, validator, true);

        let qname = DnsName::from_str("pkg.freebsd.org").unwrap();
        let target = DnsName::from_str("pkgmir.geo.freebsd.org").unwrap();
        let response = Message {
            header: Header {
                id: 1, qr: true, opcode: Opcode::Query,
                aa: false, tc: false, rd: true, ra: true,
                ad: false, cd: false, rcode: Rcode::NoError,
                qd_count: 1, an_count: 2, ns_count: 0, ar_count: 0,
            },
            questions: vec![Question {
                name: qname.clone(),
                qtype: RecordType::A,
                qclass: RecordClass::IN,
            }],
            answers: vec![
                ResourceRecord {
                    name: qname.clone(),
                    rtype: RecordType::CNAME,
                    rclass: RecordClass::IN,
                    ttl: 300,
                    rdata: RData::CNAME(target.clone()),
                },
                ResourceRecord {
                    name: target.clone(),
                    rtype: RecordType::A,
                    rclass: RecordClass::IN,
                    ttl: 300,
                    rdata: RData::A(Ipv4Addr::new(163, 237, 194, 42)),
                },
            ],
            authority: vec![],
            additional: vec![],
            edns: None,
        };

        let key = CacheKey::new(qname.clone(), RecordType::A, RecordClass::IN);
        resolver.cache_response(&key, &response);

        let entry = cache.lookup(&key).expect("entry should be cached");
        assert_eq!(entry.answers.len(), 2, "both CNAME and chained A must be cached");
        assert!(entry.answers.iter().any(|rr| matches!(rr.rdata, RData::A(_))),
            "chained A record must survive bailiwick filtering");
    }
}
