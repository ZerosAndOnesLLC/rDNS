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
    /// TTL sent to clients when we return a stale answer (RFC 8767 §5
    /// recommends a small value — default 30 s — so clients re-query
    /// soon and pick up fresh data once upstream recovers).
    stale_answer_ttl: u32,
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
        stale_answer_ttl: u32,
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
                stale_answer_ttl,
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
        stale_answer_ttl: u32,
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
                stale_answer_ttl,
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
                // Serve-stale fallback (RFC 8767). Only activates if the
                // cache has a non-zero stale window — `lookup_stale`
                // returns None otherwise.
                if let Some(stale) = self.inner.cache.lookup_stale(&key) {
                    tracing::info!(
                        name = %name,
                        rtype = %rtype,
                        error = %e,
                        staleness_secs = stale.staleness_secs(),
                        "Upstream failed; serving stale answer"
                    );
                    return self.build_stale_response(name, rtype, rclass, &stale);
                }
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
            // minimal-responses: keep authority only when the client needs
            // SOA for negative caching; drop additional unconditionally.
            authority: if crate::listener::minimal_keep_authority(entry.negative) {
                entry.authority_with_adjusted_ttl()
            } else {
                Vec::new()
            },
            additional: Vec::new(),
            edns: None,
        }
    }

    /// Build a response from a stale cache entry (RFC 8767). Same shape as
    /// `build_cached_response` but every record's TTL is clamped to the
    /// configured stale-answer TTL so clients re-query quickly once upstream
    /// recovers instead of latching the stale data for its original TTL.
    fn build_stale_response(
        &self,
        name: &DnsName,
        rtype: RecordType,
        rclass: RecordClass,
        entry: &CacheEntry,
    ) -> Message {
        use crate::protocol::header::Header;
        use crate::protocol::opcode::Opcode;
        use crate::protocol::record::{Question, ResourceRecord};

        let stale_ttl = self.inner.stale_answer_ttl;
        let with_stale_ttl = |records: &[ResourceRecord]| -> Vec<ResourceRecord> {
            records
                .iter()
                .map(|rr| ResourceRecord {
                    name: rr.name.clone(),
                    rtype: rr.rtype,
                    rclass: rr.rclass,
                    ttl: stale_ttl,
                    rdata: rr.rdata.clone(),
                })
                .collect()
        };

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
            answers: with_stale_ttl(&entry.answers),
            authority: if crate::listener::minimal_keep_authority(entry.negative) {
                with_stale_ttl(&entry.authority)
            } else {
                Vec::new()
            },
            additional: Vec::new(),
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
        let resolver = Resolver::new(cache, vec![], 30, validator, true, 30);
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
        let resolver = Resolver::new(cache.clone(), vec![], 30, validator, true, 30);

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

    /// Cached positive answers should ship without authority/additional —
    /// stubs never use them and carrying NS / glue fills UDP budget for
    /// nothing.
    #[test]
    fn build_cached_response_drops_authority_and_additional_on_positive() {
        use crate::cache::entry::CacheEntry;
        use crate::protocol::rdata::RData;
        use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
        use std::net::Ipv4Addr;

        let cache = CacheStore::new(1000, 60, 86400, 300);
        let validator = DnssecValidator::new(false);
        let resolver = Resolver::new(cache, vec![], 30, validator, true, 30);

        let qname = DnsName::from_str("www.example.com").unwrap();
        let entry = CacheEntry {
            answers: vec![ResourceRecord {
                name: qname.clone(),
                rtype: RecordType::A,
                rclass: RecordClass::IN,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
            }],
            authority: vec![ResourceRecord {
                name: DnsName::from_str("example.com").unwrap(),
                rtype: RecordType::NS,
                rclass: RecordClass::IN,
                ttl: 300,
                rdata: RData::NS(DnsName::from_str("ns.example.com").unwrap()),
            }],
            additional: vec![ResourceRecord {
                name: DnsName::from_str("ns.example.com").unwrap(),
                rtype: RecordType::A,
                rclass: RecordClass::IN,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            }],
            negative: false,
            negative_rcode: Rcode::NoError,
            original_ttl: 300,
            inserted_at: std::time::Instant::now(),
            hit_count: 0,
        };

        let msg = resolver.build_cached_response(&qname, RecordType::A, RecordClass::IN, &entry);
        assert_eq!(msg.answers.len(), 1);
        assert!(msg.authority.is_empty(), "positive response must drop authority");
        assert!(msg.additional.is_empty(), "positive response must drop additional");
    }

    /// Negative cached responses need the SOA in authority so downstream
    /// stubs can do negative caching per RFC 2308. Additional still gets
    /// dropped.
    #[test]
    fn build_cached_response_keeps_authority_on_negative() {
        use crate::cache::entry::CacheEntry;
        use crate::protocol::rdata::{RData, SoaData};
        use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};

        let cache = CacheStore::new(1000, 60, 86400, 300);
        let validator = DnssecValidator::new(false);
        let resolver = Resolver::new(cache, vec![], 30, validator, true, 30);

        let qname = DnsName::from_str("nope.example.com").unwrap();
        let entry = CacheEntry {
            answers: vec![],
            authority: vec![ResourceRecord {
                name: DnsName::from_str("example.com").unwrap(),
                rtype: RecordType::SOA,
                rclass: RecordClass::IN,
                ttl: 300,
                rdata: RData::SOA(SoaData {
                    mname: DnsName::from_str("ns.example.com").unwrap(),
                    rname: DnsName::from_str("admin.example.com").unwrap(),
                    serial: 1, refresh: 3600, retry: 900, expire: 604800, minimum: 300,
                }),
            }],
            additional: vec![],
            negative: true,
            negative_rcode: Rcode::NxDomain,
            original_ttl: 300,
            inserted_at: std::time::Instant::now(),
            hit_count: 0,
        };

        let msg = resolver.build_cached_response(&qname, RecordType::A, RecordClass::IN, &entry);
        assert!(msg.answers.is_empty());
        assert_eq!(msg.authority.len(), 1, "negative response must keep SOA for RFC 2308");
        assert!(matches!(msg.authority[0].rdata, RData::SOA(_)));
        assert!(msg.additional.is_empty());
    }
}
