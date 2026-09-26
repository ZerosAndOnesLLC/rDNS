use crate::auth::AuthEngine;
use crate::cache::CacheStore;
use crate::resolver::Resolver;
use crate::rpz::RpzEngine;
use crate::security::acl::RecursionAcl;
use crate::security::rate_limit::RateLimiter;

/// Shared handles for the stream (TCP and DNS-over-TLS) listeners. Wrapped
/// in an `Arc` once per listener so each accepted connection clones a single
/// pointer instead of every engine handle.
pub struct StreamContext {
    pub cache: CacheStore,
    pub resolver: Option<Resolver>,
    pub auth: Option<AuthEngine>,
    pub rpz: RpzEngine,
    pub rate_limiter: RateLimiter,
    pub acl: RecursionAcl,
}
