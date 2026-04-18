pub mod forwarder;
pub mod iterator;
pub mod recursive;

pub use recursive::Resolver;

use crate::protocol::edns::{self, EdnsOpt};

/// Build the OPT we attach to outbound queries. Payload size comes from
/// the shared runtime so operators can retune without caring whether the
/// number affects the listener, the resolver, or both. DO stays false
/// until DNSSEC validation actually works — promising DNSSEC we can't
/// verify would invite mis-trusted data. No options yet; ECS / cookies
/// land in later sub-phases of #75.
pub(crate) fn outbound_query_edns() -> EdnsOpt {
    EdnsOpt {
        udp_payload_size: edns::runtime().udp_payload_size,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: false,
        z: 0,
        options: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_edns_matches_runtime() {
        let opt = outbound_query_edns();
        assert_eq!(opt.udp_payload_size, edns::runtime().udp_payload_size);
        assert_eq!(opt.version, 0);
        assert!(
            !opt.dnssec_ok,
            "DO must stay false until DNSSEC validation is implemented"
        );
        assert!(opt.options.is_empty());
    }
}
