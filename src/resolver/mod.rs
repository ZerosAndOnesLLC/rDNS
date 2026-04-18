pub mod forwarder;
pub mod iterator;
pub mod recursive;

pub use recursive::Resolver;

use crate::protocol::edns::EdnsOpt;

/// EDNS0 payload size we advertise on our outbound queries. Matches the
/// server-side default in `listener::DEFAULT_SERVER_UDP_PAYLOAD_SIZE` — we
/// want one number for "what rDNS can handle over UDP", regardless of
/// which socket observes it. Phase E makes it config-driven.
pub(crate) const OUTBOUND_UDP_PAYLOAD_SIZE: u16 = 1232;

/// Build the OPT we attach to outbound queries. DO is left false until
/// DNSSEC validation actually works — promising DNSSEC we can't verify
/// would invite mis-trusted data. No options yet; ECS / cookies land in
/// later sub-phases of #75.
pub(crate) fn outbound_query_edns() -> EdnsOpt {
    EdnsOpt {
        udp_payload_size: OUTBOUND_UDP_PAYLOAD_SIZE,
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
    fn outbound_edns_defaults_match_server_policy() {
        let opt = outbound_query_edns();
        assert_eq!(opt.udp_payload_size, OUTBOUND_UDP_PAYLOAD_SIZE);
        assert_eq!(opt.version, 0);
        assert!(
            !opt.dnssec_ok,
            "DO must stay false until DNSSEC validation is implemented"
        );
        assert!(opt.options.is_empty());
    }
}
