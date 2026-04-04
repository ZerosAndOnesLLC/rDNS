use super::trust_anchor::ValidationStatus;
use crate::protocol::message::Message;
use crate::protocol::record::RecordType;

/// DNSSEC response validator.
/// Validates the chain of trust from root trust anchors down to the response.
#[derive(Clone)]
pub struct DnssecValidator {
    enabled: bool,
}

impl DnssecValidator {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Validate a DNS response.
    /// Returns the validation status and whether the AD (Authenticated Data) bit should be set.
    pub fn validate(&self, response: &Message) -> ValidationStatus {
        if !self.enabled {
            return ValidationStatus::Insecure;
        }

        // Check if response contains any DNSSEC records
        let has_rrsig = response
            .answers
            .iter()
            .any(|rr| rr.rtype == RecordType::RRSIG);

        if !has_rrsig {
            // No signatures — zone is unsigned or stripped
            return ValidationStatus::Insecure;
        }

        // DNSSEC cryptographic signature verification is not yet implemented.
        // Return Indeterminate for all signed responses to avoid false security.
        tracing::debug!("DNSSEC validation not implemented — treating signed response as Indeterminate");
        ValidationStatus::Indeterminate
    }

    /// Set the AD bit on a response based on validation status.
    pub fn set_ad_bit(response: &mut Message, status: ValidationStatus) {
        response.header.ad = status == ValidationStatus::Secure;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::header::Header;
    use crate::protocol::name::DnsName;
    use crate::protocol::opcode::Opcode;
    use crate::protocol::rcode::Rcode;
    use crate::protocol::rdata::RData;
    use crate::protocol::record::{RecordClass, ResourceRecord};

    fn empty_response() -> Message {
        Message {
            header: Header {
                id: 1,
                qr: true,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
                qd_count: 0,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    #[test]
    fn test_disabled_validator() {
        let validator = DnssecValidator::new(false);
        let response = empty_response();
        assert_eq!(validator.validate(&response), ValidationStatus::Insecure);
    }

    #[test]
    fn test_no_rrsig_insecure() {
        let validator = DnssecValidator::new(true);
        let mut response = empty_response();
        response.answers.push(ResourceRecord {
            name: DnsName::from_str("example.com").unwrap(),
            rtype: RecordType::A,
            rclass: RecordClass::IN,
            ttl: 300,
            rdata: RData::A(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        });
        assert_eq!(validator.validate(&response), ValidationStatus::Insecure);
    }

    #[test]
    fn test_ad_bit_setting() {
        let mut response = empty_response();
        DnssecValidator::set_ad_bit(&mut response, ValidationStatus::Secure);
        assert!(response.header.ad);

        DnssecValidator::set_ad_bit(&mut response, ValidationStatus::Insecure);
        assert!(!response.header.ad);
    }
}
