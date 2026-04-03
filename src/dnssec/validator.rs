use super::algorithms::{DnskeyData, RrsigData};
use super::trust_anchor::ValidationStatus;
use crate::protocol::message::Message;
use crate::protocol::rdata::RData;
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

        // Extract RRSIG records from the answer
        let rrsigs: Vec<RrsigData> = response
            .answers
            .iter()
            .filter(|rr| rr.rtype == RecordType::RRSIG)
            .filter_map(|rr| {
                if let RData::Raw { data, .. } = &rr.rdata {
                    RrsigData::from_rdata(data)
                } else {
                    None
                }
            })
            .collect();

        if rrsigs.is_empty() {
            return ValidationStatus::Insecure;
        }

        // Check signature time validity
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        for rrsig in &rrsigs {
            if !rrsig.is_time_valid(now) {
                tracing::warn!(
                    key_tag = rrsig.key_tag,
                    expiration = rrsig.sig_expiration,
                    inception = rrsig.sig_inception,
                    "RRSIG time validation failed"
                );
                return ValidationStatus::Bogus;
            }
        }

        // Extract DNSKEY records if present (in additional or answer for DNSKEY queries)
        let dnskeys: Vec<DnskeyData> = response
            .answers
            .iter()
            .chain(response.additional.iter())
            .filter(|rr| rr.rtype == RecordType::DNSKEY)
            .filter_map(|rr| {
                if let RData::Raw { data, .. } = &rr.rdata {
                    DnskeyData::from_rdata(data)
                } else {
                    None
                }
            })
            .collect();

        // Verify key tags match between RRSIG and available DNSKEYs
        for rrsig in &rrsigs {
            let matching_key = dnskeys.iter().find(|k| k.key_tag() == rrsig.key_tag);

            if matching_key.is_none() {
                // Key not available in response — would need to be fetched
                // For now, mark as indeterminate
                tracing::debug!(
                    key_tag = rrsig.key_tag,
                    "DNSKEY not found for RRSIG"
                );
                return ValidationStatus::Indeterminate;
            }

            let key = matching_key.unwrap();

            // Verify algorithm is supported
            if !key.algorithm.is_supported() || !rrsig.algorithm.is_supported() {
                tracing::warn!(
                    algorithm = ?rrsig.algorithm,
                    "Unsupported DNSSEC algorithm"
                );
                return ValidationStatus::Indeterminate;
            }

            // TODO: Implement actual cryptographic signature verification
            // This requires the `ring` crate and building the signed data
            // (canonical RRset + RRSIG header) then verifying against the public key.
            // For now, we check structural validity only.
        }

        // Cryptographic signature verification is not yet implemented.
        // Without actual signature verification, we MUST NOT return Secure
        // as that would set AD=1 and give clients false assurance.
        // All structurally-valid-but-unverified responses are Indeterminate.
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
