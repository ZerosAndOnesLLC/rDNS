use super::catalog::ZoneCatalog;
use crate::protocol::header::Header;
use crate::protocol::message::Message;
use crate::protocol::name::DnsName;
use crate::protocol::opcode::Opcode;
use crate::protocol::rcode::Rcode;
use crate::protocol::rdata::RData;
use crate::protocol::record::{Question, RecordClass, RecordType, ResourceRecord};

/// The authoritative DNS engine. Answers queries from loaded zones.
#[derive(Clone)]
pub struct AuthEngine {
    catalog: ZoneCatalog,
}

/// Result of an authoritative query.
pub enum AuthResult {
    /// Authoritative answer found
    Answer(Message),
    /// Name is not in any of our zones — not authoritative
    NotAuthoritative,
}

impl AuthEngine {
    pub fn new(catalog: ZoneCatalog) -> Self {
        Self { catalog }
    }

    pub fn catalog(&self) -> &ZoneCatalog {
        &self.catalog
    }

    /// Process an authoritative query.
    pub fn query(&self, name: &DnsName, rtype: RecordType, rclass: RecordClass) -> AuthResult {
        // Find the authoritative zone for this name
        let zone = match self.catalog.find_zone(name) {
            Some(z) => z,
            None => return AuthResult::NotAuthoritative,
        };

        // Verify the name is within the zone
        if !zone.contains_name(name) {
            return AuthResult::NotAuthoritative;
        }

        // Check for delegation (NS records at a point between zone apex and query name)
        if let Some(ns_rrset) = zone.find_delegation(name) {
            return AuthResult::Answer(self.build_referral(name, rtype, rclass, ns_rrset, &zone));
        }

        // Look up exact match
        if let Some(rrset) = zone.lookup(name, rtype) {
            return AuthResult::Answer(self.build_answer(
                name,
                rtype,
                rclass,
                rrset.records.clone(),
                &zone,
            ));
        }

        // Check for CNAME at this name
        if rtype != RecordType::CNAME {
            if let Some(cname_rrset) = zone.lookup(name, RecordType::CNAME) {
                return AuthResult::Answer(self.build_answer(
                    name,
                    rtype,
                    rclass,
                    cname_rrset.records.clone(),
                    &zone,
                ));
            }
        }

        // Check if name exists but no records of the requested type (NODATA)
        if zone.name_exists(name) {
            return AuthResult::Answer(self.build_nodata(name, rtype, rclass, &zone));
        }

        // Check for wildcard match
        if let Some((wildcard_rrset, _wildcard_name)) = zone.find_wildcard(name) {
            // Synthesize records with the queried name
            let synthesized: Vec<ResourceRecord> = wildcard_rrset
                .records
                .iter()
                .map(|rr| ResourceRecord {
                    name: name.clone(),
                    rtype: rr.rtype,
                    rclass: rr.rclass,
                    ttl: rr.ttl,
                    rdata: rr.rdata.clone(),
                })
                .collect();
            return AuthResult::Answer(self.build_answer(name, rtype, rclass, synthesized, &zone));
        }

        // NXDOMAIN — name does not exist
        AuthResult::Answer(self.build_nxdomain(name, rtype, rclass, &zone))
    }

    fn build_answer(
        &self,
        name: &DnsName,
        rtype: RecordType,
        rclass: RecordClass,
        answers: Vec<ResourceRecord>,
        zone: &crate::auth::zone::Zone,
    ) -> Message {
        let mut authority = Vec::new();
        // Include NS records in authority section
        if let Some(ns) = zone.apex_ns() {
            authority.extend(ns.records.clone());
        }

        Message {
            header: Header {
                id: 0,
                qr: true,
                opcode: Opcode::Query,
                aa: true, // Authoritative
                tc: false,
                rd: false,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
                qd_count: 1,
                an_count: answers.len() as u16,
                ns_count: authority.len() as u16,
                ar_count: 0,
            },
            questions: vec![Question {
                name: name.clone(),
                qtype: rtype,
                qclass: rclass,
            }],
            answers,
            authority,
            additional: vec![],
        }
    }

    fn build_nxdomain(
        &self,
        name: &DnsName,
        rtype: RecordType,
        rclass: RecordClass,
        zone: &crate::auth::zone::Zone,
    ) -> Message {
        Message {
            header: Header {
                id: 0,
                qr: true,
                opcode: Opcode::Query,
                aa: true,
                tc: false,
                rd: false,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NxDomain,
                qd_count: 1,
                an_count: 0,
                ns_count: 1,
                ar_count: 0,
            },
            questions: vec![Question {
                name: name.clone(),
                qtype: rtype,
                qclass: rclass,
            }],
            answers: vec![],
            authority: vec![zone.soa_record()],
            additional: vec![],
        }
    }

    fn build_nodata(
        &self,
        name: &DnsName,
        rtype: RecordType,
        rclass: RecordClass,
        zone: &crate::auth::zone::Zone,
    ) -> Message {
        Message {
            header: Header {
                id: 0,
                qr: true,
                opcode: Opcode::Query,
                aa: true,
                tc: false,
                rd: false,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
                qd_count: 1,
                an_count: 0,
                ns_count: 1,
                ar_count: 0,
            },
            questions: vec![Question {
                name: name.clone(),
                qtype: rtype,
                qclass: rclass,
            }],
            answers: vec![],
            authority: vec![zone.soa_record()],
            additional: vec![],
        }
    }

    fn build_referral(
        &self,
        name: &DnsName,
        rtype: RecordType,
        rclass: RecordClass,
        ns_rrset: &crate::auth::zone::RRSet,
        zone: &crate::auth::zone::Zone,
    ) -> Message {
        let mut additional = Vec::new();

        // Add glue records for NS targets that are within this zone
        for rr in &ns_rrset.records {
            if let RData::NS(ref ns_name) = rr.rdata {
                if zone.contains_name(ns_name) {
                    // Add A records for this NS
                    if let Some(a_rrset) = zone.lookup(ns_name, RecordType::A) {
                        additional.extend(a_rrset.records.clone());
                    }
                    if let Some(aaaa_rrset) = zone.lookup(ns_name, RecordType::AAAA) {
                        additional.extend(aaaa_rrset.records.clone());
                    }
                }
            }
        }

        Message {
            header: Header {
                id: 0,
                qr: true,
                opcode: Opcode::Query,
                aa: false, // Not authoritative — this is a referral
                tc: false,
                rd: false,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
                qd_count: 1,
                an_count: 0,
                ns_count: ns_rrset.records.len() as u16,
                ar_count: additional.len() as u16,
            },
            questions: vec![Question {
                name: name.clone(),
                qtype: rtype,
                qclass: rclass,
            }],
            answers: vec![],
            authority: ns_rrset.records.clone(),
            additional,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::zone_parser::parse_zone_str;

    fn test_engine() -> AuthEngine {
        let zone_content = r#"
$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 300
@   IN  NS  ns1.example.com.
@   IN  NS  ns2.example.com.
@   IN  A   93.184.216.34
www IN  A   93.184.216.34
www IN  A   93.184.216.35
mail IN A   93.184.216.36
@   IN  MX  10 mail.example.com.
alias IN CNAME www.example.com.
*.wild IN A 1.2.3.4
ns1 IN  A   192.0.2.1
ns2 IN  A   192.0.2.2
"#;
        let origin = DnsName::from_str("example.com").unwrap();
        let zone = parse_zone_str(zone_content, &origin).unwrap();

        let catalog = ZoneCatalog::new();
        catalog.insert(zone);

        AuthEngine::new(catalog)
    }

    #[test]
    fn test_exact_match() {
        let engine = test_engine();
        let result = engine.query(
            &DnsName::from_str("www.example.com").unwrap(),
            RecordType::A,
            RecordClass::IN,
        );

        match result {
            AuthResult::Answer(msg) => {
                assert_eq!(msg.header.rcode, Rcode::NoError);
                assert!(msg.header.aa);
                assert_eq!(msg.answers.len(), 2);
            }
            AuthResult::NotAuthoritative => panic!("Expected authoritative answer"),
        }
    }

    #[test]
    fn test_nxdomain() {
        let engine = test_engine();
        let result = engine.query(
            &DnsName::from_str("nonexistent.example.com").unwrap(),
            RecordType::A,
            RecordClass::IN,
        );

        match result {
            AuthResult::Answer(msg) => {
                assert_eq!(msg.header.rcode, Rcode::NxDomain);
                assert!(msg.header.aa);
                // Should have SOA in authority
                assert_eq!(msg.authority.len(), 1);
                assert_eq!(msg.authority[0].rtype, RecordType::SOA);
            }
            AuthResult::NotAuthoritative => panic!("Expected NXDOMAIN"),
        }
    }

    #[test]
    fn test_nodata() {
        let engine = test_engine();
        let result = engine.query(
            &DnsName::from_str("www.example.com").unwrap(),
            RecordType::MX, // No MX for www
            RecordClass::IN,
        );

        match result {
            AuthResult::Answer(msg) => {
                assert_eq!(msg.header.rcode, Rcode::NoError);
                assert!(msg.header.aa);
                assert_eq!(msg.answers.len(), 0);
                assert_eq!(msg.authority.len(), 1); // SOA
            }
            AuthResult::NotAuthoritative => panic!("Expected NODATA"),
        }
    }

    #[test]
    fn test_cname() {
        let engine = test_engine();
        let result = engine.query(
            &DnsName::from_str("alias.example.com").unwrap(),
            RecordType::A,
            RecordClass::IN,
        );

        match result {
            AuthResult::Answer(msg) => {
                assert_eq!(msg.header.rcode, Rcode::NoError);
                assert_eq!(msg.answers.len(), 1);
                assert_eq!(msg.answers[0].rtype, RecordType::CNAME);
            }
            AuthResult::NotAuthoritative => panic!("Expected CNAME answer"),
        }
    }

    #[test]
    fn test_wildcard() {
        let engine = test_engine();
        let result = engine.query(
            &DnsName::from_str("anything.wild.example.com").unwrap(),
            RecordType::A,
            RecordClass::IN,
        );

        match result {
            AuthResult::Answer(msg) => {
                assert_eq!(msg.header.rcode, Rcode::NoError);
                assert_eq!(msg.answers.len(), 1);
                // Wildcard should synthesize with the queried name
                assert_eq!(
                    msg.answers[0].name,
                    DnsName::from_str("anything.wild.example.com").unwrap()
                );
            }
            AuthResult::NotAuthoritative => panic!("Expected wildcard answer"),
        }
    }

    #[test]
    fn test_not_authoritative() {
        let engine = test_engine();
        let result = engine.query(
            &DnsName::from_str("www.other.com").unwrap(),
            RecordType::A,
            RecordClass::IN,
        );

        matches!(result, AuthResult::NotAuthoritative);
    }
}
