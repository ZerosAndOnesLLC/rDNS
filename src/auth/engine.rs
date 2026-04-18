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

        // RFC 8482: respond to ANY queries with a minimal synthesized HINFO
        // ("RFC8482"/""). Avoids amplification and resists DNS-walk reconnaissance.
        if rtype == RecordType::ANY {
            return AuthResult::Answer(self.build_rfc8482(name, rclass, &zone));
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
        if let Some((wildcard_rrset, _wildcard_name)) = zone.find_wildcard(name, rtype) {
            if wildcard_rrset.rtype == rtype || rtype == RecordType::CNAME {
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
                return AuthResult::Answer(
                    self.build_answer(name, rtype, rclass, synthesized, &zone),
                );
            } else {
                // Wildcard exists but not for this type -- NODATA
                return AuthResult::Answer(self.build_nodata(name, rtype, rclass, &zone));
            }
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
            edns: None,
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
            edns: None,
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
            edns: None,
        }
    }

    fn build_rfc8482(
        &self,
        name: &DnsName,
        rclass: RecordClass,
        zone: &crate::auth::zone::Zone,
    ) -> Message {
        let hinfo = ResourceRecord {
            name: name.clone(),
            rtype: RecordType::HINFO,
            rclass,
            ttl: 3789, // Matches the TTL Cloudflare returns for its RFC 8482 replies.
            rdata: RData::HINFO {
                cpu: b"RFC8482".to_vec(),
                os: Vec::new(),
            },
        };
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
                an_count: 1,
                ns_count: 1,
                ar_count: 0,
            },
            questions: vec![Question {
                name: name.clone(),
                qtype: RecordType::ANY,
                qclass: rclass,
            }],
            answers: vec![hinfo],
            authority: vec![zone.soa_record()],
            additional: vec![],
            edns: None,
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
            edns: None,
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
    fn test_any_query_rfc8482() {
        let engine = test_engine();
        let result = engine.query(
            &DnsName::from_str("example.com").unwrap(),
            RecordType::ANY,
            RecordClass::IN,
        );

        match result {
            AuthResult::Answer(msg) => {
                assert_eq!(msg.header.rcode, Rcode::NoError);
                assert!(msg.header.aa);
                assert_eq!(msg.answers.len(), 1);
                assert_eq!(msg.answers[0].rtype, RecordType::HINFO);
                match &msg.answers[0].rdata {
                    RData::HINFO { cpu, .. } => assert_eq!(cpu, b"RFC8482"),
                    other => panic!("expected HINFO, got {:?}", other),
                }
                assert_eq!(msg.authority.len(), 1);
                assert_eq!(msg.authority[0].rtype, RecordType::SOA);
            }
            AuthResult::NotAuthoritative => panic!("Expected RFC 8482 ANY answer"),
        }
    }

    // ---- Phase 4: per-record-type query path coverage ----

    fn full_test_engine() -> AuthEngine {
        use crate::auth::zone::Zone;
        use crate::protocol::rdata::{CaaData, SoaData, SrvData, SvcbData};

        let origin = DnsName::from_str("example.com").unwrap();
        let soa = SoaData {
            mname: DnsName::from_str("ns1.example.com").unwrap(),
            rname: DnsName::from_str("admin.example.com").unwrap(),
            serial: 2024010101,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 300,
        };
        let mut zone = Zone::new(origin.clone(), soa, 300);
        // Also expose SOA via the rrset lookup path so `@ SOA` queries hit an answer.
        let soa_rr = zone.soa_record();
        zone.add_record(soa_rr);

        let push = |zone: &mut Zone, name: &str, rtype, rdata| {
            zone.add_record(ResourceRecord {
                name: DnsName::from_str(name).unwrap(),
                rtype,
                rclass: RecordClass::IN,
                ttl: 300,
                rdata,
            });
        };

        // Apex
        push(&mut zone, "example.com", RecordType::NS, RData::NS(DnsName::from_str("ns1.example.com").unwrap()));
        push(&mut zone, "example.com", RecordType::A, RData::A("93.184.216.34".parse().unwrap()));
        push(&mut zone, "example.com", RecordType::AAAA, RData::AAAA("2001:db8::34".parse().unwrap()));
        push(&mut zone, "example.com", RecordType::MX, RData::MX {
            preference: 10,
            exchange: DnsName::from_str("mail.example.com").unwrap(),
        });
        push(&mut zone, "example.com", RecordType::TXT, RData::TXT(vec![b"v=spf1 -all".to_vec()]));
        push(&mut zone, "example.com", RecordType::CAA, RData::CAA(CaaData {
            flags: 0,
            tag: "issue".into(),
            value: b"letsencrypt.org".to_vec(),
        }));

        // Labels
        push(&mut zone, "www.example.com", RecordType::A, RData::A("93.184.216.34".parse().unwrap()));
        push(&mut zone, "www.example.com", RecordType::AAAA, RData::AAAA("2001:db8::1".parse().unwrap()));
        push(&mut zone, "mail.example.com", RecordType::A, RData::A("93.184.216.35".parse().unwrap()));
        push(&mut zone, "_sip._tcp.example.com", RecordType::SRV, RData::SRV(SrvData {
            priority: 10,
            weight: 60,
            port: 5060,
            target: DnsName::from_str("sipserver.example.com").unwrap(),
        }));
        push(&mut zone, "alias.example.com", RecordType::CNAME,
             RData::CNAME(DnsName::from_str("www.example.com").unwrap()));
        push(&mut zone, "svc.example.com", RecordType::HTTPS, RData::HTTPS(SvcbData {
            priority: 1,
            target: DnsName::from_str("www.example.com").unwrap(),
            params: vec![0x00, 0x01, 0x00, 0x03, 0x02, b'h', b'2'],
        }));
        push(&mut zone, "svc.example.com", RecordType::SVCB, RData::SVCB(SvcbData {
            priority: 2,
            target: DnsName::from_str("www.example.com").unwrap(),
            params: Vec::new(),
        }));

        let catalog = ZoneCatalog::new();
        catalog.insert(zone);
        AuthEngine::new(catalog)
    }

    fn assert_answered(engine: &AuthEngine, name: &str, rtype: RecordType) -> Message {
        let n = DnsName::from_str(name).unwrap();
        match engine.query(&n, rtype, RecordClass::IN) {
            AuthResult::Answer(m) => m,
            AuthResult::NotAuthoritative => panic!("not authoritative for {} {:?}", name, rtype),
        }
    }

    #[test]
    fn test_every_type_query() {
        let e = full_test_engine();

        let m = assert_answered(&e, "example.com", RecordType::NS);
        assert_eq!(m.header.rcode, Rcode::NoError);
        assert_eq!(m.answers[0].rtype, RecordType::NS);

        let m = assert_answered(&e, "example.com", RecordType::SOA);
        assert_eq!(m.answers[0].rtype, RecordType::SOA);

        let m = assert_answered(&e, "www.example.com", RecordType::A);
        assert_eq!(m.answers[0].rtype, RecordType::A);

        let m = assert_answered(&e, "www.example.com", RecordType::AAAA);
        assert_eq!(m.answers[0].rtype, RecordType::AAAA);

        let m = assert_answered(&e, "example.com", RecordType::MX);
        assert_eq!(m.answers[0].rtype, RecordType::MX);

        let m = assert_answered(&e, "example.com", RecordType::TXT);
        assert_eq!(m.answers[0].rtype, RecordType::TXT);

        let m = assert_answered(&e, "example.com", RecordType::CAA);
        assert_eq!(m.answers[0].rtype, RecordType::CAA);

        let m = assert_answered(&e, "_sip._tcp.example.com", RecordType::SRV);
        assert_eq!(m.answers[0].rtype, RecordType::SRV);

        let m = assert_answered(&e, "alias.example.com", RecordType::A);
        assert_eq!(m.answers[0].rtype, RecordType::CNAME);

        let m = assert_answered(&e, "svc.example.com", RecordType::HTTPS);
        assert_eq!(m.answers[0].rtype, RecordType::HTTPS);

        let m = assert_answered(&e, "svc.example.com", RecordType::SVCB);
        assert_eq!(m.answers[0].rtype, RecordType::SVCB);
    }

    #[test]
    fn test_any_query_on_full_zone() {
        let e = full_test_engine();
        let m = assert_answered(&e, "example.com", RecordType::ANY);
        assert_eq!(m.header.rcode, Rcode::NoError);
        assert_eq!(m.answers.len(), 1);
        assert_eq!(m.answers[0].rtype, RecordType::HINFO);
    }

    #[test]
    fn test_response_wire_encode_every_type() {
        // Proves each authoritative response round-trips through the wire format.
        let e = full_test_engine();
        let cases: &[(&str, RecordType)] = &[
            ("example.com", RecordType::NS),
            ("example.com", RecordType::SOA),
            ("www.example.com", RecordType::A),
            ("www.example.com", RecordType::AAAA),
            ("example.com", RecordType::MX),
            ("example.com", RecordType::TXT),
            ("example.com", RecordType::CAA),
            ("_sip._tcp.example.com", RecordType::SRV),
            ("alias.example.com", RecordType::A),
            ("svc.example.com", RecordType::HTTPS),
            ("svc.example.com", RecordType::SVCB),
            ("example.com", RecordType::ANY),
        ];
        for (name, qtype) in cases {
            let msg = assert_answered(&e, name, *qtype);
            let wire = msg.encode();
            let decoded = Message::decode(&wire).expect("decode response");
            assert_eq!(decoded.header.rcode, msg.header.rcode);
            assert_eq!(decoded.answers.len(), msg.answers.len());
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
