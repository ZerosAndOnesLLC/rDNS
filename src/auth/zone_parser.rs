use crate::auth::zone::Zone;
use crate::protocol::name::DnsName;
use crate::protocol::rdata::{CaaData, RData, SoaData, SrvData};
use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("line {line}: {message}")]
    Syntax { line: usize, message: String },

    #[error("no SOA record found in zone file")]
    NoSoa,
}

/// Parse an RFC 1035 zone file into a Zone.
pub fn parse_zone_file(path: &Path, origin: &DnsName) -> Result<Zone, ParseError> {
    let content = std::fs::read_to_string(path)?;
    parse_zone_str(&content, origin)
}

/// Parse a zone file from a string.
pub fn parse_zone_str(content: &str, origin: &DnsName) -> Result<Zone, ParseError> {
    let mut current_origin = origin.clone();
    let mut default_ttl: u32 = 3600;
    let mut last_name = origin.clone();
    let mut records: Vec<ResourceRecord> = Vec::new();
    let mut soa: Option<(SoaData, u32)> = None;

    for (line_num, raw_line) in content.lines().enumerate() {
        let line_num = line_num + 1; // 1-indexed

        // Strip comments
        let line = if let Some(idx) = raw_line.find(';') {
            &raw_line[..idx]
        } else {
            raw_line
        };

        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }

        // Handle directives
        if line.starts_with("$ORIGIN") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(ParseError::Syntax {
                    line: line_num,
                    message: "$ORIGIN requires a domain name".into(),
                });
            }
            current_origin = resolve_name(parts[1], &current_origin)?;
            continue;
        }

        if line.starts_with("$TTL") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(ParseError::Syntax {
                    line: line_num,
                    message: "$TTL requires a value".into(),
                });
            }
            default_ttl = parse_ttl(parts[1]).map_err(|e| ParseError::Syntax {
                line: line_num,
                message: format!("invalid TTL: {}", e),
            })?;
            continue;
        }

        if line.starts_with("$INCLUDE") {
            // Skip $INCLUDE for now
            continue;
        }

        // Parse resource record
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let (name, ttl, rclass, rtype, rdata_tokens) =
            parse_rr_tokens(&tokens, &last_name, &current_origin, default_ttl, line_num)?;

        last_name = name.clone();

        let rdata =
            parse_rdata(rtype, &rdata_tokens, &current_origin).map_err(|e| ParseError::Syntax {
                line: line_num,
                message: format!("invalid rdata for {}: {}", rtype, e),
            })?;

        // Capture SOA
        if rtype == RecordType::SOA {
            if let RData::SOA(ref soa_data) = rdata {
                soa = Some((soa_data.clone(), ttl));
            }
        }

        records.push(ResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        });
    }

    let (soa_data, soa_ttl) = soa.ok_or(ParseError::NoSoa)?;
    let mut zone = Zone::new(origin.clone(), soa_data, soa_ttl);

    for rr in records {
        zone.add_record(rr);
    }

    Ok(zone)
}

/// Parse RR tokens into components: (name, ttl, class, type, rdata_tokens)
fn parse_rr_tokens<'a>(
    tokens: &'a [&'a str],
    last_name: &DnsName,
    origin: &DnsName,
    default_ttl: u32,
    line_num: usize,
) -> Result<(DnsName, u32, RecordClass, RecordType, Vec<&'a str>), ParseError> {
    let mut idx = 0;

    // Determine name
    let name = if tokens[0].starts_with(char::is_whitespace) || tokens[0] == "@" {
        if tokens[0] == "@" {
            idx += 1;
            origin.clone()
        } else {
            last_name.clone()
        }
    } else if is_rr_type(tokens[0]) || is_class(tokens[0]) || tokens[0].parse::<u32>().is_ok() {
        // No name field — continuation of previous name
        last_name.clone()
    } else {
        idx += 1;
        resolve_name(tokens[0], origin)?
    };

    // Parse optional TTL and class (can appear in either order)
    let mut ttl = default_ttl;
    let mut rclass = RecordClass::IN;

    // Try TTL then class, or class then TTL
    if idx < tokens.len() {
        if let Ok(t) = parse_ttl(tokens[idx]) {
            ttl = t;
            idx += 1;
        }
    }
    if idx < tokens.len() && is_class(tokens[idx]) {
        rclass = parse_class(tokens[idx]);
        idx += 1;
    }
    if idx < tokens.len() {
        if let Ok(t) = parse_ttl(tokens[idx]) {
            if ttl == default_ttl {
                // Only override if we haven't already parsed a TTL
                ttl = t;
                idx += 1;
            }
        }
    }

    // Record type
    if idx >= tokens.len() {
        return Err(ParseError::Syntax {
            line: line_num,
            message: "missing record type".into(),
        });
    }

    let rtype = parse_record_type(tokens[idx]).ok_or_else(|| ParseError::Syntax {
        line: line_num,
        message: format!("unknown record type: {}", tokens[idx]),
    })?;
    idx += 1;

    let rdata_tokens = tokens[idx..].to_vec();

    Ok((name, ttl, rclass, rtype, rdata_tokens))
}

/// Parse RDATA from tokens based on record type.
fn parse_rdata(rtype: RecordType, tokens: &[&str], origin: &DnsName) -> Result<RData, String> {
    match rtype {
        RecordType::A => {
            if tokens.is_empty() {
                return Err("missing IP address".into());
            }
            let ip: Ipv4Addr = tokens[0].parse().map_err(|e| format!("{}", e))?;
            Ok(RData::A(ip))
        }
        RecordType::AAAA => {
            if tokens.is_empty() {
                return Err("missing IPv6 address".into());
            }
            let ip: Ipv6Addr = tokens[0].parse().map_err(|e| format!("{}", e))?;
            Ok(RData::AAAA(ip))
        }
        RecordType::NS => {
            if tokens.is_empty() {
                return Err("missing nameserver".into());
            }
            let name = resolve_name(tokens[0], origin).map_err(|e| format!("{}", e))?;
            Ok(RData::NS(name))
        }
        RecordType::CNAME => {
            if tokens.is_empty() {
                return Err("missing canonical name".into());
            }
            let name = resolve_name(tokens[0], origin).map_err(|e| format!("{}", e))?;
            Ok(RData::CNAME(name))
        }
        RecordType::PTR => {
            if tokens.is_empty() {
                return Err("missing pointer name".into());
            }
            let name = resolve_name(tokens[0], origin).map_err(|e| format!("{}", e))?;
            Ok(RData::PTR(name))
        }
        RecordType::MX => {
            if tokens.len() < 2 {
                return Err("MX requires preference and exchange".into());
            }
            let preference: u16 = tokens[0].parse().map_err(|e| format!("{}", e))?;
            let exchange = resolve_name(tokens[1], origin).map_err(|e| format!("{}", e))?;
            Ok(RData::MX {
                preference,
                exchange,
            })
        }
        RecordType::SOA => {
            if tokens.len() < 7 {
                return Err("SOA requires mname rname serial refresh retry expire minimum".into());
            }
            let mname = resolve_name(tokens[0], origin).map_err(|e| format!("{}", e))?;
            let rname = resolve_name(tokens[1], origin).map_err(|e| format!("{}", e))?;
            let serial: u32 = tokens[2].parse().map_err(|e| format!("{}", e))?;
            let refresh: u32 = parse_ttl(tokens[3]).map_err(|e| format!("{}", e))?;
            let retry: u32 = parse_ttl(tokens[4]).map_err(|e| format!("{}", e))?;
            let expire: u32 = parse_ttl(tokens[5]).map_err(|e| format!("{}", e))?;
            let minimum: u32 = parse_ttl(tokens[6]).map_err(|e| format!("{}", e))?;
            Ok(RData::SOA(SoaData {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }))
        }
        RecordType::TXT => {
            // Join all remaining tokens and handle quoted strings
            let text = tokens.join(" ");
            let data = parse_txt_rdata(&text)?;
            Ok(RData::TXT(data))
        }
        RecordType::SRV => {
            if tokens.len() < 4 {
                return Err("SRV requires priority weight port target".into());
            }
            let priority: u16 = tokens[0].parse().map_err(|e| format!("{}", e))?;
            let weight: u16 = tokens[1].parse().map_err(|e| format!("{}", e))?;
            let port: u16 = tokens[2].parse().map_err(|e| format!("{}", e))?;
            let target = resolve_name(tokens[3], origin).map_err(|e| format!("{}", e))?;
            Ok(RData::SRV(SrvData {
                priority,
                weight,
                port,
                target,
            }))
        }
        RecordType::CAA => {
            if tokens.len() < 3 {
                return Err("CAA requires flags tag value".into());
            }
            let flags: u8 = tokens[0].parse().map_err(|e| format!("{}", e))?;
            let tag = tokens[1].to_string();
            let value = tokens[2..].join(" ");
            let value = value.trim_matches('"').as_bytes().to_vec();
            Ok(RData::CAA(CaaData { flags, tag, value }))
        }
        _ => {
            // Unknown type — store as raw
            Ok(RData::Raw {
                type_code: u16::from(rtype),
                data: Vec::new(),
            })
        }
    }
}

/// Parse TXT record data, handling quoted strings.
fn parse_txt_rdata(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in text.chars() {
        if escaped {
            current.push(ch as u8);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    strings.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch as u8),
        }
    }
    if !current.is_empty() {
        strings.push(current);
    }

    if strings.is_empty() {
        strings.push(Vec::new());
    }

    Ok(strings)
}

/// Resolve a name relative to the origin. Names ending with "." are absolute.
fn resolve_name(name: &str, origin: &DnsName) -> Result<DnsName, ParseError> {
    if name == "@" {
        return Ok(origin.clone());
    }
    if name.ends_with('.') {
        DnsName::from_str(name).map_err(|e| ParseError::Syntax {
            line: 0,
            message: format!("invalid name '{}': {}", name, e),
        })
    } else {
        // Relative name — append origin
        let full = format!("{}.{}", name, origin.to_dotted());
        DnsName::from_str(&full).map_err(|e| ParseError::Syntax {
            line: 0,
            message: format!("invalid name '{}': {}", full, e),
        })
    }
}

fn is_rr_type(s: &str) -> bool {
    parse_record_type(s).is_some()
}

fn is_class(s: &str) -> bool {
    matches!(s.to_uppercase().as_str(), "IN" | "CH" | "HS" | "ANY")
}

fn parse_class(s: &str) -> RecordClass {
    match s.to_uppercase().as_str() {
        "IN" => RecordClass::IN,
        "CH" => RecordClass::CH,
        "HS" => RecordClass::HS,
        "ANY" => RecordClass::ANY,
        _ => RecordClass::IN,
    }
}

fn parse_record_type(s: &str) -> Option<RecordType> {
    match s.to_uppercase().as_str() {
        "A" => Some(RecordType::A),
        "AAAA" => Some(RecordType::AAAA),
        "NS" => Some(RecordType::NS),
        "CNAME" => Some(RecordType::CNAME),
        "SOA" => Some(RecordType::SOA),
        "PTR" => Some(RecordType::PTR),
        "MX" => Some(RecordType::MX),
        "TXT" => Some(RecordType::TXT),
        "SRV" => Some(RecordType::SRV),
        "CAA" => Some(RecordType::CAA),
        "DS" => Some(RecordType::DS),
        "DNSKEY" => Some(RecordType::DNSKEY),
        "RRSIG" => Some(RecordType::RRSIG),
        "NSEC" => Some(RecordType::NSEC),
        "NSEC3" => Some(RecordType::NSEC3),
        _ => None,
    }
}

/// Parse a TTL value (supports bare seconds and BIND-style suffixes: 1h, 30m, etc.)
fn parse_ttl(s: &str) -> Result<u32, String> {
    // Try plain number first
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }

    // Parse BIND-style: 1h30m, 1d, 2w, etc.
    let mut total: u32 = 0;
    let mut current: u32 = 0;

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current = current * 10 + ch.to_digit(10).unwrap();
        } else {
            let multiplier = match ch.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                'w' => 604800,
                _ => return Err(format!("invalid TTL suffix: {}", ch)),
            };
            total += current * multiplier;
            current = 0;
        }
    }
    total += current; // Trailing number without suffix = seconds

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ttl_plain() {
        assert_eq!(parse_ttl("300").unwrap(), 300);
        assert_eq!(parse_ttl("86400").unwrap(), 86400);
    }

    #[test]
    fn test_parse_ttl_suffixes() {
        assert_eq!(parse_ttl("1h").unwrap(), 3600);
        assert_eq!(parse_ttl("30m").unwrap(), 1800);
        assert_eq!(parse_ttl("1d").unwrap(), 86400);
        assert_eq!(parse_ttl("1w").unwrap(), 604800);
        assert_eq!(parse_ttl("1h30m").unwrap(), 5400);
    }

    #[test]
    fn test_parse_simple_zone() {
        let zone_content = r#"
$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 300
@   IN  NS  ns1.example.com.
@   IN  NS  ns2.example.com.
@   IN  A   93.184.216.34
www IN  A   93.184.216.34
@   IN  MX  10 mail.example.com.
mail IN A   93.184.216.35
@   IN  TXT "v=spf1 include:_spf.example.com ~all"
"#;
        let origin = DnsName::from_str("example.com").unwrap();
        let zone = parse_zone_str(zone_content, &origin).unwrap();

        assert_eq!(zone.origin, origin);
        assert_eq!(zone.soa.serial, 2024010101);

        // Check A record at apex
        let apex_a = zone.lookup(&origin, RecordType::A);
        assert!(apex_a.is_some());

        // Check www A record
        let www = DnsName::from_str("www.example.com").unwrap();
        let www_a = zone.lookup(&www, RecordType::A);
        assert!(www_a.is_some());

        // Check MX record
        let mail_name = DnsName::from_str("mail.example.com").unwrap();
        let mx = zone.lookup(&origin, RecordType::MX);
        assert!(mx.is_some());

        // Check NS records
        let ns = zone.lookup(&origin, RecordType::NS);
        assert!(ns.is_some());
        assert_eq!(ns.unwrap().records.len(), 2);
    }

    #[test]
    fn test_parse_zone_with_origin_directive() {
        let zone_content = r#"
$ORIGIN example.com.
$TTL 300
@   SOA ns1 admin 1 3600 900 604800 300
@   NS  ns1
ns1 A   192.0.2.1
"#;
        let origin = DnsName::from_str("example.com").unwrap();
        let zone = parse_zone_str(zone_content, &origin).unwrap();

        let ns1 = DnsName::from_str("ns1.example.com").unwrap();
        assert!(zone.lookup(&ns1, RecordType::A).is_some());
    }

    #[test]
    fn test_resolve_name_absolute() {
        let origin = DnsName::from_str("example.com").unwrap();
        let name = resolve_name("foo.bar.com.", &origin).unwrap();
        assert_eq!(name.to_dotted(), "foo.bar.com.");
    }

    #[test]
    fn test_resolve_name_relative() {
        let origin = DnsName::from_str("example.com").unwrap();
        let name = resolve_name("www", &origin).unwrap();
        assert_eq!(name.to_dotted(), "www.example.com.");
    }

    #[test]
    fn test_resolve_name_at() {
        let origin = DnsName::from_str("example.com").unwrap();
        let name = resolve_name("@", &origin).unwrap();
        assert_eq!(name, origin);
    }
}
