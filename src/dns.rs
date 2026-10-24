//! DNS message parsing: question-section extraction with RFC 1035 name
//! decompression. We only need the asked name, the type, and the rcode —
//! answers are never inspected, which keeps the parser small and auditable.

/// A parsed DNS query as seen on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub name: String,
    pub qtype: u16,
    pub client: [u8; 4],
    pub server: [u8; 4],
    pub is_response: bool,
    pub rcode: u8,
}

impl Query {
    pub fn is_nxdomain(&self) -> bool {
        self.is_response && self.rcode == 3
    }
}

/// Errors from the packet/dns layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    NotUdp,
    NotDnsPort,
    MalformedIpHeader,
    MalformedUdp,
    MalformedName,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ParseError::TooShort => "packet too short",
            ParseError::NotUdp => "not a UDP packet",
            ParseError::NotDnsPort => "neither side is port 53",
            ParseError::MalformedIpHeader => "malformed IPv4 header",
            ParseError::MalformedUdp => "malformed UDP datagram",
            ParseError::MalformedName => "malformed dns name",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ParseError {}

/// Extract the DNS query from a captured Ethernet/IPv4/UDP frame.
/// Returns `Ok(None)` for non-DNS traffic so callers can skip quietly.
pub fn extract_query(frame: &[u8]) -> Result<Option<Query>, ParseError> {
    if frame.len() < 14 + 20 + 8 {
        return Err(ParseError::TooShort);
    }
    if frame[12] != 0x08 || frame[13] != 0x00 {
        return Ok(None); // not IPv4
    }
    let ip = &frame[14..];
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl > ip.len() {
        return Err(ParseError::MalformedIpHeader);
    }
    if ip.len() < ihl + 8 {
        return Err(ParseError::TooShort);
    }
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total_len < ihl + 8 {
        return Err(ParseError::MalformedIpHeader);
    }
    if ip.len() < total_len {
        return Err(ParseError::TooShort);
    }
    // Skip IPv4 fragments: the DNS payload may be incomplete or start in a later fragment.
    let fragment = u16::from_be_bytes([ip[6], ip[7]]);
    if fragment & 0x3fff != 0 {
        return Ok(None);
    }
    if ip[9] != 17 {
        return Err(ParseError::NotUdp);
    }
    let src_ip = [ip[12], ip[13], ip[14], ip[15]];
    let dst_ip = [ip[16], ip[17], ip[18], ip[19]];
    let udp = &ip[ihl..total_len];
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return Err(ParseError::MalformedUdp);
    }
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    let dns_payload = &udp[8..udp_len];
    let (client, server, dns) = if dport == 53 {
        (src_ip, dst_ip, dns_payload)
    } else if sport == 53 {
        (dst_ip, src_ip, dns_payload)
    } else {
        return Err(ParseError::NotDnsPort);
    };
    let q = parse_dns_message(dns)?;
    Ok(Some(Query {
        name: q.0, qtype: q.1, client, server,
        is_response: q.2, rcode: q.3,
    }))
}

/// Parse a DNS message: header + first question. Returns (name, qtype,
/// is_response, rcode).
fn parse_dns_message(msg: &[u8]) -> Result<(String, u16, bool, u8), ParseError> {
    if msg.len() < 12 {
        return Err(ParseError::TooShort);
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let is_response = flags & 0x8000 != 0;
    let rcode = (flags & 0x000f) as u8;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    if qdcount == 0 {
        return Err(ParseError::MalformedName);
    }
    let (name, end) = read_name(msg, 12)?;
    if end + 4 > msg.len() {
        return Err(ParseError::TooShort);
    }
    let qtype = u16::from_be_bytes([msg[end], msg[end + 1]]);
    Ok((name, qtype, is_response, rcode))
}

/// Decompress a DNS name starting at `offset`. Compression pointers may
/// jump at most once and the total walk is step-bounded, so hostile
/// pointer loops terminate instead of hanging the sentinel.
pub fn read_name(msg: &[u8], offset: usize) -> Result<(String, usize), ParseError> {
    let mut labels: Vec<String> = Vec::new();
    let mut wire_len = 0usize;
    let mut pos = offset;
    let mut jumped = false;
    let mut steps = 0usize;
    let mut end_after_name = 0usize;
    loop {
        steps += 1;
        if steps > 128 || pos >= msg.len() {
            return Err(ParseError::MalformedName);
        }
        let len = msg[pos] as usize;
        if len == 0 {
            if !jumped {
                end_after_name = pos + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= msg.len() {
                return Err(ParseError::MalformedName);
            }
            let ptr = ((len & 0x3f) << 8) | msg[pos + 1] as usize;
            if jumped {
                return Err(ParseError::MalformedName); // second jump: refuse
            }
            jumped = true;
            end_after_name = pos + 2;
            pos = ptr;
            continue;
        }
        if len & 0xc0 != 0 || pos + 1 + len > msg.len() {
            return Err(ParseError::MalformedName);
        }
        // RFC 1035 limits the expanded wire-format name to 255 octets,
        // including each label-length byte and the terminating root label.
        wire_len += 1 + len;
        if wire_len > 254 {
            return Err(ParseError::MalformedName);
        }
        match std::str::from_utf8(&msg[pos + 1..pos + 1 + len]) {
            Ok(s) => labels.push(s.to_string()),
            Err(_) => return Err(ParseError::MalformedName),
        }
        pos += 1 + len;
    }
    Ok((labels.join("."), end_after_name))
}

/// Build a raw DNS query message (single A-record question). Shared by
/// tests and the selftest synthesizer.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD set
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // IN
    msg
}

/// Build a matching response with the given rcode (3 = NXDOMAIN).
pub fn build_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let mut msg = query.to_vec();
    msg[2] = 0x81; // QR + RD
    msg[3] = (msg[3] & 0xf0) | (rcode & 0x0f) | 0x80; // RA
    msg
}



#[cfg(test)]
mod packet_framing_tests {
    use super::{extract_query, parse_dns_message, ParseError};
    use crate::dns::build_query;
    use crate::pcap::udp_frame;

    fn sample_frame() -> Vec<u8> {
        udp_frame([192, 168, 1, 20], [1, 1, 1, 1], 53000, 53,
                  &build_query(1, "example.com", 1))
    }

    #[test]
    fn rejects_ipv4_header_lengths_below_minimum() {
        let mut frame = sample_frame();
        frame[14] = 0x44; // IHL=16 bytes, invalid for IPv4.
        assert!(matches!(extract_query(&frame), Err(ParseError::MalformedIpHeader)));
    }

    #[test]
    fn skips_fragmented_ipv4_packets() {
        let mut frame = sample_frame();
        frame[20] = 0x20; // More Fragments flag.
        assert_eq!(extract_query(&frame).unwrap(), None);
    }

    #[test]
    fn rejects_udp_lengths_shorter_than_header() {
        let mut frame = sample_frame();
        frame[38..40].copy_from_slice(&7u16.to_be_bytes());
        assert!(matches!(extract_query(&frame), Err(ParseError::MalformedUdp)));
    }

    #[test]
    fn rejects_dns_messages_without_questions() {
        let message = vec![0u8; 12];
        assert!(matches!(parse_dns_message(&message), Err(ParseError::MalformedName)));
    }

    #[test]
    fn extracts_well_formed_dns_queries() {
        let query = extract_query(&sample_frame()).unwrap().unwrap();
        assert_eq!(query.name, "example.com");
        assert_eq!(query.client, [192, 168, 1, 20]);
    }
}
