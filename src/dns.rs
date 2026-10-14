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
    MalformedName,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ParseError::TooShort => "packet too short",
            ParseError::NotUdp => "not a UDP packet",
            ParseError::NotDnsPort => "neither side is port 53",
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
    if ip.len() < ihl + 8 {
        return Err(ParseError::TooShort);
    }
    if ip[9] != 17 {
        return Err(ParseError::NotUdp);
    }
    let src_ip = [ip[12], ip[13], ip[14], ip[15]];
    let dst_ip = [ip[16], ip[17], ip[18], ip[19]];
    let udp = &ip[ihl..];
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    let (client, server, dns) = if dport == 53 {
        (src_ip, dst_ip, &udp[8..])
    } else if sport == 53 {
        (dst_ip, src_ip, &udp[8..])
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
        match std::str::from_utf8(&msg[pos + 1..pos + 1 + len]) {
            Ok(s) => labels.push(s.to_string()),
            Err(_) => return Err(ParseError::MalformedName),
        }
        pos += 1 + len;
    }
    Ok((labels.join("."), end_after_name))
}

