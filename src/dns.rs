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

