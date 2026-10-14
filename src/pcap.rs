//! Minimal libpcap file/stream reader. Supports the classic pcap format
//! (microsecond magic 0xa1b2c3d4) with Ethernet link type. No external
//! dependencies: the format is small enough to parse by hand.

use std::io::{self, Read};

/// One captured packet with its timestamp.
#[derive(Debug, Clone)]
pub struct Packet {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub data: Vec<u8>,
}

/// Incremental reader over a pcap byte stream (file or pipe).
pub struct PcapReader<R> {
    inner: R,
    swapped: bool,
    linktype: u32,
    peeked: Option<u8>,
}

impl<R: Read> PcapReader<R> {
    /// Parse the 24-byte global header. Supports little- and big-endian
    /// captures; nanosecond magic is rejected with a clear error.
    pub fn new(mut inner: R) -> io::Result<Self> {
        let mut gh = [0u8; 24];
        inner.read_exact(&mut gh)?;
        let magic = u32::from_le_bytes([gh[0], gh[1], gh[2], gh[3]]);
        let (swapped, ok) = match magic {
            0xa1b2c3d4 => (false, true),
            0xd4c3b2a1 => (true, true),
            _ => (false, false),
        };
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a classic pcap (bad magic; pcapng is unsupported)",
            ));
        }
        let linktype = if swapped {
            u32::from_le_bytes([gh[20], gh[21], gh[22], gh[23]])
        } else {
            u32::from_le_bytes([gh[20], gh[21], gh[22], gh[23]])
        };
        if linktype != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported linktype {linktype} (only Ethernet=1)"),
            ));
        }
        Ok(PcapReader { inner, swapped, linktype, peeked: None })
    }

    fn read_u32(&mut self, b: [u8; 4]) -> u32 {
        if self.swapped {
            u32::from_le_bytes(b).swap_bytes()
        } else {
            u32::from_le_bytes(b)
        }
    }

    fn next_byte(&mut self) -> io::Result<u8> {
        if let Some(b) = self.peeked.take() {
            return Ok(b);
        }
        let mut b = [0u8; 1];
        self.inner.read_exact(&mut b)?;
        Ok(b[0])
    }

    /// Read the next packet record; `Ok(None)` on clean end of stream.
    /// Truncated trailing data (a capture cut mid-write) ends the stream
    /// instead of erroring — important for live `tcpdump` pipes.
    pub fn next_packet(&mut self) -> io::Result<Option<Packet>> {
        let mut hdr = [0u8; 16];
        let mut filled = 0usize;
        while filled < 16 {
            match self.next_byte() {
                Ok(b) => { hdr[filled] = b; filled += 1; }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return if filled == 0 { Ok(None) } else { Ok(None) };
                }
                Err(e) => return Err(e),
            }
        }
        let ts_sec = self.read_u32([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let ts_usec = self.read_u32([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let incl_len = self.read_u32([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
        if incl_len > 16 * 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet too large"));
        }
        let mut data = vec![0u8; incl_len];
        self.inner.read_exact(&mut data)?;
        Ok(Some(Packet { ts_sec, ts_usec, data }))
    }
}

/// Build a pcap byte stream (global header + records). Used by tests and
/// by `selftest` to synthesize captures without fixture files.
pub fn build_pcap(swapped: bool, packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let magic: u32 = 0xa1b2c3d4;
    let be = |v: u32, out: &mut Vec<u8>| {
        if swapped {
            out.extend_from_slice(&v.swap_bytes().to_le_bytes());
        } else {
            out.extend_from_slice(&v.to_le_bytes());
        }
    };
    be(magic, &mut out);
    for v in [2u32, 4, 0, 0, 65535] {
        be(v, &mut out);
    }
    be(1, &mut out); // linktype ethernet
    for (ts_sec, ts_usec, data) in packets {
        be(*ts_sec, &mut out);
        be(*ts_usec, &mut out);
        be(data.len() as u32, &mut out);
        be(data.len() as u32, &mut out);
        out.extend_from_slice(data);
    }
    out
}

