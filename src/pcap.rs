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

