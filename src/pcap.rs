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
    snaplen: usize,
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
        let snaplen = if swapped {
            u32::from_be_bytes([gh[16], gh[17], gh[18], gh[19]])
        } else {
            u32::from_le_bytes([gh[16], gh[17], gh[18], gh[19]])
        } as usize;
        let linktype = if swapped {
            u32::from_be_bytes([gh[20], gh[21], gh[22], gh[23]])
        } else {
            u32::from_le_bytes([gh[20], gh[21], gh[22], gh[23]])
        };
        if linktype != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported linktype {linktype} (only Ethernet=1)"),
            ));
        }
        Ok(PcapReader { inner, swapped, snaplen, peeked: None })
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
                    return Ok(None); // truncated tail: treat as end of stream
                }
                Err(e) => return Err(e),
            }
        }
        let ts_sec = self.read_u32([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let ts_usec = self.read_u32([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let incl_len = self.read_u32([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
        let orig_len = self.read_u32([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;
        if incl_len > 16 * 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet too large"));
        }
        if incl_len > self.snaplen {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "captured packet length exceeds pcap snaplen",
            ));
        }
        if incl_len > orig_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "captured packet length exceeds original length",
            ));
        }
        let mut data = vec![0u8; incl_len];
        if let Err(error) = self.inner.read_exact(&mut data) {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                return Ok(None); // A capture stopped while the final payload was being written.
            }
            return Err(error);
        }
        Ok(Some(Packet { ts_sec, ts_usec, data }))
    }
}

/// Build a pcap byte stream (global header + records). Used by tests and
/// by `selftest` to synthesize captures without fixture files.
pub fn build_pcap(swapped: bool, packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let magic: u32 = 0xa1b2c3d4;
    let be32 = |v: u32, out: &mut Vec<u8>| {
        if swapped {
            out.extend_from_slice(&v.swap_bytes().to_le_bytes());
        } else {
            out.extend_from_slice(&v.to_le_bytes());
        }
    };
    let be16 = |v: u16, out: &mut Vec<u8>| {
        if swapped {
            out.extend_from_slice(&v.swap_bytes().to_le_bytes());
        } else {
            out.extend_from_slice(&v.to_le_bytes());
        }
    };
    be32(magic, &mut out);
    be16(2, &mut out); // version major
    be16(4, &mut out); // version minor
    be32(0, &mut out); // thiszone
    be32(0, &mut out); // sigfigs
    be32(65535, &mut out); // snaplen
    be32(1, &mut out); // linktype: ethernet
    for (ts_sec, ts_usec, data) in packets {
        be32(*ts_sec, &mut out);
        be32(*ts_usec, &mut out);
        be32(data.len() as u32, &mut out);
        be32(data.len() as u32, &mut out);
        out.extend_from_slice(data);
    }
    out
}

/// Wrap a UDP payload in Ethernet + IPv4 + UDP headers the way a capture
/// would see it. Checksums are zero — captures don't require valid ones.
pub fn udp_frame(src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]); // dst mac
    f.extend_from_slice(&[0x6a, 0x3f, 0x11, 0x22, 0x33, 0x44]); // src mac
    f.extend_from_slice(&[0x08, 0x00]); // ethertype ipv4
    let ihl_ver = 0x45u8;
    let total = 20 + 8 + payload.len();
    f.push(ihl_ver);
    f.push(0);
    f.extend_from_slice(&(total as u16).to_be_bytes());
    f.extend_from_slice(&[0x00, 0x01]); // id
    f.extend_from_slice(&[0x00, 0x00]); // flags/frag
    f.push(64); // ttl
    f.push(17); // proto udp
    f.extend_from_slice(&[0, 0]); // checksum (ignored)
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f
}



#[cfg(test)]
mod truncated_payload_tests {
    use super::{PcapReader, build_pcap};
    use std::io::Cursor;

    #[test]
    fn incomplete_final_packet_payload_is_clean_eof() {
        let mut bytes = build_pcap(false, &[]);
        // Record header: timestamp, captured length=5, original length=5.
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&[0xaa, 0xbb]); // capture ended mid-payload

        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        assert!(reader.next_packet().unwrap().is_none());
    }

    #[test]
    fn captured_length_cannot_exceed_global_snaplen() {
        let packet = (10u32, 0u32, vec![1u8, 2, 3]);
        let mut bytes = build_pcap(false, &[packet]);
        // The pcap global-header snaplen field occupies bytes 16..20.
        bytes[16..20].copy_from_slice(&2u32.to_le_bytes());

        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        let error = reader.next_packet().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("snaplen"));
    }

    #[test]
    fn captured_length_cannot_exceed_original_length() {
        let packet = (10u32, 0u32, vec![1u8, 2, 3]);
        let mut bytes = build_pcap(false, &[packet]);
        // The global header is 24 bytes; orig_len occupies record-header bytes 12..16.
        bytes[24 + 12..24 + 16].copy_from_slice(&2u32.to_le_bytes());

        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        let error = reader.next_packet().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("original length"));
    }

    #[test]
    fn complete_packet_before_truncated_tail_is_preserved() {
        let packet = (10u32, 0u32, vec![1u8, 2, 3]);
        let mut bytes = build_pcap(false, &[packet]);
        bytes.extend_from_slice(&11u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&[0xaa]);

        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        let first = reader.next_packet().unwrap().unwrap();
        assert_eq!(first.ts_sec, 10);
        assert_eq!(first.data, vec![1, 2, 3]);
        assert!(reader.next_packet().unwrap().is_none());
    }
}
