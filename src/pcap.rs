//! Minimal libpcap file/stream reader. Supports the classic pcap format
//! (microsecond magic) with Ethernet link type, in both byte orders. No
//! external dependencies: the format is small enough to parse by hand.
//!
//! Reading is *resumable*: if the underlying stream reports `WouldBlock`
//! (a polled pipe with no data yet), the partially read record is kept and
//! the next call picks up exactly where it stopped. `UnexpectedEof` is
//! treated as a clean end of stream, because live `tcpdump` pipes end that
//! way when the capture is torn down.

use std::io::{self, Read};

/// One captured packet with its timestamp.
#[derive(Debug, Clone)]
pub struct Packet {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub data: Vec<u8>,
}

/// Hard cap on a single record's captured length, independent of snaplen:
/// a corrupt length field must never drive a huge allocation.
const MAX_INCL_LEN: usize = 16 * 1024 * 1024;

struct PartialRecord {
    ts_sec: u32,
    ts_usec: u32,
    data: Vec<u8>,
    filled: usize,
}

/// Incremental reader over a pcap byte stream (file or pipe).
pub struct PcapReader<R> {
    inner: R,
    big_endian: bool,
    snaplen: usize,
    header: [u8; 16],
    header_filled: usize,
    record: Option<PartialRecord>,
}

impl<R: Read> PcapReader<R> {
    /// Parse the 24-byte global header. Supports little- and big-endian
    /// captures; nanosecond-resolution and pcapng files are rejected with a
    /// clear error.
    pub fn new(mut inner: R) -> io::Result<Self> {
        let mut gh = [0u8; 24];
        inner.read_exact(&mut gh)?;
        let magic = u32::from_le_bytes([gh[0], gh[1], gh[2], gh[3]]);
        let (big_endian, ok) = match magic {
            0xa1b2c3d4 => (false, true), // file stores little-endian fields
            0xd4c3b2a1 => (true, true),  // file stores big-endian fields
            _ => (false, false),
        };
        if !ok {
            let reason = match magic {
                0xa1b23c4d | 0x4d3cb2a1 => {
                    "nanosecond-resolution pcap is unsupported (use microsecond resolution)"
                }
                _ => "not a classic pcap file (bad magic; pcapng is unsupported)",
            };
            return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
        }
        let u16_at = |off: usize| -> u16 {
            let b = [gh[off], gh[off + 1]];
            if big_endian {
                u16::from_be_bytes(b)
            } else {
                u16::from_le_bytes(b)
            }
        };
        let u32_at = |off: usize| -> u32 {
            let b = [gh[off], gh[off + 1], gh[off + 2], gh[off + 3]];
            if big_endian {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            }
        };
        if (u16_at(4), u16_at(6)) != (2, 4) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported pcap version {}.{} (expected 2.4)",
                    u16_at(4),
                    u16_at(6)
                ),
            ));
        }
        let snaplen = u32_at(16) as usize;
        if snaplen == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pcap snaplen must be greater than zero",
            ));
        }
        let linktype = u32_at(20);
        if linktype != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported linktype {linktype} (only Ethernet=1)"),
            ));
        }
        Ok(PcapReader {
            inner,
            big_endian,
            snaplen,
            header: [0; 16],
            header_filled: 0,
            record: None,
        })
    }

    fn header_u32(&self, off: usize) -> u32 {
        let b = [
            self.header[off],
            self.header[off + 1],
            self.header[off + 2],
            self.header[off + 3],
        ];
        if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    }

    /// Read the next packet record; `Ok(None)` on clean end of stream.
    /// Truncated trailing data (a capture cut mid-write) ends the stream
    /// instead of erroring — important for live `tcpdump` pipes. A
    /// `WouldBlock` error leaves all partial-read state intact.
    pub fn next_packet(&mut self) -> io::Result<Option<Packet>> {
        // Fill the 16-byte record header across as many calls as needed.
        while self.header_filled < 16 {
            let mut byte = [0u8; 1];
            match self.inner.read_exact(&mut byte) {
                Ok(()) => {
                    self.header[self.header_filled] = byte[0];
                    self.header_filled += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e), // WouldBlock and others propagate
            }
        }

        let ts_sec = self.header_u32(0);
        let ts_usec = self.header_u32(4);
        let incl_len = self.header_u32(8) as usize;
        let orig_len = self.header_u32(12) as usize;
        if ts_usec >= 1_000_000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pcap packet timestamp microseconds must be below one million",
            ));
        }
        if incl_len > MAX_INCL_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too large",
            ));
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

        // Start (or resume) the payload buffer for this record. Progress is
        // persisted on every read, so a WouldBlock partway through resumes
        // from the exact byte where it stopped.
        if self.record.is_none() {
            self.record = Some(PartialRecord {
                ts_sec,
                ts_usec,
                data: vec![0u8; incl_len],
                filled: 0,
            });
        }
        let record = self.record.as_mut().expect("record initialized");
        while record.filled < record.data.len() {
            match self.inner.read(&mut record.data[record.filled..]) {
                Ok(0) => return Ok(None), // capture ended mid-payload
                Ok(n) => record.filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e), // WouldBlock and others propagate
            }
        }
        let record = self.record.take().expect("record initialized");
        self.header_filled = 0;
        Ok(Some(Packet {
            ts_sec: record.ts_sec,
            ts_usec: record.ts_usec,
            data: record.data,
        }))
    }
}

fn put16(out: &mut Vec<u8>, v: u16, big_endian: bool) {
    if big_endian {
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn put32(out: &mut Vec<u8>, v: u32, big_endian: bool) {
    if big_endian {
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// Build a pcap byte stream (global header + records). Used by tests and
/// by `selftest` to synthesize captures without fixture files.
pub fn build_pcap(swapped: bool, packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    put32(&mut out, 0xa1b2c3d4, swapped); // magic
    put16(&mut out, 2, swapped); // version major
    put16(&mut out, 4, swapped); // version minor
    put32(&mut out, 0, swapped); // thiszone
    put32(&mut out, 0, swapped); // sigfigs
    put32(&mut out, 65535, swapped); // snaplen
    put32(&mut out, 1, swapped); // linktype: ethernet
    for (ts_sec, ts_usec, data) in packets {
        put32(&mut out, *ts_sec, swapped);
        put32(&mut out, *ts_usec, swapped);
        put32(&mut out, data.len() as u32, swapped);
        put32(&mut out, data.len() as u32, swapped);
        out.extend_from_slice(data);
    }
    out
}

/// Wrap a UDP payload in Ethernet + IPv4 + UDP headers the way a capture
/// would see it. Checksums are zero — captures don't require valid ones.
pub fn udp_frame(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]); // dst mac
    f.extend_from_slice(&[0x6a, 0x3f, 0x11, 0x22, 0x33, 0x44]); // src mac
    f.extend_from_slice(&[0x08, 0x00]); // ethertype ipv4
    f.push(0x45); // version 4, IHL 20 bytes
    f.push(0); // DSCP/ECN
    f.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes()); // total length
    f.extend_from_slice(&[0x00, 0x01]); // identification
    f.extend_from_slice(&[0x00, 0x00]); // flags / fragment offset
    f.push(64); // ttl
    f.push(17); // protocol: UDP
    f.extend_from_slice(&[0, 0]); // checksum (ignored)
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]); // checksum (ignored)
    f.extend_from_slice(payload);
    f
}

#[cfg(test)]
mod tests {
    use super::{build_pcap, Packet, PcapReader};
    use std::io::{self, Cursor, Read};

    /// Feeds bytes in tiny chunks and injects one WouldBlock at `fault_at`.
    struct FaultyReader {
        data: Vec<u8>,
        pos: usize,
        fault_at: usize,
        faulted: bool,
    }

    impl FaultyReader {
        fn new(data: Vec<u8>, fault_at: usize) -> Self {
            FaultyReader {
                data,
                pos: 0,
                fault_at,
                faulted: false,
            }
        }
    }

    impl Read for FaultyReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            if self.pos >= self.fault_at && !self.faulted {
                self.faulted = true;
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let n = buf.len().min(self.data.len() - self.pos).min(3);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn sample_packets() -> Vec<(u32, u32, Vec<u8>)> {
        vec![
            (10, 0, vec![1, 2, 3, 4, 5]),
            (11, 999, vec![0xaa; 60]),
            (12, 42, vec![7u8; 17]),
        ]
    }

    fn read_all<R: Read>(reader: R) -> io::Result<Vec<Packet>> {
        let mut reader = PcapReader::new(reader)?;
        let mut out = Vec::new();
        while let Some(p) = reader.next_packet()? {
            out.push(p);
        }
        Ok(out)
    }

    #[test]
    fn parses_little_and_big_endian_files_identically() {
        let packets = sample_packets();
        let le = read_all(Cursor::new(build_pcap(false, &packets))).unwrap();
        let be = read_all(Cursor::new(build_pcap(true, &packets))).unwrap();
        let dump = |ps: &[Packet]| -> Vec<(u32, u32, Vec<u8>)> {
            ps.iter()
                .map(|p| (p.ts_sec, p.ts_usec, p.data.clone()))
                .collect()
        };
        assert_eq!(dump(&le), packets);
        assert_eq!(dump(&be), packets);
    }

    #[test]
    fn rejects_invalid_global_header_magic() {
        let mut bytes = build_pcap(false, &[]);
        bytes[0..4].copy_from_slice(&[0, 0, 0, 0]);
        let error = match PcapReader::new(Cursor::new(bytes)) {
            Err(error) => error,
            Ok(_) => panic!("invalid pcap magic unexpectedly accepted"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("bad magic"));
    }

    #[test]
    fn names_nanosecond_resolution_as_the_rejection_reason() {
        let mut bytes = build_pcap(false, &[]);
        bytes[0..4].copy_from_slice(&0xa1b23c4du32.to_le_bytes());
        let error = PcapReader::new(Cursor::new(bytes))
            .err()
            .expect("ns magic rejected");
        assert!(error.to_string().contains("nanosecond"), "message: {error}");
    }

    #[test]
    fn rejects_input_shorter_than_a_global_header() {
        let error = PcapReader::new(Cursor::new(vec![0u8; 10]))
            .err()
            .expect("short input rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn empty_capture_has_no_packets() {
        let bytes = build_pcap(false, &[]);
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        assert!(reader.next_packet().unwrap().is_none());
    }

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
    fn incomplete_record_header_is_clean_eof() {
        let mut bytes = build_pcap(false, &[]);
        bytes.extend_from_slice(&[0x11, 0x22, 0x33]); // 3 of 16 header bytes

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

    #[test]
    fn rejects_unsupported_classic_pcap_versions() {
        let mut bytes = build_pcap(false, &[]);
        bytes[4..6].copy_from_slice(&3u16.to_le_bytes());
        let error = PcapReader::new(Cursor::new(bytes))
            .err()
            .expect("invalid header must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("expected 2.4"));
    }

    #[test]
    fn rejects_zero_snaplen() {
        let mut bytes = build_pcap(false, &[]);
        bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        let error = PcapReader::new(Cursor::new(bytes))
            .err()
            .expect("invalid header must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("snaplen"));
    }

    #[test]
    fn rejects_microsecond_timestamps_outside_the_valid_range() {
        let bytes = build_pcap(false, &[(10, 1_000_000, vec![0xaa])]);
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        let error = reader.next_packet().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("microseconds"));
    }

    #[test]
    fn would_block_mid_header_preserves_partial_bytes() {
        let bytes = build_pcap(false, &sample_packets());
        // 24-byte global header + part of the first record header.
        let reader = PcapReader::new(FaultyReader::new(bytes, 30));
        let mut packets = Vec::new();
        let mut saw_block = false;
        let mut reader = reader.unwrap();
        loop {
            match reader.next_packet() {
                Ok(Some(p)) => packets.push(p),
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => saw_block = true,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert!(saw_block, "the injected WouldBlock must surface");
        assert_eq!(packets.len(), 3);
    }

    #[test]
    fn would_block_mid_payload_preserves_partial_payload() {
        let bytes = build_pcap(false, &sample_packets());
        // Fault inside the first packet's payload (24 + 16 + 2 bytes in).
        let reader = PcapReader::new(FaultyReader::new(bytes, 42));
        let mut packets = Vec::new();
        let mut saw_block = false;
        let mut reader = reader.unwrap();
        loop {
            match reader.next_packet() {
                Ok(Some(p)) => packets.push(p),
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => saw_block = true,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert!(saw_block, "the injected WouldBlock must surface");
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn zero_length_record_yields_an_empty_packet() {
        let bytes = build_pcap(false, &[(5, 0, Vec::new())]);
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        let packet = reader.next_packet().unwrap().expect("packet exists");
        assert!(packet.data.is_empty());
        assert!(reader.next_packet().unwrap().is_none());
    }
}

#[cfg(test)]
mod record_validation_tests {
    use super::{build_pcap, PcapReader};
    use std::io::Cursor;

    #[test]
    fn captured_length_at_the_snaplen_boundary_is_accepted() {
        let payload = vec![0u8; 100];
        let mut bytes = build_pcap(false, &[(10, 0, payload)]);
        bytes[16..20].copy_from_slice(&100u32.to_le_bytes()); // snaplen == incl_len
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        let packet = reader
            .next_packet()
            .unwrap()
            .expect("boundary length is legal");
        assert_eq!(packet.data.len(), 100);
    }

    #[test]
    fn captured_length_over_the_hard_cap_is_rejected() {
        // incl_len above the 16 MiB cap, with a snaplen large enough that
        // only the cap catches it.
        let mut bytes = build_pcap(false, &[]);
        bytes.extend_from_slice(&10u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(17 * 1024 * 1024 as u32).to_le_bytes()); // incl_len
        bytes.extend_from_slice(&(17 * 1024 * 1024 as u32).to_le_bytes()); // orig_len
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        let error = reader.next_packet().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("too large"));
    }

    #[test]
    fn records_follow_each_other_back_to_back() {
        let packets = vec![
            (1u32, 0u32, vec![1u8]),
            (2, 1, vec![2, 2]),
            (3, 2, vec![3, 3, 3]),
            (4, 3, vec![]),
        ];
        let bytes = build_pcap(false, &packets);
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        for (ts_sec, ts_usec, data) in &packets {
            let p = reader.next_packet().unwrap().expect("record exists");
            assert_eq!(p.ts_sec, *ts_sec);
            assert_eq!(p.ts_usec, *ts_usec);
            assert_eq!(&p.data, data);
        }
        assert!(reader.next_packet().unwrap().is_none());
    }

    #[test]
    fn a_truncated_header_after_valid_records_is_clean_eof() {
        let mut bytes = build_pcap(false, &[(1, 0, vec![9])]);
        bytes.extend_from_slice(&[0xde, 0xad]); // 2 of 16 record-header bytes
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        assert!(reader.next_packet().unwrap().is_some());
        assert!(reader.next_packet().unwrap().is_none());
    }
}

#[cfg(test)]
mod linktype_tests {
    use super::{build_pcap, PcapReader};
    use std::io::Cursor;

    #[test]
    fn non_ethernet_linktypes_are_rejected_by_name() {
        let mut bytes = build_pcap(false, &[]);
        // Linktype field occupies global-header bytes 20..24.
        bytes[20..24].copy_from_slice(&113u32.to_le_bytes()); // Linux SLL
        let error = PcapReader::new(Cursor::new(bytes)).err().expect("rejected");
        assert!(error.to_string().contains("linktype"), "message: {error}");
    }
}
