//! Minimal libpcap file/stream reader. Supports the classic pcap format
//! (microsecond magic 0xa1b2c3d4) with Ethernet link type. No external
//! dependencies: the format is small enough to parse by hand.

use std::io::{self, Read};

