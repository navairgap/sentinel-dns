//! sentinel-dns — passive DNS exfiltration and DGA detection.
//!
//! Reads libpcap data (files or a live `tcpdump` pipe), scores resolver
//! traffic per client per window, and alerts on sustained badness.
//!
//!   sentinel-dns analyze capture.pcap
//!   tcpdump -i eth0 -w - port 53 | sentinel-dns watch
//!   sentinel-dns selftest

mod alert;
mod config;
mod dns;
mod pcap;
mod score;

use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use alert::Alert;
use config::Config;
use score::{Tracker, window_score};

