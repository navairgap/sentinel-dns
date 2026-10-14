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

static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_hup(_sig: i32) {
    RELOAD.store(true, Ordering::SeqCst);
}

const USAGE: &str = "sentinel-dns — passive DNS exfiltration and DGA detection

USAGE:
    sentinel-dns <command> [options]

COMMANDS:
    analyze <file.pcap>     score an offline capture
    watch                   read a pcap stream from stdin (tcpdump pipe)
    selftest                synthesize a capture and verify the pipeline
    config                  print the default configuration

OPTIONS:
    -c, --config <path>     config file (default: built-in defaults)
    -v, --verbose           print skipped-packet reasons to stderr
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        print!("{USAGE}");
        return ExitCode::from(2);
    };

    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");
    let cfg_path = args
        .iter()
        .position(|a| a == "-c" || a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);

    let config = match &cfg_path {
        Some(p) => match Config::load(p) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sentinel-dns: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => Config::default(),
    };

    // SIGHUP asks the loop to reload the config between windows.
    unsafe {
        libc::signal(libc::SIGHUP, on_hup as usize);
    }

