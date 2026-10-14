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

    match cmd {
        "analyze" => match args.get(1) {
            Some(file) => run_reader(
                BufReader::new(match std::fs::File::open(file) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("sentinel-dns: {file}: {e}");
                        return ExitCode::FAILURE;
                    }
                }),
                &config,
                cfg_path.as_deref(),
                verbose,
                false,
            ),
            None => {
                eprintln!("sentinel-dns: analyze needs a pcap file");
                ExitCode::from(2)
            }
        },
        "watch" => run_reader(BufReader::new(io::stdin().lock()), &config, cfg_path.as_deref(), verbose, true),
        "selftest" => selftest(),
        "config" => {
            println!("{}", Config::default_json());
            ExitCode::SUCCESS
        }
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("sentinel-dns: unknown command {other:?}\n");
            print!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Shared pipeline over any pcap byte source. In `live` mode (stdin pipe)
/// windows are emitted as time passes; offline, everything drains at the end.
fn run_reader<R: io::Read>(
    reader: R,
    config: &Config,
    cfg_path: Option<&std::path::Path>,
    verbose: bool,
    live: bool,
) -> ExitCode {
    let mut reader = match pcap::PcapReader::new(reader) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sentinel-dns: not a pcap stream: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut tracker = Tracker::new(config.window_seconds);
    let mut highest_seen_window = 0u64;
    let mut consecutive: std::collections::HashMap<[u8; 4], u64> = std::collections::HashMap::new();
    let mut fired: std::collections::HashMap<[u8; 4], u64> = std::collections::HashMap::new();
    let mut config = config.clone();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    loop {
        if RELOAD.swap(false, Ordering::SeqCst) {
            match cfg_path {
                Some(p) => match Config::load(p) {
                    Ok(c) => {
                        config = c;
                        eprintln!("sentinel-dns: config reloaded from {}", p.display());
                    }
                    Err(e) => eprintln!("sentinel-dns: reload failed: {e}"),
                },
                None => eprintln!("sentinel-dns: SIGHUP ignored (no -c config path)"),
            }
        }

        let pkt = match reader.next_packet() {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(e) => {
                if verbose {
                    eprintln!("sentinel-dns: stream ended: {e}");
                }
                break;
            }
        };
        let ts = pkt.ts_sec as u64;
        let window = ts / config.window_seconds.max(1);
        if window > highest_seen_window {
            highest_seen_window = window;
            // all windows before the current one are final
            emit_due(&mut tracker, window, &config, &mut consecutive, &mut fired, &mut out);
        }

        match dns::extract_query(&pkt.data) {
            Ok(Some(q)) => {
                if config.is_trusted(q.client) {
                    continue;
                }
                tracker.observe_at(&q, ts);
            }
            Ok(None) => {}
            Err(e) => {
                if verbose {
                    eprintln!("sentinel-dns: skipped packet: {e}");
                }
            }
        }
        if live {
            out.flush().ok();
        }
    }

    emit_due(&mut tracker, u64::MAX, &config, &mut consecutive, &mut fired, &mut out);
    out.flush().ok();
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn emit_due(
    tracker: &mut Tracker,
    before: u64,
    config: &Config,
    consecutive: &mut std::collections::HashMap<[u8; 4], u64>,
    fired: &mut std::collections::HashMap<[u8; 4], u64>,
    out: &mut impl Write,
) {
    let due = tracker.drain_older_than(before);
    for (window, client, stats) in due {
        let (score, reasons) = window_score(&stats);
        if score >= config.score_threshold {
            *consecutive.entry(client).or_insert(0) += 1;
        } else {
            consecutive.remove(&client);
        }
        let streak = *consecutive.get(&client).unwrap_or(&0);
        let already = *fired.get(&client).unwrap_or(&0);
        if streak >= config.windows_before_alert && already < streak {
            let a = Alert {
                client: client.map(|b| b.to_string()).join("."),
                window_start: window * config.window_seconds,
                score,
                reasons,
                queries: stats.queries,
                nxdomains: stats.nxdomains,
            };
            writeln!(out, "{}", a.to_jsonl()).ok();
            if !config.webhook_url.is_empty() {
                alert::send_webhook(&config.webhook_url, &a.to_jsonl());
            }
            fired.insert(client, streak);
        }
        if score < config.score_threshold {
            fired.remove(&client);
        }
    }
}

