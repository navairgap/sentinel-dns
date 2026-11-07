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

use std::collections::{HashMap, HashSet};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alert::Alert;
use config::Config;
use score::{window_score, Tracker, WindowStats};

static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_hup(_sig: i32) {
    RELOAD.store(true, Ordering::SeqCst);
}

/// How often a quiet live pipe wakes the loop, in milliseconds. This bounds
/// how late wall-clock window closes and SIGHUP handling can be.
const POLL_TIMEOUT_MS: i32 = 500;

const USAGE: &str = "sentinel-dns — passive DNS exfiltration and DGA detection

USAGE:
    sentinel-dns <command> [options]

COMMANDS:
    analyze <file.pcap>     score an offline pcap capture
    watch                   read a pcap stream from stdin (tcpdump pipe)
    selftest                synthesize a capture and verify the pipeline
    config                  print the default configuration

OPTIONS:
    -c, --config <path>     config file (default: built-in defaults)
    -v, --verbose           log skipped packets to stderr
    -V, --version           print the version
    -h, --help              print this help
";

#[derive(Debug)]
enum Command {
    Analyze(PathBuf),
    Watch,
    Selftest,
    PrintConfig,
    PrintVersion,
    Help,
}

#[derive(Debug)]
struct Invocation {
    command: Command,
    config_path: Option<PathBuf>,
    verbose: bool,
}

/// Parse argv (without the program name). Flags may appear in any order
/// relative to the command.
fn parse_args(args: &[String]) -> Result<Invocation, String> {
    let mut command: Option<Command> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut verbose = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-v" | "--verbose" => verbose = true,
            "-c" | "--config" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "-c/--config needs a file path".to_string())?;
                if config_path.replace(PathBuf::from(value)).is_some() {
                    return Err("-c/--config given more than once".to_string());
                }
            }
            "-V" | "--version" => {
                if command.is_some() {
                    return Err("--version cannot be combined with a command".to_string());
                }
                command = Some(Command::PrintVersion);
            }
            "-h" | "--help" | "help" => {
                if command.is_some() {
                    return Err("--help cannot be combined with a command".to_string());
                }
                command = Some(Command::Help);
            }
            "analyze" => {
                i += 1;
                let file = args
                    .get(i)
                    .ok_or_else(|| "analyze needs a pcap file".to_string())?;
                if file.starts_with('-') {
                    return Err(format!("analyze: {file:?} does not look like a pcap file"));
                }
                if command.is_some() {
                    return Err("only one command can be given".to_string());
                }
                command = Some(Command::Analyze(PathBuf::from(file)));
            }
            "watch" | "selftest" | "config" => {
                if command.is_some() {
                    return Err("only one command can be given".to_string());
                }
                command = Some(match arg {
                    "watch" => Command::Watch,
                    "selftest" => Command::Selftest,
                    _ => Command::PrintConfig,
                });
            }
            other => return Err(format!("unknown command or flag {other:?}")),
        }
        i += 1;
    }

    Ok(Invocation {
        command: command.ok_or("no command given")?,
        config_path,
        verbose,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let invocation = match parse_args(&args) {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("sentinel-dns: {e}\n");
            print!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    // SIGHUP asks the pipeline loop to reload the config at the next safe
    // point. SAFETY: the handler only sets an atomic flag; it allocates
    // nothing and is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGHUP, on_hup as *const () as usize);
    }

    let config = match &invocation.config_path {
        Some(p) => match Config::load(p) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sentinel-dns: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => Config::default(),
    };

    match invocation.command {
        Command::Help => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Command::PrintVersion => {
            println!("sentinel-dns {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::PrintConfig => {
            println!("{}", Config::default_json());
            ExitCode::SUCCESS
        }
        Command::Selftest => selftest(),
        Command::Analyze(file) => match std::fs::File::open(&file) {
            Ok(f) => {
                let stdout = io::stdout();
                let mut out = BufWriter::new(stdout.lock());
                match run_pipeline(
                    BufReader::new(f),
                    &config,
                    invocation.config_path.as_deref(),
                    invocation.verbose,
                    false,
                    &mut out,
                ) {
                    Some(stats) => {
                        out.flush().ok();
                        if stats.packets > 0 {
                            eprintln!(
                                "sentinel-dns: {} packets, {} dns messages, {} alerts",
                                stats.packets, stats.dns_messages, stats.alerts
                            );
                        }
                        ExitCode::SUCCESS
                    }
                    None => ExitCode::FAILURE,
                }
            }
            Err(e) => {
                eprintln!("sentinel-dns: {}: {e}", file.display());
                ExitCode::FAILURE
            }
        },
        Command::Watch => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            let mut out = BufWriter::new(stdout.lock());
            let ran = run_pipeline(
                TimeoutReader::new(stdin.lock(), POLL_TIMEOUT_MS),
                &config,
                invocation.config_path.as_deref(),
                invocation.verbose,
                true,
                &mut out,
            );
            out.flush().ok();
            if ran.is_some() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// Serve stdin with `poll(2)`: identical behavior while traffic flows, but
/// a quiet pipe returns `WouldBlock` after the timeout so the caller can
/// close windows on wall-clock time and process SIGHUP while the capture
/// is silent.
///
/// Mechanism: the descriptor is made non-blocking, a read that reports
/// `EAGAIN` waits in `poll` (bounded), then retries. This is safe to pair
/// with the descriptor's own buffering — `StdinLock` serves its internal
/// buffer before any syscall, so `EAGAIN` means both the buffer and the
/// descriptor are truly empty. The original descriptor flags are restored
/// on drop so a shared terminal keeps its blocking behavior for others.
struct TimeoutReader {
    inner: io::StdinLock<'static>,
    timeout_ms: i32,
    saved_flags: Option<i32>,
}

impl TimeoutReader {
    fn new(inner: io::StdinLock<'static>, timeout_ms: i32) -> Self {
        // SAFETY: plain fcntl flag read/write on our own stdin descriptor.
        let current = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) };
        let saved_flags = if current >= 0 { Some(current) } else { None };
        if let Some(flags) = saved_flags {
            unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }
        TimeoutReader {
            inner,
            timeout_ms,
            saved_flags,
        }
    }
}

impl Drop for TimeoutReader {
    fn drop(&mut self) {
        if let Some(flags) = self.saved_flags {
            // SAFETY: restoring the flags read at construction.
            unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, flags) };
        }
    }
}

impl Read for TimeoutReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let mut fds = [libc::pollfd {
                    fd: libc::STDIN_FILENO,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                // SAFETY: fds outlives the call; a single-fd poll is trivial.
                let ready = unsafe { libc::poll(fds.as_mut_ptr(), 1, self.timeout_ms) };
                if ready < 0 {
                    return Err(io::Error::last_os_error()); // EINTR and friends
                }
                if ready == 0 {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock)); // poll timeout
                }
                self.inner.read(buf)
            }
            result => result,
        }
    }
}

/// Per-client alert bookkeeping: the consecutive-bad-window streak, whether
/// the current streak has already fired an alert, and the highest window
/// already scored. The watermark keeps late packets (or a lagging live
/// pipe) from re-creating a drained window and scoring it twice; it grows
/// with the number of distinct clients seen, which is what a monitor of a
/// fixed network does anyway.
#[derive(Default)]
struct AlertState {
    consecutive: HashMap<[u8; 4], u64>,
    alerted: HashSet<[u8; 4]>,
    last_closed: HashMap<[u8; 4], u64>,
}

impl AlertState {
    /// Score one closed window. Windows must arrive in ascending order
    /// (`Tracker::drain_older_than` guarantees this). Fires an alert exactly
    /// when the client crosses the threshold for the first time in the
    /// current streak — sustained badness alerts once, and a clean window
    /// re-arms it.
    fn close_window(
        &mut self,
        config: &Config,
        window: u64,
        client: [u8; 4],
        stats: &WindowStats,
    ) -> Option<Alert> {
        if self
            .last_closed
            .get(&client)
            .is_some_and(|&seen| seen >= window)
        {
            return None; // already scored; this is a duplicate close
        }
        self.last_closed.insert(client, window);

        let (score, reasons) = window_score(stats);
        if score >= config.score_threshold {
            let streak = self.consecutive.entry(client).or_insert(0);
            *streak += 1;
            if *streak >= config.windows_before_alert && self.alerted.insert(client) {
                return Some(Alert {
                    client: std::net::Ipv4Addr::from(client).to_string(),
                    window_start: window * config.window_seconds,
                    score,
                    reasons,
                    queries: stats.queries,
                    nxdomains: stats.nxdomains,
                });
            }
        } else {
            self.consecutive.remove(&client);
            self.alerted.remove(&client);
        }
        None
    }
}

/// Totals reported for offline runs.
#[derive(Debug, Default, PartialEq, Eq)]
struct PipelineStats {
    packets: u64,
    dns_messages: u64,
    alerts: u64,
}

/// Shared pipeline over any pcap byte source. In `live` mode (stdin pipe)
/// a quiet pipe closes finished windows on wall-clock time; offline, all
/// windows drain when the file ends. Windows strictly older than the
/// current packet's window are closed as packets arrive, which keeps the
/// tracker bounded even if timestamps jump backwards. Returns `None` when
/// the stream is not a pcap file at all.
fn run_pipeline<R: Read, W: Write>(
    reader: R,
    config: &Config,
    cfg_path: Option<&Path>,
    verbose: bool,
    live: bool,
    out: &mut W,
) -> Option<PipelineStats> {
    let mut reader = match pcap::PcapReader::new(reader) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sentinel-dns: not a pcap stream: {e}");
            return None;
        }
    };
    let mut tracker = Tracker::new(config.window_seconds);
    let mut alerts = AlertState::default();
    let mut config = config.clone();
    let mut stats = PipelineStats::default();

    loop {
        // SIGHUP is handled between packets and on poll timeouts.
        if RELOAD.swap(false, Ordering::SeqCst) {
            match cfg_path {
                Some(p) => match Config::load(p) {
                    Ok(c) => {
                        // A changed window length invalidates every window
                        // key and watermark; start scoring fresh rather
                        // than mixing scales.
                        if c.window_seconds != config.window_seconds {
                            tracker = Tracker::new(c.window_seconds);
                            alerts = AlertState::default();
                        }
                        config = c;
                        eprintln!("sentinel-dns: config reloaded from {}", p.display());
                    }
                    Err(e) => {
                        eprintln!("sentinel-dns: reload failed, keeping previous config: {e}")
                    }
                },
                None => eprintln!("sentinel-dns: SIGHUP ignored (no -c config path)"),
            }
        }

        let packet = match reader.next_packet() {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(e) if live && e.kind() == io::ErrorKind::WouldBlock => {
                // Pipe is quiet: close windows that wall-clock time has finished.
                let now = unix_now();
                close_windows(
                    &mut tracker,
                    now / config.window_seconds.max(1),
                    &config,
                    &mut alerts,
                    out,
                    &mut stats.alerts,
                );
                out.flush().ok();
                continue;
            }
            Err(e) => {
                if verbose {
                    eprintln!("sentinel-dns: stream ended early: {e}");
                }
                break;
            }
        };
        stats.packets += 1;
        let ts = u64::from(packet.ts_sec);
        let window = ts / config.window_seconds.max(1);
        close_windows(
            &mut tracker,
            window,
            &config,
            &mut alerts,
            out,
            &mut stats.alerts,
        );

        match dns::extract_query(&packet.data) {
            Ok(Some(q)) => {
                stats.dns_messages += 1;
                if verbose {
                    eprintln!(
                        "pkt {}.{:06} {} qtype={} {}",
                        packet.ts_sec,
                        packet.ts_usec,
                        q.name,
                        q.qtype,
                        if q.is_nxdomain() { "NXDOMAIN" } else { "" }
                    );
                }
                if !config.is_trusted(q.client) {
                    tracker.observe_at(&q, ts);
                }
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

    close_windows(
        &mut tracker,
        u64::MAX,
        &config,
        &mut alerts,
        out,
        &mut stats.alerts,
    );
    Some(stats)
}

fn close_windows(
    tracker: &mut Tracker,
    before: u64,
    config: &Config,
    alerts: &mut AlertState,
    out: &mut impl Write,
    fired: &mut u64,
) {
    for (window, client, stats) in tracker.drain_older_than(before) {
        if let Some(alert) = alerts.close_window(config, window, client, &stats) {
            let line = alert.to_jsonl();
            writeln!(out, "{line}").ok();
            *fired += 1;
            if !config.webhook_url.is_empty() {
                alert::send_webhook(config.webhook_url.clone(), line);
            }
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a synthetic capture — one clean client, one DGA offender whose
/// every lookup fails — run the full pipeline over it, and verify exactly
/// one alert fires for exactly the offender. Exits non-zero on any failure;
/// CI runs this.
fn selftest() -> ExitCode {
    let mut packets: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let base = 1_700_000_000u32;

    for i in 0..30 {
        let name = format!("api{i}.github.com");
        let q = dns::build_query(i as u16, &name, 1);
        packets.push((
            base,
            i as u32,
            pcap::udp_frame([10, 0, 0, 8], [1, 1, 1, 1], 40000, 53, &q),
        ));
    }
    for i in 0..25 {
        let name = format!("xq7z9w2k1v4b8-{i}.example.xyz");
        let q = dns::build_query(1000 + i as u16, &name, 1);
        packets.push((
            base,
            1000 + i as u32,
            pcap::udp_frame([10, 0, 0, 7], [1, 1, 1, 1], 40001, 53, &q),
        ));
        let resp = dns::build_response(&q, 3);
        packets.push((
            base,
            2000 + i as u32,
            pcap::udp_frame([1, 1, 1, 1], [10, 0, 0, 7], 53, 40001, &resp),
        ));
    }

    let bytes = pcap::build_pcap(false, &packets);
    let cfg = Config {
        score_threshold: 0.5,
        windows_before_alert: 1,
        ..Config::default()
    };

    let mut sink = Vec::new();
    let stats = match run_pipeline(&bytes[..], &cfg, None, false, false, &mut sink) {
        Some(stats) => stats,
        None => {
            eprintln!("selftest: pipeline rejected the synthesized pcap");
            return ExitCode::FAILURE;
        }
    };

    let text = String::from_utf8_lossy(&sink);
    let alert_lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    if stats.packets != packets.len() as u64 {
        eprintln!(
            "selftest: read {} packets, expected {}",
            stats.packets,
            packets.len()
        );
        return ExitCode::FAILURE;
    }
    if alert_lines.len() != 1 {
        eprintln!(
            "selftest: expected exactly 1 alert, got {}",
            alert_lines.len()
        );
        return ExitCode::FAILURE;
    }
    if !alert_lines[0].contains("\"client\":\"10.0.0.7\"") {
        eprintln!(
            "selftest: alert fired for the wrong client: {}",
            alert_lines[0]
        );
        return ExitCode::FAILURE;
    }
    println!("selftest OK — 1 alert, correct client: {}", alert_lines[0]);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod alert_state_tests {
    use super::AlertState;
    use crate::config::Config;
    use crate::score::WindowStats;

    fn bad_stats() -> WindowStats {
        WindowStats {
            queries: 40,
            nxdomains: 30,
            suspicious: 30,
            reasons: vec!["high_entropy".to_string()],
        }
    }

    #[test]
    fn one_alert_per_bad_streak_not_per_window() {
        let config = Config {
            windows_before_alert: 3,
            ..Config::default()
        };
        let client = [10, 0, 0, 9];
        let mut alerts = AlertState::default();

        let mut fired = Vec::new();
        for window in 0..6u64 {
            if let Some(a) = alerts.close_window(&config, window, client, &bad_stats()) {
                fired.push(a);
            }
        }
        assert_eq!(fired.len(), 1, "a sustained streak must alert exactly once");

        // A clean window re-arms the client.
        let clean = WindowStats::default();
        assert!(alerts.close_window(&config, 6, client, &clean).is_none());
        for window in 7..10u64 {
            if let Some(a) = alerts.close_window(&config, window, client, &bad_stats()) {
                fired.push(a);
            }
        }
        assert_eq!(
            fired.len(),
            2,
            "a new streak after going clean must alert again"
        );
    }

    #[test]
    fn streak_must_reach_the_configured_length_before_firing() {
        let config = Config {
            windows_before_alert: 3,
            ..Config::default()
        };
        let client = [10, 0, 0, 9];
        let mut alerts = AlertState::default();
        assert!(alerts
            .close_window(&config, 0, client, &bad_stats())
            .is_none());
        assert!(alerts
            .close_window(&config, 1, client, &bad_stats())
            .is_none());
        assert!(alerts
            .close_window(&config, 2, client, &bad_stats())
            .is_some());
    }

    #[test]
    fn alert_window_start_uses_the_configured_window_length() {
        let config = Config {
            window_seconds: 30,
            windows_before_alert: 1,
            ..Config::default()
        };
        let mut alerts = AlertState::default();
        let alert = alerts
            .close_window(&config, 7, [192, 0, 2, 5], &bad_stats())
            .expect("fires on the first bad window");
        assert_eq!(alert.window_start, 210);
        assert_eq!(alert.client, "192.0.2.5");
    }

    #[test]
    fn a_recreated_window_is_never_scored_twice() {
        // Late packets can re-create a drained window (live pipe backlog);
        // the watermark must keep one window from counting twice.
        let config = Config {
            windows_before_alert: 1,
            ..Config::default()
        };
        let client = [10, 0, 0, 9];
        let mut alerts = AlertState::default();
        assert!(alerts
            .close_window(&config, 4, client, &bad_stats())
            .is_some());
        assert!(alerts
            .close_window(&config, 4, client, &bad_stats())
            .is_none());
        assert!(alerts
            .close_window(&config, 3, client, &bad_stats())
            .is_none());

        // A strictly newer window still scores: a clean window re-arms the
        // client, and the next bad window fires again.
        let clean = WindowStats::default();
        assert!(alerts.close_window(&config, 5, client, &clean).is_none());
        assert!(alerts
            .close_window(&config, 6, client, &bad_stats())
            .is_some());
    }
}

#[cfg(test)]
mod args_tests {
    use super::{parse_args, Command};

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_commands_with_flags_in_any_order() {
        let inv = parse_args(&args(&["analyze", "c.pcap", "-c", "cfg.json", "-v"])).unwrap();
        assert!(matches!(inv.command, Command::Analyze(_)));
        assert_eq!(
            inv.config_path.as_deref(),
            Some(std::path::Path::new("cfg.json"))
        );
        assert!(inv.verbose);

        let inv = parse_args(&args(&["watch"])).unwrap();
        assert!(matches!(inv.command, Command::Watch));
    }

    #[test]
    fn every_command_parses() {
        assert!(matches!(
            parse_args(&args(&["selftest"])).unwrap().command,
            Command::Selftest
        ));
        assert!(matches!(
            parse_args(&args(&["config"])).unwrap().command,
            Command::PrintConfig
        ));
        assert!(matches!(
            parse_args(&args(&["--version"])).unwrap().command,
            Command::PrintVersion
        ));
        assert!(matches!(
            parse_args(&args(&["-h"])).unwrap().command,
            Command::Help
        ));
    }

    #[test]
    fn missing_config_value_is_an_error() {
        let e = parse_args(&args(&["watch", "-c"])).unwrap_err();
        assert!(e.contains("-c"), "message: {e}");
    }

    #[test]
    fn analyze_requires_a_file() {
        assert!(parse_args(&args(&["analyze"])).is_err());
    }

    #[test]
    fn unknown_tokens_are_errors() {
        assert!(parse_args(&args(&["frobnicate"])).is_err());
        assert!(parse_args(&args(&["watch", "--bogus"])).is_err());
        assert!(parse_args(&[]).is_err());
    }

    #[test]
    fn duplicate_config_flags_are_errors() {
        assert!(parse_args(&args(&["watch", "-c", "a.json", "-c", "b.json"])).is_err());
    }
}
