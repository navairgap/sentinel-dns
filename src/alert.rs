//! Alerts: JSONL to stdout, optional append to a file, optional webhook.
//! The webhook is a deliberately small HTTP/1.1 POST over plain TCP —
//! TLS would need a dependency, and internal webhooks are usually http.

use std::fmt::Write as _;
use std::io;
use std::net::TcpStream;
use std::time::Duration;

/// A firing: one client crossed the threshold for a window.
#[derive(Debug, Clone)]
pub struct Alert {
    pub client: String,
    pub window_start: u64,
    pub score: f64,
    pub reasons: Vec<String>,
    pub queries: u64,
    pub nxdomains: u64,
}

impl Alert {
    /// One JSON object per line — the whole contract.
    pub fn to_jsonl(&self) -> String {
        let mut s = String::new();
        s.push_str("{\"v\":1,\"client\":\"");
        s.push_str(&self.client);
        let _ = write!(s, "\",\"window\":{},\"score\":{:.2}", self.window_start, self.score);
        s.push_str(",\"reasons\":[");
        for (i, r) in self.reasons.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, "\"{r}\"");
        }
        let _ = write!(s, "],\"queries\":{},\"nxdomains\":{}}}", self.queries, self.nxdomains);
        s
    }
}

/// Fire-and-forget webhook POST. Failures are written to stderr and never
/// stop the pipeline — alerting must not become the outage.
pub fn send_webhook(url: &str, body: &str) {
    if let Err(e) = try_send(url, body) {
        eprintln!("sentinel-dns: webhook failed: {e}");
    }
}

