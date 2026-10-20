//! Alerts: JSONL to stdout, optional append to a file, optional HTTPS webhook.
//! Webhooks require TLS so alert metadata is not sent in cleartext.

use std::fmt::Write as _;
use std::io;
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

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Alert {
    /// One JSON object per line — the whole contract.
    pub fn to_jsonl(&self) -> String {
        let mut s = String::new();
        s.push_str("{\"v\":1,\"client\":");
        s.push_str(&json_string(&self.client));
        let _ = write!(s, ",\"window\":{},\"score\":{:.2},\"reasons\":[", self.window_start, self.score);
        for (i, reason) in self.reasons.iter().enumerate() {
            if i > 0 { s.push(','); }
            s.push_str(&json_string(reason));
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

fn try_send(url: &str, body: &str) -> io::Result<()> {
    if !url.starts_with("https://") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "webhook URL must use https://",
        ));
    }

    // ureq verifies TLS certificates by default. Disable redirects so a
    // configured endpoint cannot forward alert contents to another host.
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .redirects(0)
        .build();
    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(body);

    match response {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(status, _)) => Err(io::Error::other(
            format!("webhook returned HTTP {status}"),
        )),
        Err(ureq::Error::Transport(error)) => Err(io::Error::other(
            format!("webhook transport failed: {error}"),
        )),
    }
}

#[cfg(test)]
mod jsonl_tests {
    use super::{json_string, Alert};

    #[test]
    fn json_string_escapes_quotes_backslashes_and_controls() {
        assert_eq!(json_string("a\"b\\c\n\t"), "\"a\\\"b\\\\c\\n\\t\"");
    }

    #[test]
    fn alert_jsonl_escapes_untrusted_fields() {
        let alert = Alert {
            client: "192.0.2.1\"bad".to_string(),
            window_start: 10,
            score: 0.75,
            reasons: vec!["query\nvolume".to_string()],
            queries: 12,
            nxdomains: 3,
        };
        let line = alert.to_jsonl();
        assert!(line.contains("192.0.2.1\\\"bad"));
        assert!(line.contains("query\\nvolume"));
        assert!(line.starts_with("{\"v\":1,"));
    }
}

#[cfg(test)]
mod webhook_tests {
    use super::try_send;

    #[test]
    fn rejects_plain_http_webhooks_before_network_access() {
        let error = try_send("http://127.0.0.1:9/hook", "{}").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
