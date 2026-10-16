//! Configuration: a flat JSON file, parsed by hand (no serde — the same
//! zero-dependency policy as the rest of the codebase). Unknown keys are
//! ignored so configs stay forward-compatible.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Config {
    pub window_seconds: u64,
    pub score_threshold: f64,
    pub windows_before_alert: u64,
    pub trusted_clients: Vec<String>,
    pub webhook_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            window_seconds: 60,
            score_threshold: 0.6,
            windows_before_alert: 3,
            trusted_clients: vec![],
            webhook_url: String::new(),
        }
    }
}

impl Config {
    pub fn default_json() -> String {
        "{\n  \"window_seconds\": 60,\n  \"score_threshold\": 0.6,\n  \
\"windows_before_alert\": 3,\n  \"trusted_clients\": [],\n  \"webhook_url\": \"\"\n}"
            .to_string()
    }

    pub fn load(path: &Path) -> io::Result<Config> {
        let text = fs::read_to_string(path)?;
        Self::from_json(&text)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("bad config {path:?}")))
    }

    pub fn from_json(text: &str) -> Option<Config> {
        let map = parse_object(text)?;
        let mut cfg = Config::default();
        if let Some(v) = map.get("window_seconds") {
            cfg.window_seconds = v.parse().ok()?;
        }
        if let Some(v) = map.get("score_threshold") {
            cfg.score_threshold = v.parse().ok()?;
        }
        if let Some(v) = map.get("windows_before_alert") {
            cfg.windows_before_alert = v.parse().ok()?;
        }
        if let Some(v) = map.get("webhook_url") {
            cfg.webhook_url = v.to_string();
        }
        if let Some(v) = map.get("trusted_clients") {
            cfg.trusted_clients = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
        }
        Some(cfg)
    }

    pub fn is_trusted(&self, client: [u8; 4]) -> bool {
        let s = client.map(|b| b.to_string()).join(".");
        self.trusted_clients.contains(&s)
    }
}

/// Parse a flat JSON object into key/value strings. String arrays become
/// comma-joined values. Nested objects are not supported and fail the
/// parse — the config stays flat on purpose.
fn parse_object(text: &str) -> Option<HashMap<String, String>> {
    let mut map = HashMap::new();
    let t = text.trim();
    let t = t.strip_prefix('{')?.strip_suffix('}')?.trim();
    if t.is_empty() {
        return Some(map);
    }
    let mut rest = t;
    while !rest.is_empty() {
        let (key, after) = parse_string(rest)?;
        let after = after.trim_start();
        let after = after.strip_prefix(':')?.trim_start();
        let (value, after) = parse_value(after)?;
        map.insert(key, value);
        let after = after.trim_start();
        if after.is_empty() {
            break;
        }
        rest = after.strip_prefix(',')?.trim_start();
    }
    Some(map)
}

fn parse_string(s: &str) -> Option<(String, &str)> {
    let s = s.strip_prefix('"')?;
    let end = s.find('"')?;
    Some((s[..end].to_string(), &s[end + 1..]))
}

fn parse_value(s: &str) -> Option<(String, &str)> {
    if s.starts_with('"') {
        return parse_string(s);
    }
    if s.starts_with('[') {
        let end = s.find(']')?;
        let inner = &s[1..end];
        let joined = inner
            .split(',')
            .filter_map(|part| {
                let part = part.trim();
                part.strip_prefix('"')?.strip_suffix('"').map(str::to_string)
            })
            .collect::<Vec<_>>()
            .join(",");
        return Some((joined, &s[end + 1..]));
    }
    let end = s.find([',', '}']).unwrap_or(s.len());
    Some((s[..end].trim().to_string(), &s[end..]))
}

