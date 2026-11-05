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
        if cfg.window_seconds == 0
            || cfg.windows_before_alert == 0
            || !cfg.score_threshold.is_finite()
            || !(0.0 < cfg.score_threshold && cfg.score_threshold <= 1.0)
            || cfg.trusted_clients.iter().any(|ip| ip.parse::<std::net::Ipv4Addr>().is_err())
            || (!cfg.webhook_url.is_empty() && !cfg.webhook_url.starts_with("https://"))
        {
            return None;
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
        if map.contains_key(&key) {
            return None;
        }
        map.insert(key, value);
        let after = after.trim_start();
        if after.is_empty() {
            break;
        }
        rest = after.strip_prefix(',')?.trim_start();
        // A comma must always be followed by another key/value pair.
        if rest.is_empty() {
            return None;
        }
    }
    Some(map)
}

fn parse_string(s: &str) -> Option<(String, &str)> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }

    let mut out = String::new();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Some((out, &s[index + 1..])),
            b'\\' => {
                let escaped = *bytes.get(index + 1)?;
                let (decoded, consumed) = match escaped {
                    b'"' => ('"', 2),
                    b'\\' => ('\\', 2),
                    b'/' => ('/', 2),
                    b'b' => ('\u{0008}', 2),
                    b'f' => ('\u{000c}', 2),
                    b'n' => ('\n', 2),
                    b'r' => ('\r', 2),
                    b't' => ('\t', 2),
                    b'u' => {
                        let first = parse_hex4(bytes, index + 2)?;
                        if (0xd800..=0xdbff).contains(&first) {
                            if bytes.get(index + 6..index + 8)? != b"\\u" {
                                return None;
                            }
                            let second = parse_hex4(bytes, index + 8)?;
                            if !(0xdc00..=0xdfff).contains(&second) {
                                return None;
                            }
                            let scalar = 0x10000
                                + (((u32::from(first) - 0xd800) << 10)
                                    | (u32::from(second) - 0xdc00));
                            (char::from_u32(scalar)?, 12)
                        } else {
                            if (0xdc00..=0xdfff).contains(&first) {
                                return None;
                            }
                            (char::from_u32(u32::from(first))?, 6)
                        }
                    }
                    _ => return None,
                };
                out.push(decoded);
                index += consumed;
            }
            byte if byte < 0x20 => return None,
            _ => {
                let character = s[index..].chars().next()?;
                out.push(character);
                index += character.len_utf8();
            }
        }
    }
    None
}

fn parse_hex4(bytes: &[u8], start: usize) -> Option<u16> {
    let digits = bytes.get(start..start.checked_add(4)?)?;
    let mut value = 0u16;
    for digit in digits {
        let nibble = (*digit as char).to_digit(16)? as u16;
        value = value.checked_mul(16)?.checked_add(nibble)?;
    }
    Some(value)
}

fn parse_value(s: &str) -> Option<(String, &str)> {
    if s.starts_with('"') {
        return parse_string(s);
    }
    if s.starts_with('[') {
        let mut rest = s.strip_prefix('[')?.trim_start();
        let mut items = Vec::new();
        if let Some(after) = rest.strip_prefix(']') {
            return Some((String::new(), after));
        }
        loop {
            let (item, after) = parse_string(rest)?;
            // This compact config schema stores trusted client IPs as a comma-
            // joined value, so commas inside an array member are not supported.
            if item.is_empty() || item.contains(',') {
                return None;
            }
            items.push(item);
            rest = after.trim_start();
            if let Some(after_array) = rest.strip_prefix(']') {
                return Some((items.join(","), after_array));
            }
            rest = rest.strip_prefix(',')?.trim_start();
            if rest.starts_with(']') {
                return None;
            }
        }
    }
    let end = s.find([',', '}']).unwrap_or(s.len());
    Some((s[..end].trim().to_string(), &s[end..]))
}



#[cfg(test)]
mod validation_tests {
    use super::Config;

    #[test]
    fn rejects_invalid_detector_settings() {
        for text in [
            r#"{"window_seconds": 0}"#,
            r#"{"windows_before_alert": 0}"#,
            r#"{"score_threshold": -0.1}"#,
            r#"{"score_threshold": 1.1}"#,
            r#"{"score_threshold": NaN}"#,
            r#"{"webhook_url": "http://example.invalid/hook"}"#,
            r#"{"trusted_clients": ["not-an-ip"]}"#,
        ] {
            assert!(Config::from_json(text).is_none(), "accepted invalid config: {text}");
        }
    }

    #[test]
    fn rejects_duplicate_keys_instead_of_silently_overwriting() {
        assert!(Config::from_json(
            r#"{"window_seconds": 30, "window_seconds": 120}"#
        ).is_none());
        assert!(Config::from_json(
            r#"{"unknown": 1, "unknown": 2}"#
        ).is_none());
    }

    #[test]
    fn rejects_trailing_commas_in_config_objects() {
        assert!(Config::from_json(r#"{ "window_seconds": 30, }"#).is_none());
        assert!(Config::from_json(r#"{ "window_seconds": 30,   }"#).is_none());
    }

    #[test]
    fn rejects_non_string_and_trailing_array_members() {
        for text in [
            r#"{ "trusted_clients": ["192.168.1.1", 42] }"#,
            r#"{ "trusted_clients": ["192.168.1.1",] }"#,
            r#"{ "trusted_clients": [192.168.1.1] }"#,
            r#"{ "trusted_clients": [""] }"#,
        ] {
            assert!(Config::from_json(text).is_none(), "accepted malformed array: {text}");
        }
    }

    #[test]
    fn accepts_valid_custom_settings() {
        let cfg = Config::from_json(
            r#"{"window_seconds": 30, "score_threshold": 0.75, "windows_before_alert": 2, "trusted_clients": ["192.168.1.1"], "webhook_url": "https://example.invalid/hook"}"#,
        )
        .expect("valid config should parse");
        assert_eq!(cfg.window_seconds, 30);
        assert_eq!(cfg.score_threshold, 0.75);
        assert_eq!(cfg.windows_before_alert, 2);
        assert!(cfg.is_trusted([192, 168, 1, 1]));
    }

    #[test]
    fn decodes_json_string_escapes_and_unicode() {
        let (decoded, rest) = super::parse_string(
            r#""path\/with\\slash and \"quotes\" \u2764 \uD83D\uDE80""#
        ).unwrap();
        assert_eq!(decoded, "path/with\\slash and \"quotes\" ❤ 🚀");
        assert_eq!(rest, "");
    }

    #[test]
    fn rejects_invalid_escapes_and_unescaped_control_characters() {
        for value in [
            "\"bad\\xescape\"",
            "\"unfinished\\",
            "\"raw\nnewline\"",
            "\"lone high surrogate \\uD800\"",
            "\"lone low surrogate \\uDC00\"",
            "\"invalid pair \\uD800\\u0041\"",
        ] {
            assert!(super::parse_string(value).is_none(), "accepted {value:?}");
        }
    }

    #[test]
    fn parses_escaped_webhook_string_from_config() {
        let cfg = Config::from_json(
            r#"{ "webhook_url": "https:\/\/example.invalid\/hook" }"#
        ).expect("escaped slashes are valid JSON strings");
        assert_eq!(cfg.webhook_url, "https://example.invalid/hook");
    }

    #[test]
    fn trusted_client_array_parser_rejects_trailing_members() {
        for value in [
            r#"{ "trusted_clients": ["192.0.2.1",] }"#,
            r#"{ "trusted_clients": ["192.0.2.1", 42] }"#,
        ] {
            assert!(Config::from_json(value).is_none());
        }
    }

}
