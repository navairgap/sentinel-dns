//! Configuration: a flat JSON file, parsed by hand (no serde — the same
//! zero-dependency policy as the rest of the codebase). Unknown keys are
//! ignored so configs stay forward-compatible. Every invalid value fails
//! the load with a message naming the offending key.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

/// One `trusted_clients` entry: an exact address or a CIDR subnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedRule {
    Exact(Ipv4Addr),
    Cidr { network: u32, mask: u32 },
}

impl TrustedRule {
    /// Parse `a.b.c.d` or `a.b.c.d/prefix`. The network address is
    /// normalized, so `10.1.2.3/8` is accepted and treated as `10.0.0.0/8`.
    pub fn parse(text: &str) -> Result<TrustedRule, String> {
        let bad_addr = |s: &str| format!("invalid IPv4 address {s:?}");
        match text.split_once('/') {
            None => {
                let ip: Ipv4Addr = text.parse().map_err(|_| bad_addr(text))?;
                Ok(TrustedRule::Exact(ip))
            }
            Some((addr, prefix)) => {
                let ip: Ipv4Addr = addr.trim().parse().map_err(|_| bad_addr(text))?;
                let prefix: u8 = prefix
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid prefix length in {text:?}"))?;
                if prefix > 32 {
                    return Err(format!(
                        "prefix length {prefix} in {text:?} is out of range (0-32)"
                    ));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix as u32)
                };
                Ok(TrustedRule::Cidr {
                    network: u32::from(ip) & mask,
                    mask,
                })
            }
        }
    }

    pub fn matches(&self, client: u32) -> bool {
        match self {
            TrustedRule::Exact(ip) => u32::from(*ip) == client,
            TrustedRule::Cidr { network, mask } => *network == client & mask,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub window_seconds: u64,
    pub score_threshold: f64,
    pub windows_before_alert: u64,
    pub trusted_rules: Vec<TrustedRule>,
    pub webhook_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            window_seconds: 60,
            score_threshold: 0.6,
            windows_before_alert: 3,
            trusted_rules: vec![],
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
        Self::from_json(&text).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })
    }

    pub fn from_json(text: &str) -> Result<Config, String> {
        // Tolerate a UTF-8 BOM; everything else must be a flat JSON object.
        let map = parse_object(text.trim_start_matches('\u{feff}'))?;
        let mut cfg = Config::default();

        if let Some(v) = map.get("window_seconds") {
            cfg.window_seconds = number_from("window_seconds", v)?;
        }
        if let Some(v) = map.get("score_threshold") {
            cfg.score_threshold = number_from("score_threshold", v)?;
        }
        if let Some(v) = map.get("windows_before_alert") {
            cfg.windows_before_alert = number_from("windows_before_alert", v)?;
        }
        if let Some(v) = map.get("trusted_clients") {
            let entries = string_array_from("trusted_clients", v)?;
            cfg.trusted_rules = entries
                .iter()
                .map(|entry| TrustedRule::parse(entry))
                .collect::<Result<Vec<_>, _>>()?;
        }
        if let Some(v) = map.get("webhook_url") {
            match v {
                JsonValue::Str(s) => cfg.webhook_url = s.clone(),
                other => {
                    return Err(format!(
                        "webhook_url: expected a quoted string, got {other:?}"
                    ))
                }
            }
        }

        if cfg.window_seconds == 0 {
            return Err("window_seconds must be at least 1".to_string());
        }
        if cfg.windows_before_alert == 0 {
            return Err("windows_before_alert must be at least 1".to_string());
        }
        if !cfg.score_threshold.is_finite()
            || !(0.0 < cfg.score_threshold && cfg.score_threshold <= 1.0)
        {
            return Err(
                "score_threshold must be a number greater than 0 and at most 1".to_string(),
            );
        }
        if !cfg.webhook_url.is_empty() && !cfg.webhook_url.starts_with("https://") {
            return Err(
                "webhook_url must use https:// (plain HTTP would leak alert data)".to_string(),
            );
        }
        Ok(cfg)
    }

    pub fn is_trusted(&self, client: [u8; 4]) -> bool {
        let addr = u32::from_be_bytes(client);
        self.trusted_rules.iter().any(|rule| rule.matches(addr))
    }
}

/// A parsed JSON value, just detailed enough to validate the known keys
/// strictly while tolerating anything an unknown key carries.
#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    /// A quoted string, escapes decoded.
    Str(String),
    /// A bare token: number, true, false, null — kept as written.
    Bare(String),
    /// An array of values (mixed kinds allowed; consumers decide).
    Array(Vec<JsonValue>),
    /// A nested object, parsed over and skipped: the config stays flat.
    Object,
}

impl JsonValue {
    /// The text of a quoted string or bare token, for numeric keys.
    fn as_token(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) | JsonValue::Bare(s) => Some(s),
            _ => None,
        }
    }
}

fn number_from<T: std::str::FromStr>(key: &str, value: &JsonValue) -> Result<T, String> {
    let text = value
        .as_token()
        .ok_or_else(|| format!("{key}: expected a number, got {value:?}"))?;
    text.trim()
        .parse::<T>()
        .map_err(|_| format!("{key}: {text:?} is not a valid number"))
}

fn string_array_from(key: &str, value: &JsonValue) -> Result<Vec<String>, String> {
    let items = match value {
        JsonValue::Array(items) => items,
        other => {
            return Err(format!(
                "{key}: expected an array of strings, got {other:?}"
            ))
        }
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            JsonValue::Str(s) if !s.is_empty() && !s.contains(',') => out.push(s.clone()),
            other => {
                return Err(format!(
                    "{key}: entries must be non-empty quoted strings, got {other:?}"
                ))
            }
        }
    }
    Ok(out)
}

/// Parse a flat JSON object. Values are parsed generically: known keys get
/// validated in `Config::from_json`, unknown keys are carried as-is so the
/// format stays forward-compatible (a future config may use arrays or
/// nested objects for keys this version has never heard of).
fn parse_object(text: &str) -> Result<HashMap<String, JsonValue>, String> {
    let t = text.trim();
    let t = t
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| "config must be a JSON object with flat key/value pairs".to_string())?
        .trim();
    let mut map = HashMap::new();
    if t.is_empty() {
        return Ok(map);
    }
    let mut rest = t;
    while !rest.is_empty() {
        let (key, after) = parse_string(rest)?;
        let after = after.trim_start();
        let after = after
            .strip_prefix(':')
            .ok_or_else(|| format!("missing ':' after key {key:?}"))?
            .trim_start();
        let (value, after) = parse_value(after)?;
        if map.contains_key(&key) {
            return Err(format!("duplicate key {key:?}"));
        }
        map.insert(key, value);
        let after = after.trim_start();
        if after.is_empty() {
            break;
        }
        rest = after
            .strip_prefix(',')
            .ok_or_else(|| "expected ',' between key/value pairs".to_string())?
            .trim_start();
        // A comma must always be followed by another key/value pair.
        if rest.is_empty() {
            return Err("trailing comma before end of object".to_string());
        }
    }
    Ok(map)
}

fn parse_string(s: &str) -> Result<(String, &str), String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err(format!("expected a quoted string, found {s:?}"));
    }

    let mut out = String::new();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Ok((out, &s[index + 1..])),
            b'\\' => {
                let escaped = *bytes
                    .get(index + 1)
                    .ok_or_else(|| "string ends with a lone backslash".to_string())?;
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
                            if bytes.get(index + 6..index + 8) != Some(b"\\u".as_slice()) {
                                return Err("unpaired surrogate in \\u escape".to_string());
                            }
                            let second = parse_hex4(bytes, index + 8)?;
                            if !(0xdc00..=0xdfff).contains(&second) {
                                return Err("unpaired surrogate in \\u escape".to_string());
                            }
                            let scalar = 0x10000
                                + (((u32::from(first) - 0xd800) << 10)
                                    | (u32::from(second) - 0xdc00));
                            (
                                char::from_u32(scalar)
                                    .ok_or_else(|| "invalid surrogate pair".to_string())?,
                                12,
                            )
                        } else {
                            if (0xdc00..=0xdfff).contains(&first) {
                                return Err("unpaired low surrogate in \\u escape".to_string());
                            }
                            (
                                char::from_u32(u32::from(first))
                                    .ok_or_else(|| "invalid \\u escape".to_string())?,
                                6,
                            )
                        }
                    }
                    _ => return Err(format!("invalid escape sequence \\{}", escaped as char)),
                };
                out.push(decoded);
                index += consumed;
            }
            byte if byte < 0x20 => return Err("control character inside a string".to_string()),
            _ => {
                let character = s[index..]
                    .chars()
                    .next()
                    .ok_or_else(|| "invalid UTF-8".to_string())?;
                out.push(character);
                index += character.len_utf8();
            }
        }
    }
    Err("string is not terminated".to_string())
}

fn parse_hex4(bytes: &[u8], start: usize) -> Result<u16, String> {
    let digits = bytes
        .get(
            start
                ..start
                    .checked_add(4)
                    .ok_or_else(|| "truncated \\u escape".to_string())?,
        )
        .ok_or_else(|| "truncated \\u escape".to_string())?;
    let mut value = 0u16;
    for digit in digits {
        let nibble = (*digit as char)
            .to_digit(16)
            .ok_or_else(|| "non-hex digit in \\u escape".to_string())? as u16;
        value = value * 16 + nibble;
    }
    Ok(value)
}

fn parse_value(s: &str) -> Result<(JsonValue, &str), String> {
    let s = s.trim_start();
    if s.starts_with('"') {
        let (value, rest) = parse_string(s)?;
        return Ok((JsonValue::Str(value), rest));
    }
    if s.starts_with('[') {
        let mut rest = s.strip_prefix('[').expect("checked above").trim_start();
        let mut items = Vec::new();
        if let Some(after) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), after));
        }
        loop {
            let (item, after) = parse_value(rest)?;
            items.push(item);
            rest = after.trim_start();
            if let Some(after_array) = rest.strip_prefix(']') {
                return Ok((JsonValue::Array(items), after_array));
            }
            rest = rest
                .strip_prefix(',')
                .ok_or_else(|| "expected ',' between array members".to_string())?
                .trim_start();
            if rest.starts_with(']') {
                return Err("trailing comma in array".to_string());
            }
        }
    }
    if s.starts_with('{') {
        let rest = skip_object(s)?;
        return Ok((JsonValue::Object, rest));
    }
    let end = s.find([',', '}', ']']).unwrap_or(s.len());
    let token = s[..end].trim();
    if token.is_empty() {
        return Err(format!("expected a value, found {s:?}"));
    }
    Ok((JsonValue::Bare(token.to_string()), &s[end..]))
}

/// Consume a nested JSON object, tracking string context so braces inside
/// strings do not count. Used only to skip values this config has no use
/// for.
fn skip_object(s: &str) -> Result<&str, String> {
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&s[i + 1..]);
                }
            }
            _ => {}
        }
    }
    Err("object is not terminated".to_string())
}

#[cfg(test)]
mod trusted_rule_tests {
    use super::TrustedRule;

    fn matches(rule: &str, client: [u8; 4]) -> bool {
        TrustedRule::parse(rule)
            .unwrap()
            .matches(u32::from_be_bytes(client))
    }

    #[test]
    fn exact_addresses_match_only_themselves() {
        assert!(matches("10.0.0.7", [10, 0, 0, 7]));
        assert!(!matches("10.0.0.7", [10, 0, 0, 8]));
    }

    #[test]
    fn cidr_subnets_match_member_addresses() {
        assert!(matches("10.0.0.0/8", [10, 200, 3, 4]));
        assert!(!matches("10.0.0.0/8", [11, 0, 0, 1]));
        assert!(matches("192.168.4.0/24", [192, 168, 4, 99]));
        assert!(!matches("192.168.4.0/24", [192, 168, 5, 99]));
        assert!(matches("1.2.3.4/32", [1, 2, 3, 4]));
        assert!(!matches("1.2.3.4/32", [1, 2, 3, 5]));
        assert!(matches("0.0.0.0/0", [203, 0, 113, 9]));
    }

    #[test]
    fn cidr_networks_are_normalized() {
        // Host bits set in the configured network are masked off.
        assert!(matches("10.9.9.9/8", [10, 1, 2, 3]));
    }

    #[test]
    fn rejects_malformed_entries() {
        for text in [
            "not-an-ip",
            "10.0.0.0/33",
            "10.0.0.0/x",
            "10.0.0.0/",
            "10.0.0/8",
            "10.0.0.999",
            "",
        ] {
            assert!(TrustedRule::parse(text).is_err(), "accepted {text:?}");
        }
    }
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
            assert!(
                Config::from_json(text).is_err(),
                "accepted invalid config: {text}"
            );
        }
    }

    #[test]
    fn error_messages_name_the_offending_key() {
        let e = Config::from_json(r#"{"window_seconds": 0}"#).unwrap_err();
        assert!(e.contains("window_seconds"), "message: {e}");
        let e = Config::from_json(r#"{"webhook_url": "http://x/"}"#).unwrap_err();
        assert!(e.contains("https://"), "message: {e}");
        let e = Config::from_json(r#"{"trusted_clients": ["nope"]}"#).unwrap_err();
        assert!(e.contains("nope"), "message: {e}");
    }

    #[test]
    fn rejects_duplicate_keys_instead_of_silently_overwriting() {
        assert!(Config::from_json(r#"{"window_seconds": 30, "window_seconds": 120}"#).is_err());
        assert!(Config::from_json(r#"{"unknown": 1, "unknown": 2}"#).is_err());
    }

    #[test]
    fn rejects_trailing_commas_in_config_objects() {
        assert!(Config::from_json(r#"{ "window_seconds": 30, }"#).is_err());
        assert!(Config::from_json(r#"{ "window_seconds": 30,   }"#).is_err());
    }

    #[test]
    fn rejects_non_string_and_trailing_array_members() {
        for text in [
            r#"{ "trusted_clients": ["192.168.1.1", 42] }"#,
            r#"{ "trusted_clients": ["192.168.1.1",] }"#,
            r#"{ "trusted_clients": [192.168.1.1] }"#,
            r#"{ "trusted_clients": [""] }"#,
        ] {
            assert!(
                Config::from_json(text).is_err(),
                "accepted malformed array: {text}"
            );
        }
    }

    #[test]
    fn accepts_valid_custom_settings() {
        let cfg = Config::from_json(
            r#"{"window_seconds": 30, "score_threshold": 0.75, "windows_before_alert": 2, "trusted_clients": ["192.168.1.1", "10.0.0.0/8"], "webhook_url": "https://example.invalid/hook"}"#,
        )
        .expect("valid config should parse");
        assert_eq!(cfg.window_seconds, 30);
        assert_eq!(cfg.score_threshold, 0.75);
        assert_eq!(cfg.windows_before_alert, 2);
        assert!(cfg.is_trusted([192, 168, 1, 1]));
        assert!(cfg.is_trusted([10, 42, 42, 42]));
        assert!(!cfg.is_trusted([192, 168, 1, 2]));
    }

    #[test]
    fn decodes_json_string_escapes_and_unicode() {
        let (decoded, rest) =
            super::parse_string(r#""path\/with\\slash and \"quotes\" \u2764 \uD83D\uDE80""#)
                .unwrap();
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
            assert!(super::parse_string(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn parses_escaped_webhook_string_from_config() {
        let cfg = Config::from_json(r#"{ "webhook_url": "https:\/\/example.invalid\/hook" }"#)
            .expect("escaped slashes are valid JSON strings");
        assert_eq!(cfg.webhook_url, "https://example.invalid/hook");
    }

    #[test]
    fn tolerates_a_utf8_bom() {
        let cfg = Config::from_json("\u{feff}{\"window_seconds\": 45}").expect("BOM is tolerated");
        assert_eq!(cfg.window_seconds, 45);
    }

    #[test]
    fn rejects_non_object_documents() {
        for text in ["[]", "\"just a string\"", "42"] {
            assert!(Config::from_json(text).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn unknown_keys_tolerate_any_value_shape() {
        // Forward compatibility: a future config may carry arrays, nested
        // objects, or exotic scalars under keys this version ignores.
        let cfg = Config::from_json(
            r#"{
                "future_array": [1, "two", {"nested": true}],
                "future_object": {"deep": {"deeper": [3]}},
                "future_null": null,
                "window_seconds": 45
            }"#,
        )
        .expect("unknown keys must not fail the parse");
        assert_eq!(cfg.window_seconds, 45);
    }

    #[test]
    fn known_keys_keep_their_strictness() {
        let e = Config::from_json(r#"{ "trusted_clients": ["10.0.0.1", 42] }"#).unwrap_err();
        assert!(e.contains("trusted_clients"), "message: {e}");
        let e = Config::from_json(r#"{ "trusted_clients": {"a": 1} }"#).unwrap_err();
        assert!(e.contains("trusted_clients"), "message: {e}");
        let e = Config::from_json(r#"{ "webhook_url": 123 }"#).unwrap_err();
        assert!(e.contains("webhook_url"), "message: {e}");
        let e = Config::from_json(r#"{ "window_seconds": {} }"#).unwrap_err();
        assert!(e.contains("window_seconds"), "message: {e}");
    }

    #[test]
    fn numeric_keys_accept_bare_and_quoted_values() {
        let cfg = Config::from_json(r#"{ "window_seconds": "45" }"#).expect("quoted number ok");
        assert_eq!(cfg.window_seconds, 45);
        let cfg = Config::from_json(r#"{ "score_threshold": 0.8 }"#).expect("bare number ok");
        assert_eq!(cfg.score_threshold, 0.8);
    }

    #[test]
    fn missing_values_are_errors() {
        assert!(Config::from_json(r#"{ "window_seconds": }"#).is_err());
        assert!(Config::from_json(r#"{ "future": [1, ] }"#).is_err());
        assert!(Config::from_json(r#"{ "future": {"x": 1 }"#).is_err());
    }
}
