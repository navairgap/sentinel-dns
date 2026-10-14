//! Scoring: per-domain heuristics plus per-client rolling windows.
//!
//! A single weird domain proves nothing — clients misbehave, CDNs are odd.
//! The unit of suspicion is a (client, window): many bad signals from one
//! host inside one minute is what an alert is made of.

use std::collections::HashMap;

use crate::dns::Query;

/// One client inside one scoring window.
#[derive(Debug, Default)]
pub struct WindowStats {
    pub queries: u64,
    pub nxdomains: u64,
    pub suspicious: u64,
    pub reasons: Vec<String>,
}

/// Shannon entropy over the domain's bytes, bits per byte.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Per-domain suspicion score in 0.0..=1.0, plus the reasons that fired.
pub fn domain_score(name: &str) -> (f64, Vec<String>) {
    let mut score = 0.0f64;
    let mut reasons: Vec<String> = Vec::new();
    let lower = name.to_lowercase();
    let core = lower.split('.').next().unwrap_or("");

    let ent = entropy(core);
    if ent > 3.5 && core.len() >= 8 {
        score += 0.45;
        reasons.push("high_entropy".to_string());
    }
    let digits = core.chars().filter(|c| c.is_ascii_digit()).count();
    if core.len() >= 6 && digits as f64 / core.len() as f64 > 0.3 {
        score += 0.25;
        reasons.push("digit_heavy".to_string());
    }
    let unique = core.chars().collect::<std::collections::BTreeSet<_>>().len();
    if core.len() >= 10 && unique >= core.len() - 2 {
        score += 0.2;
        reasons.push("dga_shape".to_string());
    }
    if !core.chars().any(|c| "aeiou".contains(c)) && core.len() >= 6 {
        score += 0.1;
        reasons.push("no_vowels".to_string());
    }
    for tld in [".xyz", ".top", ".buzz", ".icu", ".cam"] {
        if lower.ends_with(tld) {
            score += 0.1;
            reasons.push("cheap_tld".to_string());
            break;
        }
    }
    if core.len() > 40 {
        score += 0.1;
        reasons.push("oversize_label".to_string());
    }
    (score.min(1.0), reasons)
}

/// Map a client's accumulated window into a final alert score + reasons.
pub fn window_score(w: &WindowStats) -> (f64, Vec<String>) {
    let mut score = 0.0f64;
    let mut reasons: Vec<String> = Vec::new();
    if w.queries == 0 {
        return (0.0, reasons);
    }
    if w.queries >= 20 && w.suspicious * 3 >= w.queries {
        score += 0.5;
        reasons.push("sustained_dga".to_string());
    }
    let nx = w.nxdomains as f64 / w.queries as f64;
    if w.queries >= 10 && nx > 0.5 {
        score += 0.3;
        reasons.push("nxdomain_burst".to_string());
        if nx > 0.8 {
            score += 0.1;
            reasons.push("nxdomain_flood".to_string());
        }
    }
    let mut all = w.reasons.clone();
    all.sort();
    all.dedup();
    if !all.is_empty() {
        score += 0.1;
        reasons.push("flag_domains".to_string());
    }
    (score.min(1.0), reasons)
}

/// Rolling per-client windows. `tick` is seconds; `window_seconds` groups
/// packets into buckets keyed by ts_sec / window.
pub struct Tracker {
    pub window_seconds: u64,
    pub windows: HashMap<u64, HashMap<[u8; 4], WindowStats>>,
}

impl Tracker {
    pub fn new(window_seconds: u64) -> Self {
        Tracker { window_seconds: window_seconds.max(1), windows: HashMap::new() }
    }

    pub fn observe_at(&mut self, q: &Query, ts: u64) {
        let key = ts / self.window_seconds;
        let client = self.windows.entry(key).or_default().entry(q.client).or_default();
        client.queries += 1;
        if q.is_nxdomain() {
            client.nxdomains += 1;
        }
        let (s, reasons) = domain_score(&q.name);
        if s >= 0.5 {
            client.suspicious += 1;
            client.reasons.extend(reasons);
        }
    }

    /// Pop all windows strictly older than `before` and return them.
    pub fn drain_older_than(&mut self, before: u64) -> Vec<(u64, [u8; 4], WindowStats)> {
        let keys: Vec<u64> = self.windows.keys().copied().filter(|k| *k < before).collect();
        let mut out = Vec::new();
        for k in keys {
            if let Some(clients) = self.windows.remove(&k) {
                for (client, stats) in clients {
                    out.push((k, client, stats));
                }
            }
        }
        out
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn q(client: [u8; 4], name: &str, nx: bool) -> Query {
        Query {
            name: name.to_string(), qtype: 1, client, server: [1, 1, 1, 1],
            is_response: nx, rcode: if nx { 3 } else { 0 },
        }
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy("aaaa"), 0.0);
        let h = entropy("x9q2z7w1");
        assert!(h > 2.9 && h <= 3.1);
    }

    #[test]
    fn random_dga_scores_high() {
        let (s, reasons) = domain_score("xq7z9w2k1v4b8.example.xyz");
        assert!(s >= 0.5, "score {s} reasons {reasons:?}");
        assert!(reasons.contains(&"high_entropy".to_string()));
    }

    #[test]
    fn normal_domain_scores_zero() {
        let (s, reasons) = domain_score("mail.google.com");
        assert_eq!(s, 0.0, "reasons {reasons:?}");
    }

    #[test]
    fn window_fires_on_dga_burst() {
        let mut t = Tracker::new(60);
        for i in 0..25 {
            let name = format!("xq7z9w2k1v4b8-{i}.example.xyz");
            t.observe_at(&q([10, 0, 0, 7], &name, true), 1_700_000_000);
        }
        let drained = t.drain_older_than(1_700_000_001);
        assert_eq!(drained.len(), 1);
        let (_, client, stats) = &drained[0];
        assert_eq!(client, &[10, 0, 0, 7]);
        let (s, reasons) = window_score(stats);
        assert!(s >= 0.5, "score {s} reasons {reasons:?}");
        assert!(reasons.contains(&"sustained_dga".to_string()));
        assert!(reasons.contains(&"nxdomain_burst".to_string()));
    }

    #[test]
    fn clean_client_stays_quiet() {
        let mut t = Tracker::new(60);
        for _ in 0..30 {
            t.observe_at(&q([10, 0, 0, 8], "api.github.com", false), 1_700_000_000);
        }
        let drained = t.drain_older_than(1_700_000_001);
        let (s, _) = window_score(&drained[0].2);
        assert_eq!(s, 0.0);
    }
}
