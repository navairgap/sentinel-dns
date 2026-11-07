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
    let unique = core
        .chars()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
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
    // Compare against ceil(queries / 3) without multiplying a potentially
    // attacker-influenced counter, which could overflow u64 in debug builds.
    let suspicious_threshold = w.queries.div_ceil(3);
    if w.queries >= 20 && w.suspicious >= suspicious_threshold {
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
        Tracker {
            window_seconds: window_seconds.max(1),
            windows: HashMap::new(),
        }
    }

    /// Record one parsed DNS message. The two directions play different
    /// roles: the query side drives volume and name suspicion, while a
    /// response only contributes its rcode. Counting both directions as
    /// "queries" would halve the NXDOMAIN ratio and hide the classic
    /// every-lookup-fails exfiltration pattern.
    pub fn observe_at(&mut self, q: &Query, ts: u64) {
        let key = ts / self.window_seconds;
        let client = self
            .windows
            .entry(key)
            .or_default()
            .entry(q.client)
            .or_default();
        if q.is_response {
            if q.is_nxdomain() {
                client.nxdomains = client.nxdomains.saturating_add(1);
            }
            return;
        }
        client.queries = client.queries.saturating_add(1);
        let (s, reasons) = domain_score(&q.name);
        if s >= 0.5 {
            client.suspicious = client.suspicious.saturating_add(1);
            for reason in reasons {
                if !client.reasons.contains(&reason) {
                    client.reasons.push(reason);
                }
            }
        }
    }

    /// Pop all windows strictly older than `before` and return them,
    /// ordered by window. Callers score clients in ascending window order,
    /// which their alert state relies on.
    pub fn drain_older_than(&mut self, before: u64) -> Vec<(u64, [u8; 4], WindowStats)> {
        let mut keys: Vec<u64> = self
            .windows
            .keys()
            .copied()
            .filter(|k| *k < before)
            .collect();
        keys.sort_unstable();
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
            name: name.to_string(),
            qtype: 1,
            client,
            server: [1, 1, 1, 1],
            is_response: nx,
            rcode: if nx { 3 } else { 0 },
        }
    }

    #[test]
    fn tracker_never_uses_a_zero_second_window() {
        assert_eq!(Tracker::new(0).window_seconds, 1);
        assert_eq!(Tracker::new(15).window_seconds, 15);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy("aaaa"), 0.0);
        let h = entropy("x9q2z7w1");
        assert!(h > 2.9 && h <= 3.1);
    }

    #[test]
    fn domain_score_is_capped_at_one() {
        let core = "bcdfghjklmnpqrstvwxyz0123456789";
        let (score, _) = domain_score(&format!("{core}.xyz"));
        assert_eq!(score, 1.0);
    }

    #[test]
    fn random_dga_scores_high() {
        let (s, reasons) = domain_score("xq7z9w2k1v4b8.example.xyz");
        assert!(s >= 0.5, "score {s} reasons {reasons:?}");
        assert!(reasons.contains(&"high_entropy".to_string()));
    }

    #[test]
    fn empty_domain_scores_zero() {
        let (score, reasons) = domain_score("");
        assert_eq!(score, 0.0);
        assert!(reasons.is_empty());
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
            // A real exchange: the query drives volume and suspicion, the
            // NXDOMAIN response records the failure.
            t.observe_at(&q([10, 0, 0, 7], &name, false), 1_700_000_000);
            t.observe_at(&q([10, 0, 0, 7], &name, true), 1_700_000_000);
        }
        let drained = t.drain_older_than(1_700_000_001);
        assert_eq!(drained.len(), 1);
        let (_, client, stats) = &drained[0];
        assert_eq!(client, &[10, 0, 0, 7]);
        assert_eq!(stats.queries, 25);
        assert_eq!(stats.nxdomains, 25);
        let (s, reasons) = window_score(stats);
        assert!(s >= 0.5, "score {s} reasons {reasons:?}");
        assert!(reasons.contains(&"sustained_dga".to_string()));
        assert!(reasons.contains(&"nxdomain_burst".to_string()));
    }

    #[test]
    fn responses_do_not_inflate_query_volume() {
        let mut t = Tracker::new(60);
        let name = "example.com";
        t.observe_at(&q([10, 0, 0, 7], name, false), 1_700_000_000);
        t.observe_at(&q([10, 0, 0, 7], name, true), 1_700_000_000);
        t.observe_at(&q([10, 0, 0, 7], name, true), 1_700_000_000);
        let drained = t.drain_older_than(1_700_000_001);
        let stats = &drained[0].2;
        assert_eq!(stats.queries, 1);
        assert_eq!(stats.nxdomains, 2);
    }

    #[test]
    fn a_client_whose_lookups_all_fail_crosses_the_nxdomain_threshold() {
        // Regression: when responses counted as queries, this pattern sat
        // at exactly 0.5 and never fired nxdomain_burst.
        let mut t = Tracker::new(60);
        for i in 0..30 {
            let name = format!("payment-{i}.example.com");
            t.observe_at(&q([10, 0, 0, 7], &name, false), 1_700_000_000);
            t.observe_at(&q([10, 0, 0, 7], &name, true), 1_700_000_000);
        }
        let drained = t.drain_older_than(1_700_000_001);
        let (s, reasons) = window_score(&drained[0].2);
        assert!(
            reasons.contains(&"nxdomain_burst".to_string()),
            "score {s} reasons {reasons:?}"
        );
    }

    #[test]
    fn response_only_traffic_scores_zero() {
        // A capture that only sees the resolver side records no queries;
        // scoring is query-driven, so this stays quiet instead of guessing.
        let mut t = Tracker::new(60);
        for _ in 0..50 {
            t.observe_at(
                &q([10, 0, 0, 7], "xq7z9w2k1v4b8.example.xyz", true),
                1_700_000_000,
            );
        }
        let drained = t.drain_older_than(1_700_000_001);
        let (s, _) = window_score(&drained[0].2);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn sustained_dga_threshold_does_not_overflow_large_counters() {
        let stats = WindowStats {
            queries: u64::MAX,
            suspicious: u64::MAX / 3 + 1,
            ..WindowStats::default()
        };
        let (score, reasons) = window_score(&stats);
        assert!(score >= 0.5);
        assert!(reasons.contains(&"sustained_dga".to_string()));
    }

    #[test]
    fn tracker_saturates_counters_and_deduplicates_reasons() {
        let client = [10, 0, 0, 9];
        let timestamp = 1_700_000_000;
        let key = timestamp / 60;
        let mut tracker = Tracker::new(60);
        {
            let stats = tracker
                .windows
                .entry(key)
                .or_default()
                .entry(client)
                .or_default();
            stats.queries = u64::MAX;
            stats.nxdomains = u64::MAX;
            stats.suspicious = u64::MAX;
            stats.reasons.push("high_entropy".to_string());
        }

        for _ in 0..5 {
            tracker.observe_at(&q(client, "xq7z9w2k1v4b8.example.xyz", false), timestamp);
            tracker.observe_at(&q(client, "xq7z9w2k1v4b8.example.xyz", true), timestamp);
        }

        let stats = &tracker.windows[&key][&client];
        assert_eq!(stats.queries, u64::MAX);
        assert_eq!(stats.nxdomains, u64::MAX);
        assert_eq!(stats.suspicious, u64::MAX);
        let mut unique = stats.reasons.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(stats.reasons.len(), unique.len());
    }

    #[test]
    fn empty_window_score_is_zero() {
        let (score, reasons) = window_score(&WindowStats::default());
        assert_eq!(score, 0.0);
        assert!(reasons.is_empty());
    }

    #[test]
    fn drain_older_than_keeps_the_current_window() {
        let mut tracker = Tracker::new(60);
        tracker.observe_at(&q([10, 0, 0, 7], "api.example.com", false), 60);
        tracker.observe_at(&q([10, 0, 0, 7], "api.example.com", false), 120);

        let drained = tracker.drain_older_than(2);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 1);
        assert!(!tracker.windows.contains_key(&1));
        assert!(tracker.windows.contains_key(&2));
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
