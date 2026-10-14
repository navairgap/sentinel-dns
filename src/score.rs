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
    let mut reasons = Vec::new();
    let lower = name.to_lowercase();
    let core = lower.split('.').next().unwrap_or("");

    let ent = entropy(core);
    if ent > 3.5 && core.len() >= 8 {
        score += 0.45;
        reasons.push("high_entropy");
    }
    let digits = core.chars().filter(|c| c.is_ascii_digit()).count();
    if core.len() >= 6 && digits as f64 / core.len() as f64 > 0.3 {
        score += 0.25;
        reasons.push("digit_heavy");
    }
    let unique = core.chars().collect::<std::collections::BTreeSet<_>>().len();
    if core.len() >= 10 && unique >= core.len() - 2 {
        score += 0.2;
        reasons.push("dga_shape");
    }
    if !core.chars().any(|c| "aeiou".contains(c)) && core.len() >= 6 {
        score += 0.1;
        reasons.push("no_vowels");
    }
    for tld in [".xyz", ".top", ".buzz", ".icu", ".cam"] {
        if lower.ends_with(tld) {
            score += 0.1;
            reasons.push("cheap_tld");
            break;
        }
    }
    if core.len() > 40 {
        score += 0.1;
        reasons.push("oversize_label");
    }
    (score.min(1.0), reasons)
}

/// Map a client's accumulated window into a final alert score + reasons.
pub fn window_score(w: &WindowStats) -> (f64, Vec<String>) {
    let mut score = 0.0f64;
    let mut reasons = Vec::new();
    if w.queries == 0 {
        return (0.0, reasons);
    }
    if w.queries >= 20 && w.suspicious * 3 >= w.queries {
        score += 0.5;
        reasons.push("sustained_dga");
    }
    let nx = w.nxdomains as f64 / w.queries as f64;
    if w.queries >= 10 && nx > 0.5 {
        score += 0.3;
        reasons.push("nxdomain_burst");
        if nx > 0.8 {
            score += 0.1;
            reasons.push("nxdomain_flood");
        }
    }
    let mut all = w.reasons.clone();
    all.sort();
    all.dedup();
    if !all.is_empty() {
        score += 0.1;
        reasons.push("flag_domains");
    }
    (score.min(1.0), reasons)
}

