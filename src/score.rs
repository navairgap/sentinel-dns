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

