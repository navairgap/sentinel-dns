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

