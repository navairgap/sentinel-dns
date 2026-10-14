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

