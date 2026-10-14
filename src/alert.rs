//! Alerts: JSONL to stdout, optional append to a file, optional webhook.
//! The webhook is a deliberately small HTTP/1.1 POST over plain TCP —
//! TLS would need a dependency, and internal webhooks are usually http.

use std::fmt::Write as _;
use std::io;
use std::net::TcpStream;
use std::time::Duration;

