# Changelog

## 0.2.0

### Fixed

- **NXDOMAIN ratio was diluted by responses counting as queries.** Window
  scoring now counts a message's direction properly: volume and name
  suspicion come from the query side, responses contribute only their
  rcode. A client whose lookups all fail — the classic NXDOMAIN
  exfiltration pattern — now actually crosses `nxdomain_burst` instead of
  stalling at exactly the 0.5 boundary.
- **Alerts re-fired on every additional bad window.** A sustained streak
  now alerts exactly once and re-arms only after a clean window, as
  documented.
- **A recreated window can no longer be scored twice** when a lagging
  live pipe or late packets re-create an already-drained window.

### Added

- Live `watch` mode closes finished windows on wall-clock time (poll on
  stdin with a 500 ms cadence), so alerts and SIGHUP handling no longer
  wait for new packets when traffic goes quiet. The pcap reader is
  resumable across those timeouts and restores stdin's descriptor flags
  on exit.
- `trusted_clients` accepts CIDR subnets (`10.0.0.0/8`) in addition to
  exact addresses.
- Config errors name the offending key and value instead of a generic
  `bad config` message; a UTF-8 BOM is tolerated.
- `--version` / `-V`; `-c` without a value is now an error instead of
  silently running on defaults.
- Offline `analyze` reports totals (`packets, dns messages, alerts`) on
  stderr.
- The pcap reader rejects nanosecond-resolution captures with a specific
  message and round-trips big-endian captures (tested).

### Changed

- Webhook delivery moved to a background thread — a slow endpoint can no
  longer stall the packet loop for up to its 5 s timeout.
- Windows strictly older than the current packet's window are closed as
  packets arrive, bounding tracker memory even when timestamps jump
  backwards.
- CI now checks formatting (`cargo fmt --check`) instead of reformatting
  sources and uploading them as an artifact.

## 0.1.0

Initial release: classic-pcap reading (Ethernet IPv4), DNS question
extraction with hardened name decompression, per-domain heuristics,
per-client window scoring, JSONL alerts, optional HTTPS webhook, hand
parser for the flat JSON config, and a synthetic selftest.
