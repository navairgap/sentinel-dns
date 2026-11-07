# sentinel-dns

[![CI](https://github.com/navairgap/sentinel-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/navairgap/sentinel-dns/actions/workflows/ci.yml)

Passive DNS exfiltration and DGA detection at the resolver. One static
binary, zero cloud lookups, works air-gapped.

sentinel-dns reads pcap data — an offline capture, or a live `tcpdump`
pipe — extracts DNS questions, and scores each client's behavior inside
rolling time windows. Many bad signals from one host inside one minute is
what an alert is made of; a single weird domain is noise and stays quiet.

## How detection works

Three layers, cheapest first:

1. **Per domain** — the question name is scored with cheap heuristics:
   Shannon entropy, digit ratio, DGA shape (many unique characters, no
   structure), vowel absence, cheap-TLD weight, oversized labels. Each
   hit contributes weight; a name scores 0.0–1.0.

2. **Per client per window** — window-level signals combine the domain
   scores into a window score (0.0–1.0):

   | signal | weight | condition |
   | --- | --- | --- |
   | `sustained_dga` | 0.5 | ≥ 20 queries, ≥ ⅓ of them high-suspicion names |
   | `nxdomain_burst` | 0.3 | ≥ 10 queries, > 50% NXDOMAIN |
   | `nxdomain_flood` | 0.1 | > 80% NXDOMAIN |
   | `flag_domains` | 0.1 | ≥ 1 high-suspicion domain seen |

3. **Per client over windows** — a window scoring ≥ `score_threshold`
   extends the client's bad streak. `windows_before_alert` consecutive
   bad windows fire **one** alert; the streak must end (a clean window)
   before the client can alert again.

Counting is query-driven: `queries` is the number of questions a client
asked, `nxdomains` the number of NXDOMAIN responses it received, so the
NXDOMAIN ratio compares failures against lookups actually attempted.

## Install

```bash
cargo build --release
sudo cp target/release/sentinel-dns /usr/local/bin/
```

The binary is static apart from libc; the only runtime work it asks of the
system is reading a pcap stream. Live capture needs a producer with packet
access (root or `CAP_NET_RAW` for tcpdump); sentinel-dns itself runs
unprivileged, reading the pipe.

## Usage

```bash
# analyze an offline capture
sentinel-dns analyze capture.pcap

# watch live resolver traffic (the intended deployment)
sudo tcpdump -i eth0 -w - 'udp port 53' | sentinel-dns watch

# analyze a week of rotated captures as one timeline
sentinel-dns analyze mon.pcap tue.pcap wed.pcap

# verify your build sees what it should
sentinel-dns selftest

# print a default config to start from
sentinel-dns config > sentinel.json
```

Alerts are one JSON object per line on stdout — pipe them to a file, a
SIEM, or anything that reads JSONL:

```json
{"v":1,"client":"10.0.0.42","window":1700000040,"score":0.90,
 "reasons":["sustained_dga","nxdomain_burst"],"queries":45,"nxdomains":41,
 "suspicious":30}
```

| field | meaning |
| --- | --- |
| `client` | IP of the client that earned the alert |
| `window` | start of the window that crossed the threshold (unix seconds) |
| `score` | window score, 0.00–1.00 |
| `reasons` | which window-level signals fired |
| `queries` | DNS questions the client asked in that window |
| `nxdomains` | NXDOMAIN responses it received |
| `suspicious` | questions whose names scored as high-suspicion |

Progress for offline runs (`packets, dns messages, alerts`) and any
skipped-packet diagnostics (with `-v`) go to stderr; stdout stays pure
JSONL. See [docs/sentinel-dns.1](docs/sentinel-dns.1) for the full command
reference.

## Configuration

Flat JSON, loaded with `-c`. Unknown keys are ignored, so configs stay
forward-compatible:

```json
{
  "window_seconds": 60,
  "score_threshold": 0.6,
  "windows_before_alert": 3,
  "trusted_clients": ["10.0.0.2", "192.168.10.0/24"],
  "webhook_url": ""
}
```

| key | default | meaning |
| --- | --- | --- |
| `window_seconds` | 60 | scoring window length (≥ 1) |
| `score_threshold` | 0.6 | window score that counts as bad (0 < t ≤ 1) |
| `windows_before_alert` | 3 | consecutive bad windows before firing |
| `trusted_clients` | `[]` | IPs or CIDR subnets never scored (your resolvers, monitoring hosts) |
| `webhook_url` | `""` | empty = stdout only |

Notes:

- **Live windows close on wall-clock time.** A client that goes quiet
  still gets its finished windows scored within about a second — alerts
  do not wait for more traffic. SIGHUP is handled at the same cadence.
- **SIGHUP reloads the config** without dropping the capture. Changing
  `window_seconds` resets in-flight windows and streaks (window keys are
  not comparable across lengths); other changes apply immediately.
- **Webhooks** require `https://` (plain HTTP is rejected at load),
  verify TLS certificates, disable redirects, and time out after 5 s.
  Delivery happens on a background thread — a slow endpoint never stalls
  packet analysis. Stdout JSONL remains the primary alert stream; webhook
  delivery is best-effort.
- Corrupt records at the end of a capture (a pipe torn down mid-write)
  end the stream quietly; malformed metadata inside a capture is an
  error.

## Tuning for your network

Both knobs are your false-positive budget:

- Trusted resolvers and CDNs score high by nature — put them (or their
  subnets) in `trusted_clients`.
- `windows_before_alert` is the cheapest false-positive filter: a single
  bad window from a misbehaving browser extension or a stuck resolver
  client never fires at the default of 3.
- Raise `score_threshold` if your users hit wildcard DNS or many
  NXDOMAINs routinely; lower it only after watching a week of baselines.

Evaluate changes with small synthetic captures and expected output
(`cargo run -- selftest` builds one end to end). Track false positives as
well as detections, and never treat a single unusual domain as proof of
exfiltration — that is what the window streak exists to prevent.

## Deployment

Run the watcher as a systemd service with the capture producer beside it:

```ini
# /etc/systemd/system/sentinel-dns.service
[Unit]
Description=passive DNS anomaly monitor
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/bin/sh -c 'exec tcpdump -i eth0 -w - -U -n "udp port 53" | exec /usr/local/bin/sentinel-dns watch -c /etc/sentinel-dns/config.json'
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# tcpdump needs raw packet access; sentinel-dns runs unprivileged.
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`tcpdump -U` flushes each packet into the pipe, which keeps alert latency
at window granularity. The alert stream goes to journald by default; point
`StandardOutput=` at a file if you want logrotate to handle retention.
`systemctl reload sentinel-dns` re-reads the config.

## Signals and exit status

- `SIGHUP` — reload the config at the next safe point; the capture keeps
  flowing. A changed `window_seconds` resets in-flight windows and
  streaks.
- `SIGINT`/`SIGTERM` — stop reading and score everything already captured
  before exiting cleanly.
- Exit `0` on success (including a drained shutdown and a closed stdout
  pipe), `1` on failure (unreadable input, bad config, not a pcap, I/O
  error), `2` on usage errors.

## Troubleshooting

- **No alerts, but you are sure traffic is suspicious** — run with `-v`
  and watch the closed-window lines: scores are printed per client per
  window, so you can see how far off the threshold you are. Then lower
  `score_threshold` or `windows_before_alert` accordingly.
- **`sentinel-dns: not a pcap stream`** — the file is pcapng or
  nanosecond-resolution. Convert with `tcpdump -r in.pcapng -w out.pcap`
  or `editcap -F pcap`.
- **Alerts stop arriving when stdout is rotated away** — the pipeline
  exits when the alert stream closes. If you rotate, point
  `StandardOutput=` at journald, or use a copytruncate-style rotator.
- **Too many alerts from one subnet** — add the subnet to
  `trusted_clients` rather than raising thresholds for everyone.

## Limitations (honest)

- Ethernet IPv4 UDP/53 only. IPv6, pcapng, VLAN tags, and DNS over
  TLS/HTTPS are not parsed. DoH/DoT leave no resolver-side trace to watch
  — block outbound 853/443 to unknown resolvers at the firewall instead.
- Packets are processed in capture order; windows assume roughly
  non-decreasing timestamps, which is what live captures and virtually
  all files provide. A lagging pipe cannot cause a window to be scored
  twice.
- Webhook delivery is fire-and-forget: failures are logged, not retried,
  and a process exit can cut a delivery short. If you need guaranteed
  delivery, consume stdout JSONL.
- Only the first question of each DNS message is inspected; answers are
  never parsed. That is deliberate — it keeps the parser small enough to
  audit against hostile input.

## Development

```bash
cargo test          # 100+ unit tests, no fixtures, no network
cargo run -- selftest   # end-to-end pipeline check (CI runs this)
cargo clippy -- -D warnings
cargo fmt --all -- --check
```

The pcap reader, DNS name decompressor (including compression-pointer
hostility), scorer, config parser, and alert state are all covered by
tests that run unprivileged and offline. Malformed-packet handling is
tested against truncated, misdeclared, and pointer-looped input.

## License

MIT
