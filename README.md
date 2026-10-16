# sentinel-dns

passive DNS exfiltration and DGA detection, at the resolver. one static
binary, zero cloud lookups, works air-gapped.

sentinel reads pcap data — an offline capture, or a live `tcpdump` pipe —
extracts DNS questions, and scores each client's behavior inside rolling
time windows. many bad signals from one host inside one minute is what an
alert is made of; single weird domains are noise and stay quiet.

## install

```bash
cargo build --release
sudo cp target/release/sentinel-dns /usr/local/bin/
```

live capture needs root (or `CAP_NET_RAW` for tcpdump); offline analysis
runs as anyone.

## usage

```bash
# analyze an offline capture
sentinel-dns analyze capture.pcap

# watch live resolver traffic (the intended deployment)
sudo tcpdump -i eth0 -w - port 53 | sentinel-dns watch

# verify your build sees what it should
sentinel-dns selftest

# print a default config to start from
sentinel-dns config > sentinel.json
```

alerts are one JSON object per line on stdout:

```json
{"v":1,"client":"10.0.0.42","window":1700000000,"score":0.90,
 "reasons":["sustained_dga","nxdomain_burst"],"queries":45,"nxdomains":41}
```

pipe them to a file, a SIEM, or anything that reads JSONL. an optional
`webhook_url` in the config POSTs each alert onward over HTTPS with certificate verification. HTTP URLs are rejected.

Webhook delivery has a five-second timeout and redirects are disabled, preventing a configured endpoint from forwarding alert data to another host. Failures are logged to stderr but do not stop packet analysis; retain stdout JSONL as the primary alert stream.

## configuration

flat JSON, loaded with `-c`:

| key | default | meaning |
| --- | --- | --- |
| `window_seconds` | 60 | scoring window length |
| `score_threshold` | 0.6 | window score that counts as bad |
| `windows_before_alert` | 3 | consecutive bad windows before firing |
| `trusted_clients` | [] | IPs never scored (your resolvers, monitoring) |
| `webhook_url` | "" | empty = stdout only |

unknown keys are ignored; the format is forward-compatible. send SIGHUP to
reload the config without dropping the capture.

## how detection works

1. **per domain**: Shannon entropy, digit ratio, DGA shape, vowel absence,
   cheap-TLD weight — combined into a 0..1 suspicion score
2. **per client per window**: query volume, NXDOMAIN ratio, count of
   high-suspicion names — a window is *bad* only on sustained patterns
3. **per client over windows**: `windows_before_alert` consecutive bad
   windows produce exactly one alert until the client goes clean

trusted resolvers and CDNs score high by nature — put them in
`trusted_clients` and require consecutive windows; both knobs are the
false-positive budget.

## v1 boundaries (honest)

- UDP port 53 only; DoH/DoT leave no resolver-side trace to watch
  (block outbound 853/443 to unknown resolvers at the firewall instead)
- webhook delivery requires HTTPS; plain HTTP is rejected
- Ethernet IPv4 captures; IPv6 and pcapng are roadmap

## selftest

`sentinel-dns selftest` synthesizes a capture — one clean client, one DGA
offender — runs the full pipeline, and fails unless exactly one alert
fires for exactly the offender. CI runs it on every push.

## tests

```bash
cargo test
```

pcap round-trips, DNS name decompression (including pointer-loop
termination), entropy math, scorer behavior on crafted domains, window
logic, config parsing, and alert formatting are all covered — unprivileged,
no network, no fixtures.

## license

MIT

## Operations

run it under systemd with `Restart=always`; the alert stream goes to journald by default. point `StandardOutput=` at a file if you want logrotate to handle retention. SIGHUP reloads the config without dropping the pipe.

## History

this repo spent weeks as documentation describing a tool that didn't exist — scored sections, alert anatomy, all of it fiction. then one evening it became the fiction: a real rust tool with a CI gate. the docs came first; the code finally caught up.
