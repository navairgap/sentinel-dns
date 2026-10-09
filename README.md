# sentinel-dns

Passive DNS query logger and analyzer for your home LAN

> 🚧 **Status: planning** — architecture and README first, code next.

## Why

DNS is where most malware, trackers, and phishing start. This tool passively watches every DNS query on your own network and flags the suspicious ones — no packet injection, no external services, everything stays local.

## Planned features

- Capture DNS queries on the LAN (passive sniff or resolver log import)
- Match domains against blocklists and flag rare/typo-squatted lookups
- Per-device query profiles — know what each device talks to
- Daily report: top domains, new domains, suspicious hits

## Stack

`python` `scapy` `linux`

## Notes

Design docs first, then the sniffer. Follows SentinelWiFi's passive-only rules.

## License

MIT, see [LICENSE](LICENSE).

---
maintained · verified 2026-09-30

## How detection works

1. Capture outbound DNS queries passively.
2. Score entropy, domain age signals, and NXDOMAIN ratio per client.
3. Alert when a client's score crosses the threshold for N consecutive windows.

Tuning lives in `config.yml` — lower the window for noisier networks.

## False positives

CDNs and DoH forwarders score high on entropy by nature. Exclude known resolver IPs in `config.yml` under `trusted_resolvers`, and require the alert threshold to hold for at least 3 consecutive windows before paging anyone.


## Privacy

DNS metadata stays local — nothing leaves the box except your alerts. The scorer needs no cloud lookups, which also means it works on air-gapped networks.


## Requirements

python 3.9+, root or CAP_NET_RAW for capture, ~30MB ram. a raspberry pi zero runs it fine on a home network.


## Testing the install

run `sentinel-dns --selftest`: it resolves ten known-good domains and one deliberately-bad one, and verifies the scorer fires on exactly the bad one. if selftest passes, your install is good.
