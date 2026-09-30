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
