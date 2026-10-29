# pcap test fixtures

Keep packet fixtures small, synthetic, and offline. Cover ordinary query/response pairs, repeated queries within a scoring window, multiple independent clients, truncated packets, malformed questions, empty captures, and captures without DNS. Assert malformed packets do not crash the process, one unusual query does not alone imply exfiltration, scores are deterministic, and JSON output remains parseable for control characters. Do not publish real customer captures or internal hostnames.

## PCAP boundary matrix

Include equivalent little-endian and big-endian fixtures with identical decoded packets. Validate that a captured length cannot exceed the original packet length or global snaplen, and reject unsupported link types and invalid magic bytes. Cover an empty capture, a partial record header, and a partial final payload separately: expected behavior should distinguish malformed metadata from a capture that ended mid-write. Keep fixtures generated in code and deterministic.
