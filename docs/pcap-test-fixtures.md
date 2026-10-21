# pcap test fixtures

Keep packet fixtures small, synthetic, and offline. Cover ordinary query/response pairs, repeated queries within a scoring window, multiple independent clients, truncated packets, malformed questions, empty captures, and captures without DNS. Assert malformed packets do not crash the process, one unusual query does not alone imply exfiltration, scores are deterministic, and JSON output remains parseable for control characters. Do not publish real customer captures or internal hostnames.
