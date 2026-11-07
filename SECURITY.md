# Security policy

## Scope

sentinel-dns parses untrusted bytes: capture files, live pipes, and config
files. Memory-safety bugs in packet or config parsing are security bugs.
Logic bugs that silence real detections or fabricate alerts are treated
with the same seriousness.

## Supported versions

Only the latest release receives fixes.

## Reporting

Open a private security advisory on GitHub, or email the address on the
maintainer's GitHub profile with:

- version and build (`sentinel-dns --version`)
- the input class involved (offline file, live pipe, config)
- a minimal reproducer: a synthetic pcap or config, never a real capture

Please include an impact statement. You will get an acknowledgment within
a week and a fix timeline for confirmed issues.

## Hardening notes

- The binary runs unprivileged; only the capture producer (tcpdump) needs
  packet access. Do not run the whole pipeline as root when you can avoid
  it.
- Alert JSONL is written with hostile content (query names) JSON-escaped;
  anything that consumes it must parse it as JSON, never split on
  delimiters.
- Webhook URLs must be https:// by configuration; plain HTTP is rejected
  at load time, not at delivery time.
