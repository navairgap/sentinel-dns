# Contributing

## Ground rules

- Every commit must build, pass `cargo test`, pass
  `cargo clippy -- -D warnings`, and be `cargo fmt --check` clean. CI runs
  all four; a red commit is a broken commit.
- One logical change per commit. Mixed refactors and behavior changes are
  hard to review and harder to revert.
- No new dependencies for things the standard library or the two existing
  ones (`libc`, `ureq`) already do. The whole point of this tool is a
  small, auditable binary.
- Malformed input is a test case, not a crash report. Anything that parses
  packets or configs gets a hostile-input test alongside it.

## Detection changes

Detection changes (scoring weights, thresholds, window logic) need an
evaluation note in the PR: what the change is for, a synthetic capture that
demonstrates it, and which false positives it does or does not introduce.
`cargo run -- selftest` must keep passing exactly as it is; adjust the
selftest only when its contract itself changes, and say so in the commit
message.

## Style

- `rustfmt` is the arbiter; run `cargo fmt` before committing.
- Comments explain why, not what. If a comment restates the code, delete
  it; if a heuristic number exists, say where it came from.
- Error messages name the offending key, file, or value. "invalid input"
  is not an error message.

## Reporting issues

Include the command line, the config (minus any internal hostnames), the
stderr diagnostics, and if possible a synthetic pcap that reproduces the
behavior. Do not attach real captures.
