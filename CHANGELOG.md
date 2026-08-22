# Changelog

Notable changes, newest first. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html). What counts as a breaking change is spelled out in the [Versioning](README.md#versioning) section of the README.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-08-22

First release. A pre-install audit for agent skills, plugins, and MCP servers: one standard-library Python file, no dependencies, no network calls, no install step.

### Added

- Remote-code detection split across two rules. `curl … | bash` executes the download and is `critical`; `curl … | python3 -c '…'` hands it to a local program whose behaviour cannot be read off the command line, and is reported at `high` rather than guessed at. Forms that can be shown to execute the download — `. /dev/stdin`, `eval`, `exec`, `$(cat)` — are promoted back to `critical`. Either way the line is reported and the verdict floor is `review`, so no piped download reaches exit `0`.
- Lethal-trifecta analysis. A skill is scored on three legs — private data, untrusted content, outbound channel — and all three present is a `stop`.
- A rule set of standalone findings that do not need the trifecta: remote code execution, encoded exfiltration, injection wording aimed at the agent, permission-system bypass, and persistence into shell profiles, schedulers, and agent config.
- Prose-versus-code classification. A skill that *describes* `~/.ssh` does not tick the leg that a skill *reading* it does. Injection wording is the exception, because a skill is instructions.
- Provenance reporting: signed, hashed, or neither. A certificate or a public key with nothing signed is reported as key material next to a verdict of `none`, never as provenance.
- `--pin` and `--check`. Every file is hashed from the bytes on disk, including binaries and anything too large to read, so a swapped payload shows up as drift.
- `.trustmebro.ignore` suppressions, which require a reason and are read only from the target's own directory.
- `--json` output for CI, and `--version`.
- Ships as a Claude Code plugin, installable from a marketplace.

### Security

- Symlinks found inside a skill are never followed and never read. A single file named through a link on the command line is refused rather than resolved, since resolving it would quote the target's lines into the report; a directory named through a link is followed and reported with its target, because that is how skills are ordinarily installed. A skill shipping `notes.md -> ~/.aws/credentials` cannot make this tool print the reader's own secrets into its own report. Links are hashed by their target, so retargeting one is drift.
- No single regex is ever handed an unbounded line. Lines over 2000 characters are matched in overlapping windows and again with their padding compressed, so a payload cannot hide behind the guard that keeps the scan fast. Such a line is reported as `critical` either way, because full pattern coverage cannot be promised at that length.
- The quoted evidence for a finding is the part of the line that matched, not its first 120 characters, so padding cannot push the command out of its own report. When the match was only found in a compressed copy, the compressed text is quoted and labelled as such rather than presented as the line.
- A match found only in the compressed copy of a line is marked inexact and treated as code. Inferring prose from an offset that does not exist in the original would quietly demote a real command.
- A target where nothing could be read reports `NOTHING READ` and exits `1`, never `0`. A scan that opened no files has cleared nothing.
- Every place the scan does not reach is named. A vendored or build directory is `SCAN-VENDOR-SKIPPED` at `high`, so a skill hiding code in `node_modules` cannot come back clean at exit `0`; a version-control or cache directory is `SCAN-DIR-SKIPPED` at `low`; a file hashed but never parsed is `SCAN-NOT-READ`.
- A file the scanner cannot open at all is reported as `SCAN-FILE-DROPPED` rather than skipped. It is absent from the lock, so `--check` cannot see it change; being absent from the tally as well would leave it in the skill and in no count at all.

[Unreleased]: https://github.com/kanywst/trust-me-bro/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kanywst/trust-me-bro/releases/tag/v0.1.0
