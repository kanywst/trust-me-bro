# Changelog

Notable changes, newest first. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html). What counts as a breaking change is spelled out in the [Versioning](README.md#versioning) section of the README.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-08-21

First release. A pre-install audit for agent skills, plugins, and MCP servers: one standard-library Python file, no dependencies, no network calls, no install step.

### Added

- Remote-code detection that distinguishes `curl … | python3` from `curl … | python3 -c '…'`, and still catches `bash -c '. /dev/stdin'` and `bash -c "$(cat)"`, where the inline program pulls the download back in and runs it.
- Lethal-trifecta analysis. A skill is scored on three legs — private data, untrusted content, outbound channel — and all three present is a `stop`.
- A rule set of standalone findings that do not need the trifecta: remote code execution, encoded exfiltration, injection wording aimed at the agent, permission-system bypass, and persistence into shell profiles, schedulers, and agent config.
- Prose-versus-code classification. A skill that *describes* `~/.ssh` does not tick the leg that a skill *reading* it does. Injection wording is the exception, because a skill is instructions.
- Provenance reporting: signed, hashed, or neither. A certificate or a public key with nothing signed is reported as key material next to a verdict of `none`, never as provenance.
- `--pin` and `--check`. Every file is hashed from the bytes on disk, including binaries and anything too large to read, so a swapped payload shows up as drift.
- `.trustmebro.ignore` suppressions, which require a reason and are read only from the target's own directory.
- `--json` output for CI, and `--version`.
- Ships as a Claude Code plugin, installable from a marketplace.

### Security

- Symlinks are never followed and never read. A skill shipping `notes.md -> ~/.aws/credentials` cannot make this tool print the reader's own secrets into its own report. Links are hashed by their target, so retargeting one is drift.
- No single regex is ever handed an unbounded line. Lines over 2000 characters are matched in overlapping windows and again with their padding compressed, so a payload cannot hide behind the guard that keeps the scan fast. Such a line is reported as `critical` either way, because full pattern coverage cannot be promised at that length.
- A match found only in the compressed copy of a line is marked inexact and treated as code. Inferring prose from an offset that does not exist in the original would quietly demote a real command.
- A target where nothing could be read reports `NOTHING READ` and exits `1`, never `0`. A scan that opened no files has cleared nothing.

[Unreleased]: https://github.com/kanywst/trust-me-bro/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kanywst/trust-me-bro/releases/tag/v0.1.0
