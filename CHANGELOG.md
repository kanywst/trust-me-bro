# Changelog

Notable changes, newest first. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html). What counts as a breaking change is spelled out in the [Versioning](README.md#versioning) section of the README.

## [Unreleased]

Nothing yet.

## [0.2.0] - 2026-09-16

Configuration is read as structure, not as text. Both of the gaps below came back exit `0` in 0.1.0 against a deliberately malicious fixture, which for a pre-install audit is the one failure mode that matters.

### Added

- `HOOK-DECLARED` at `high`. A hook block — in `hooks/hooks.json`, a plugin manifest, or a `settings.json` — binds a command to one of the agent's own events, so installing the plugin installs a command that runs before you see anything and whether or not you ever use the skill. The declaration is the finding; the command it binds is then scanned like any other command. A manifest that points at a hook file rather than declaring one is not a declaration, and the file it names is walked on its own.
- `MCP-SERVER-REMOTE` and `MCP-SERVER-LOCAL` at `medium`, with two new legs, `UNTR-MCP-SERVER` and `EXFIL-MCP-SERVER`. A remote MCP server is another party deciding what enters the agent's context and your tool arguments leaving for them, so it raises the untrusted-content and outbound legs by construction rather than by pattern. A skill that also reads a credential is then the trifecta.
- Commands are reassembled out of the keys JSON splits them across. `"command"`, `"args"`, `"env"` and `"headers"` become one line and go through the existing rules, so `npx -y pkg@latest` spread over three lines is now the runtime install and moving reference it always was. A reassembled quote is labelled `(reassembled from JSON)` and never presented as a line that exists in the file.
- `SCAN-CONFIG-UNPARSED` at `low`, for a config that names one of these shapes and then will not parse. The text pass has still read every line of it, but the structure nobody could read is worth saying out loud, because the agent's own parser is likely more forgiving than this one. Line comments and trailing commas parse for the same reason.

### Changed

- The shapes are matched on shape, at any depth, rather than on a list of filenames. Where a hook block lives has moved from `settings.json` to a plugin manifest to `hooks/hooks.json` already, and a scanner pinned to today's filenames goes quiet the next time it moves. Every entry under a shape is judged on its own: a block recognised all-or-nothing is a block that one `{"enabled": false}` sibling switches off, and that needs no adversary.
- Reach seen both as JSON text and as a reassembled command is reported once, as the reassembled one, which quotes the whole command instead of the fragment a line happened to hold.

## [0.1.0] - 2026-08-22

First release. A pre-install audit for agent skills, plugins, and MCP servers: one standard-library Python file, no dependencies, no network calls, no install step.

### Added

- Remote-code detection split across two rules. `curl … | bash` executes the download and is `critical`; `curl … | python3 -c '…'` hands it to a local program whose behaviour cannot be read off the command line, and is reported at `high` rather than guessed at. Forms that can be shown to execute the download — `. /dev/stdin`, `eval`, `exec`, `$(cat)` — are promoted back to `critical`. Either way the line is reported and the verdict floor is `review`, so no piped download reaches exit `0`.
- Lethal-trifecta analysis. A skill is scored on three legs — private data, untrusted content, outbound channel — and all three present is a `stop`.
- A rule set of standalone findings that do not need the trifecta: remote code execution, encoded exfiltration, injection wording aimed at the agent, permission-system bypass, and persistence into shell profiles, schedulers, and agent config.
- Prose-versus-code classification. A skill that *describes* `~/.ssh` does not tick the leg that a skill *reading* it does. Injection wording is the exception, because a skill is instructions.
- Provenance reporting: signed, hashed, or neither. A certificate or a public key with nothing signed is reported as key material next to a verdict of `none`, never as provenance.
- `--pin` and `--check`. Every file the walk reaches is hashed from the bytes on disk, including binaries and anything too large to read, so a swapped payload shows up as drift. Directories the walk skips are not hashed, and are named in the report for exactly that reason.
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

[Unreleased]: https://github.com/kanywst/trust-me-bro/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kanywst/trust-me-bro/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kanywst/trust-me-bro/releases/tag/v0.1.0
