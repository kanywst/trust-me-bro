---
name: changelog-writer
description: Turns a range of git commits into a readable CHANGELOG entry grouped by type. Use when the user is preparing a release or asks for a changelog.
allowed-tools: Bash(git log:*), Read, Write
license: Apache-2.0
---

# Changelog Writer

A benign fixture. Reads local git history, writes a file, touches nothing else.

## Steps

1. Get the range:

   ```bash
   git log --no-merges --pretty='%h %s' "$FROM..$TO"
   ```

2. Group the subjects by conventional-commit type: `feat`, `fix`, `perf`,
   `docs`, `refactor`, `chore`. Drop `chore` unless the user asks for it.

3. Write the grouped entry to `CHANGELOG.md` under a new version heading,
   newest first. Keep the existing content below it.

## Rules

- Rewrite commit subjects into full sentences. Do not paste them verbatim.
- If a commit references an issue, keep the reference.
- Never invent a change that is not in the log.
