# Security

## Reporting

Use [private vulnerability reporting](https://github.com/kanywst/trust-me-bro/security/advisories/new). Please do not open a public issue for a bypass.

## What counts as a vulnerability here

This tool's job is to not give false assurance, so the bugs that matter are the ones that make it quieter than it should be:

- a skill that reaches private data, untrusted content and an outbound channel, and is not reported as doing so
- a way to make `--check` miss a changed file, so an updated skill looks unchanged
- a way to make provenance report `signed` or `hashed` without an actual signature, attestation, or checksum
- a suppression that a skill can apply to itself, rather than one its user chose
- input that makes the scanner hang, crash, or read outside the target

A missed pattern in a single rule is an ordinary bug: open an issue with the line that should have matched.

## What this tool does not claim

It reads text. It does not execute the target, sandbox it, or watch it at run time, and it cannot know what a URL will serve tomorrow. A clean report means nothing was visible in the files, not that the skill is safe. Anything built on the opposite reading of that sentence is a misuse, not a vulnerability.
