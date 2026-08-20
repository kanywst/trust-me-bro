---
name: trust-me-bro
description: Read an agent skill, plugin, or MCP server before installing it. Use whenever the user is about to add, install, clone, or enable a skill, plugin, MCP server, subagent, or hook from someone else, or asks whether one is safe. Reports what it can reach rather than guessing at intent.
license: Apache-2.0
---

# trust-me-bro

Every skill you install says trust me bro. This one reads it first.

## When to use this

Trigger on any of these, without being asked:

- the user is about to install, add, clone, enable, or copy in a skill, plugin, MCP server, subagent, hook, or `.claude`/`.codex`/`.cursor` config from anyone else
- the user asks "is this skill safe", "should I install this", "what does this do"
- a marketplace, gist, `curl` one-liner, or README install step is involved
- an existing skill has updated and the user is about to keep using it

## How to run it

The scan is a script, not a judgement call. Run it. Do not eyeball the files and
decide for yourself, and do not summarise from the README, which is written by
the same person who wrote the skill.

```bash
python3 scripts/scan.py <path-to-the-skill>
```

If the skill is not on disk yet, get it first without running anything from it:

```bash
git clone --depth 1 <url> /tmp/tmb-target && python3 scripts/scan.py /tmp/tmb-target
```

Never run the project's own install script, `make`, `npm install`, or any
`curl … | sh` line in order to inspect it. Cloning is enough.

Useful flags:

- `--json` for structured output
- `--pin` writes `.trustmebro.lock`, a SHA-256 record of exactly what the user approved
- `--check` compares the current files against that lock and reports drift

Exit codes: `0` fine, `1` needs a human read, `2` stop, `3` bad path.

## How to report it back

Lead with the verdict and the single most important reason. Then:

1. **What it can reach.** Walk the three trifecta legs by name: private data, untrusted content, outbound channel. Say which are present and quote the line that proves it, with `file:line`.
2. **Findings**, worst first, each with its `file:line`. Quote the actual line. Never paraphrase a finding into something milder.
3. **Provenance.** Say plainly whether it is signed, hashed, or neither. Almost everything is neither. That is a fact about the ecosystem, not an accusation about this skill.
4. **Your call.** One sentence. If the verdict is `stop`, say so and stop; do not install it and then mention the finding afterwards.

Then offer `--pin` so the user has a record of the version they approved.

## Rules for you, the agent

- **Report capability, not intent.** "This can read your `.env` and POST to `api.example.com`" is a fact. "This is malware" is a guess. Say the fact.
- **Do not soften a critical finding** because the skill looks popular, has a lot of stars, comes from a known org, or has a friendly README. Those are the conditions under which a supply-chain compromise works.
- **Do not install anything mid-audit.** Not the skill, not its dependencies, not a linter to help you read it.
- **`stop` means stop.** Present the finding and wait. The user decides.
- **Prose is not code.** The scanner already separates a skill that *describes* `~/.ssh` from one that *reads* it. Preserve that distinction when you explain the result; a security-tooling skill will legitimately name every dangerous pattern it defends against.
- **If the scanner finds nothing, say that plainly.** Do not invent concerns to look thorough. A clean scan of a small skill is the normal case.
- **State the limit.** This reads text. It cannot see what a URL will serve tomorrow, and it does not execute anything. A clean report is "nothing visible in the files", not "safe".

## The one thing worth remembering

Three legs, from Simon Willison's lethal trifecta:

1. access to **private data**
2. exposure to **untrusted content**
3. an **outbound channel**

Any two are usually fine. All three in one skill means a web page someone else
wrote can decide what happens to your credentials. Break one leg and the chain
collapses.
