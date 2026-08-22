#!/usr/bin/env python3
"""trust-me-bro: read an agent skill or plugin before it reads your machine.

Stdlib only. No network. No install step. Point it at a directory or a file.

    python3 scripts/scan.py ./some-skill
    python3 scripts/scan.py ./some-skill --json
    python3 scripts/scan.py ./some-skill --pin      # record what you approved
    python3 scripts/scan.py ./some-skill --check    # has it changed since?
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

# The one place the version is written. The plugin manifests are checked
# against it in CI, so a release cannot ship three numbers that disagree.
__version__ = "0.1.0"

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.json"
LOCK_NAME = ".trustmebro.lock"
IGNORE_NAME = ".trustmebro.ignore"
SKILL_NAME = "skill.md"

TEXT_SUFFIXES = {
    ".md",
    ".markdown",
    ".txt",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".jsonc",
    ".yaml",
    ".yml",
    ".toml",
    ".rb",
    ".go",
    ".rs",
    ".ps1",
    ".bat",
    ".cmd",
    ".env",
    ".cfg",
    ".ini",
    ".conf",
    ".xml",
    ".html",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache"}
MAX_BYTES = 2_000_000
# No reviewable line is this long. A single regex call is bounded to this many
# characters so a hostile skill cannot hand the engine a 50 KB line and stall
# the scan. Longer lines are matched in overlapping windows rather than
# truncated: truncating would let a line pad past the limit and hide the real
# payload behind the very guard that exists to protect the scan. The overlap
# is wider than any pattern can span, so nothing falls between two windows.
MAX_LINE = 2_000
WINDOW_OVERLAP = 400

# A detached signature or an attestation. A certificate or a public key is not
# one: shipping cosign.pub proves nothing was signed, only that someone has a
# key. Reporting that as "signed" would be a false assurance from a tool whose
# entire job is to not give false assurances.
SIGNATURE_SUFFIXES = {".sig", ".asc", ".sigstore", ".att"}
SIGNATURE_NAMES = {"signature", "signatures"}
ATTESTATION_PARTS = (".intoto.jsonl", ".sigstore.json", ".dsse.json", ".provenance.json")
KEY_MATERIAL_SUFFIXES = {".pem", ".pub", ".crt", ".cer"}
MANIFEST_NAMES = {
    "manifest.yaml",
    "manifest.yml",
    "manifest.json",
    "sha256sums",
    "sha256sum.txt",
    "checksums.txt",
    "sha256sums.txt",
    LOCK_NAME,
}
SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b")

URL_RE = re.compile(r"https?://([a-zA-Z0-9._-]+)")
# "Never use sudo" should not be reported as using sudo. Applied only to rules
# marked negation_safe, because some rules are themselves about negative phrasing.
NEGATION_RE = re.compile(
    r"\b(never|do not|don't|dont|avoid|refuse to|must not|no need to|instead of|rather than|without)\b[^.;]{0,40}$",
    re.IGNORECASE,
)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
LEG_LABEL = {
    "private": "private data",
    "untrusted": "untrusted content",
    "exfil": "outbound channel",
}


# ---------------------------------------------------------------- collection


def load_rules(path: Path = RULES_PATH) -> dict:
    with path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    for entry in raw["legs"] + raw["rules"]:
        pattern = entry.get("pattern")
        entry["_re"] = re.compile(pattern, 0 if entry.get("cs") else re.IGNORECASE) if pattern else None
    return raw


def iter_files(root: Path, links: list[dict] | None = None, skipped: list[str] | None = None):
    """Every real file in the target, including binaries. Filtering happens later.

    The lock has to cover files the rules cannot read, or swapping a binary
    payload would slip past --check.

    Symlinks are never followed and never read. A skill can ship
    `notes.md -> ~/.aws/credentials`, and following it would make this tool
    print the reader's own secrets into its own report, which is the exact
    failure it exists to prevent. They are collected in `links` instead so the
    caller can report them.
    """
    if root.is_file() and not root.is_symlink():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in sorted(dirnames):
            directory = Path(dirpath) / name
            if directory.is_symlink() and links is not None:
                links.append(link_record(root, directory))
        if skipped is not None:
            # Not walked means not hashed and not in the lock, so the caller has
            # to be able to say which places this scan does not reach.
            skipped += [relative_name(root, Path(dirpath) / d) for d in sorted(dirnames) if d in SKIP_DIRS]
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not (Path(dirpath) / d).is_symlink()]
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if name in (LOCK_NAME, IGNORE_NAME):
                continue  # the detector's own bookkeeping is not a target
            if path.is_symlink():
                if links is not None:
                    links.append(link_record(root, path))
                continue
            try:
                if path.resolve() == RULES_PATH:
                    continue
            except OSError:
                # Cannot tell whether this is the rule file. Dropping it here
                # would leave it unhashed, uncounted and absent from the lock,
                # which is the silent gap SCAN-FILE-DROPPED exists to close.
                # Let it through and let the hash step report it if it fails.
                pass
            yield path


def link_record(root: Path, path: Path) -> dict:
    base = (root if root.is_dir() else root.parent).resolve()
    try:
        target = os.readlink(path)
    except OSError:
        target = "?"
    try:
        escapes = not path.resolve().is_relative_to(base)
    except (OSError, ValueError):
        escapes = True
    return {"file": relative_name(root, path), "target": str(target), "escapes": escapes}


def is_readable_text(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in TEXT_SUFFIXES or name in MANIFEST_NAMES or not path.suffix


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def digest_of(path: Path) -> str | None:
    """Hash the bytes on disk, not a decoded copy of them."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def trim(line: str, limit: int = 120, around: int | None = None) -> str:
    """Quote the line, and for a long one quote the part the rule matched.

    Cutting at the first 120 characters shows padding when a line was padded,
    which is the one case where the quote matters most: the reader is told a
    command fired and handed a screenful of filler as the evidence for it.
    """
    lead = len(line) - len(line.lstrip())
    line = line.strip()
    if len(line) <= limit:
        return line
    if around is None:
        return line[: limit - 1] + "…"
    start = max(0, min(around - lead - limit // 3, len(line) - limit))
    return ("…" if start else "") + line[start : start + limit] + ("…" if start + limit < len(line) else "")


FENCE_RE = re.compile(r"^\s*(```|~~~)")


def code_mask(path: Path, lines: list[str]) -> list[bool]:
    """True where a line is something that runs, False where it is prose.

    Markdown gets a real fence walk plus indented blocks; anything else is code
    throughout. Prose matches still get reported, but they do not count toward
    the trifecta, because a skill that *describes* ~/.ssh is not a skill that
    *reads* it. Security tooling and threat-model docs would otherwise trip
    every rule they document.
    """
    if path.suffix.lower() not in {".md", ".markdown", ".txt"}:
        return [True] * len(lines)
    mask, in_fence = [], False
    for line in lines:
        if FENCE_RE.match(line):
            in_fence = not in_fence
            mask.append(False)
            continue
        mask.append(in_fence or line.startswith("    ") or line.startswith("\t"))
    return mask


def in_inline_code(line: str, position: int) -> bool:
    """A backticked command in a markdown bullet is still a command the agent runs.

    Unless the bullet is an enumeration. Three or more backtick spans on one
    line is a list of examples ("touching `~/.ssh/`, `~/.aws/`, `~/.env`"),
    which is how every threat-model document is written.
    """
    if line.count("`") >= 6:
        return False
    return line.count("`", 0, position) % 2 == 1


# ------------------------------------------------------------------ scanning

DEMOTE = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}


def demote(severity: str) -> str:
    return DEMOTE[severity]


def relative_name(root: Path, path: Path) -> str:
    if not root.is_dir():
        return path.name
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def scan_text(rel: str, path: Path, text: str, rules: dict) -> dict:
    """Everything one readable file contributes. No aggregation, no policy."""
    findings, mentions = [], []
    legs = {"private": [], "untrusted": [], "exfil": []}

    lines = text.splitlines()
    mask = code_mask(path, lines)

    for entry in rules["legs"]:
        # Legs are capability claims, so "never read ~/.ssh" is not a claim.
        hits = match_lines(entry["_re"], lines, mask=mask, negation_safe=True)
        code_hits = [h for h in hits if h["context"] == "code"]
        record = {"id": entry["id"], "title": entry["title"], "file": rel}
        if code_hits:
            legs[entry["leg"]].append({**record, "hits": code_hits})
        elif hits:
            mentions.append({**record, "hits": hits[:1]})

    for entry in rules["rules"]:
        if entry["_re"] is None:
            continue
        hits = match_lines(entry["_re"], lines, mask=mask, negation_safe=entry.get("negation_safe", False))
        if not hits:
            continue
        # For injection and permission rules the prose *is* the payload: a
        # skill is instructions, so a sentence aimed at the agent runs.
        prose_only = not entry.get("prose_is_code") and all(h["context"] == "prose" for h in hits)
        findings.append(
            {
                "id": entry["id"],
                "severity": demote(entry["severity"]) if prose_only else entry["severity"],
                "title": entry["title"] + (" (described, not run)" if prose_only else ""),
                "why": entry["why"],
                "file": rel,
                "hits": hits,
            }
        )

    return {
        "findings": findings,
        "mentions": mentions,
        "legs": legs,
        "declares_allowed_tools": bool(re.search(r"^\s*allowed[-_]tools\s*:", text, re.IGNORECASE | re.MULTILINE)),
        "hosts": URL_RE.findall(text),
    }


def synthetic(rules: dict, rule_id: str, file: str = "-", extra: str = "") -> dict:
    entry = next((e for e in rules["rules"] if e["id"] == rule_id), None)
    if entry is None:
        return {}
    return {
        "id": entry["id"],
        "severity": entry["severity"],
        "title": entry["title"] + extra,
        "why": entry["why"],
        "file": file,
        "hits": [],
    }


def scan(root: Path, rules: dict, named_link: str | None = None) -> dict:
    """`named_link` is the symlink the caller typed, already resolved to `root`.

    It is reported but not refused: pointing a skills directory at a dotfiles
    checkout is how most people install skills, and refusing it would break the
    ordinary case to close a hole that only exists for single files. Links found
    *inside* a skill stay unfollowed, because the skill chose those.
    """
    findings: list[dict] = []
    mentions: list[dict] = []
    legs: dict[str, list[dict]] = {"private": [], "untrusted": [], "exfil": []}
    hosts: dict[str, int] = {}
    digests: dict[str, str] = {}
    unread: list[str] = []
    dropped: list[str] = []
    notread: list[str] = []
    skipped: list[str] = []
    longline: list[str] = []
    links: list[dict] = []
    declares_allowed_tools = False
    is_skill = False
    scanned = 0

    allowlist = set(rules["host_allowlist"])

    for path in iter_files(root, links, skipped):
        rel = relative_name(root, path)

        # Hash first and unconditionally. A file the rules cannot read is
        # exactly the file an attacker would put a payload in, so --check has
        # to cover it even when --scan cannot.
        digest = digest_of(path)
        if digest is None:
            # Dropping it silently would leave a file that is in the skill, not
            # in the lock, and not in any tally -- the one place a payload can
            # sit where nothing has looked and nothing will notice it change.
            dropped.append(rel)
            continue
        digests[rel] = digest

        try:
            oversized = path.stat().st_size > MAX_BYTES
        except OSError:
            dropped.append(rel)
            continue
        if not is_readable_text(path) or oversized:
            (unread if oversized else notread).append(rel)
            continue

        text = read_text(path)
        if text is None:
            dropped.append(rel)
            continue
        scanned += 1
        is_skill = is_skill or path.name.lower() == SKILL_NAME
        if any(len(line) > MAX_LINE for line in text.splitlines()):
            longline.append(rel)

        result = scan_text(rel, path, text, rules)
        findings += result["findings"]
        mentions += result["mentions"]
        for leg in legs:
            legs[leg] += result["legs"][leg]
        declares_allowed_tools = declares_allowed_tools or result["declares_allowed_tools"]
        for host in result["hosts"]:
            if host not in allowlist:
                hosts[host] = hosts.get(host, 0) + 1

    # `allowed-tools` is an Agent Skills frontmatter field. Reporting it absent
    # from an MCP config or a bare script is noise about a field that does not
    # exist there, and noise is how a real finding gets scrolled past.
    if is_skill and not declares_allowed_tools:
        findings.append(synthetic(rules, "META-NO-ALLOWED-TOOLS"))
    if named_link is not None:
        findings.append(synthetic(rules, "LINK-TARGET-NAMED", extra=f" -> {named_link}"))
    for rel in unread:
        findings.append(synthetic(rules, "SCAN-TOO-LARGE", file=rel))
    for rel in dropped:
        findings.append(synthetic(rules, "SCAN-FILE-DROPPED", file=rel))
    for rel in notread:
        findings.append(synthetic(rules, "SCAN-NOT-READ", file=rel))
    for rel in skipped:
        findings.append(synthetic(rules, "SCAN-DIR-SKIPPED", file=rel))
    for rel in longline:
        findings.append(synthetic(rules, "OBFUS-LONG-LINE", file=rel))
    for link in links:
        # A link is hashed by where it points, so retargeting it is drift even
        # though no byte inside the skill changed.
        digests[link["file"]] = "symlink:" + hashlib.sha256(link["target"].encode("utf-8")).hexdigest()
        rule = "LINK-ESCAPES-TREE" if link["escapes"] else "LINK-PRESENT"
        findings.append(synthetic(rules, rule, file=link["file"], extra=f" -> {link['target']}"))

    ignored = load_ignores(root)
    if ignored:
        findings = [f for f in findings if f and f["id"] not in ignored]
        for leg in legs:
            legs[leg] = [e for e in legs[leg] if e["id"] not in ignored]

    findings = [f for f in findings if f]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"], f["file"]))
    present = [leg for leg in ("private", "untrusted", "exfil") if legs[leg]]

    return {
        "target": str(root),
        "files_scanned": scanned,
        "files_hashed": len(digests),
        "files_unread": sorted(unread),
        "files_dropped": sorted(dropped),
        "files_not_read": sorted(notread),
        "dirs_skipped": sorted(skipped),
        "symlinks": links,
        "findings": findings,
        "mentions": mentions,
        "legs": legs,
        "legs_present": present,
        "trifecta": len(present) == 3,
        "external_hosts": dict(sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "provenance": check_provenance(root),
        "digests": digests,
        "verdict": None,
    }


class _Hit:
    """A match position in the original line, not in the window.

    `exact` is False when the match was found in a compressed copy of the line,
    where no position in the original survives. Callers must not judge context
    from an invented offset: a fabricated 0 reads as "outside any inline code
    span", which would demote a real command to prose and quietly drop it from
    the trifecta.

    `quote` and `quote_at` carry the compressed text and the offset the match
    landed at inside it, so the report can still show the command rather than
    whichever 120 characters happen to come first.
    """

    __slots__ = ("_start", "exact", "quote", "quote_at")

    def __init__(self, start: int, exact: bool = True, quote: str = "", quote_at: int = 0):
        self._start = start
        self.exact = exact
        self.quote = quote
        self.quote_at = quote_at

    def start(self) -> int:
        return self._start


RUN_RE = re.compile(r"(.)\1{7,}")


def squeeze(line: str) -> str:
    """Collapse padding while keeping the shape of a command intact.

    Windowing alone is not enough. Several patterns have to span a gap, so
    `curl <2500 characters of filler> | bash` fits in no single window and the
    rule silently stops firing. Padding is compressible by construction, so
    compress it: runs of one character, runs of whitespace, and a token repeated
    over and over all shrink to a few copies. What is left still looks like the
    command it is.
    """
    line = RUN_RE.sub(lambda match: match.group(1) * 8, line)
    # Per distinct token, not per consecutive run: filler is usually a short
    # cycle such as "-H x -H x -H x", where no two neighbours are equal.
    seen: dict[str, int] = {}
    out = []
    for token in line.split():
        count = seen.get(token, 0) + 1
        seen[token] = count
        if count <= 3:
            out.append(token)
    return " ".join(out)


def search_bounded(pattern: re.Pattern, line: str):
    """Search the whole line without ever handing the engine an unbounded one.

    Truncating instead would let a hostile line pad past the limit and hide its
    payload behind the guard that exists to keep the scan fast. A line this long
    also raises OBFUS-LONG-LINE, which is critical on its own, so a pattern that
    still slips through cannot quietly downgrade the verdict.
    """
    if len(line) <= MAX_LINE:
        return pattern.search(line)

    step = MAX_LINE - WINDOW_OVERLAP
    for offset in range(0, len(line), step):
        found = pattern.search(line[offset : offset + MAX_LINE])
        if found:
            return _Hit(offset + found.start())

    compressed = squeeze(line)
    if len(compressed) < len(line):
        for offset in range(0, max(len(compressed), 1), step):
            found = pattern.search(compressed[offset : offset + MAX_LINE])
            if found:
                # No position in the original line survives compression, so the
                # match is marked inexact and the caller treats it as code. The
                # offset inside the compressed copy is kept, because that copy
                # is what the report quotes and it has to quote the command.
                return _Hit(0, exact=False, quote=compressed, quote_at=offset + found.start())
    return None


def match_lines(
    pattern: re.Pattern, lines: list[str], mask: list[bool], cap: int = 3, negation_safe: bool = False
) -> list[dict]:
    hits = []
    for index, line in enumerate(lines):
        match = search_bounded(pattern, line)
        if not match:
            continue
        if negation_safe and NEGATION_RE.search(line[: match.start()]):
            continue
        # An inexact match came out of a compressed copy of the line, where no
        # original position exists. Treat it as code: the alternative is to
        # infer prose from an invented offset and demote a real command.
        exact = getattr(match, "exact", True)
        is_code = mask[index] or not exact or in_inline_code(line, match.start())
        # An inexact match has no position in the original, so quoting around
        # one is impossible. Quote the compressed copy the match was found in
        # instead, which keeps the shape of the command, and say that is what
        # it is rather than passing filler off as the evidence.
        text = trim(line, around=match.start()) if exact else trim(match.quote, around=match.quote_at)
        hit = {"line": index + 1, "text": text, "context": "code" if is_code else "prose"}
        if not exact:
            hit["compressed"] = True
        hits.append(hit)
        # Keep looking past prose matches: one real command outranks any number
        # of mentions, and the caller only ever shows `cap` of them.
        if len(hits) >= cap and any(h["context"] == "code" for h in hits):
            break
    hits.sort(key=lambda h: (h["context"] != "code", h["line"]))
    return hits[:cap]


def load_ignores(root: Path) -> dict[str, str]:
    """`RULE-ID  reason` per line. A suppression without a reason is not a suppression.

    Read only from the target directory itself, never from a parent. Walking up
    would let anything that can write next to a skill blind the scanner for it.
    """
    path = (root if root.is_dir() else root.parent) / IGNORE_NAME
    if not path.exists():
        return {}
    ignores = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        rule_id, _, reason = line.partition(" ")
        if reason.strip():
            ignores[rule_id] = reason.strip()
    return ignores


def classify_provenance_file(path: Path) -> str | None:
    """signature | attestation | key | manifest, or None.

    A certificate is not a signature and a plugin manifest is not a checksum
    file. Both used to be reported as provenance, which is worse than reporting
    none: it tells you something was verified when nothing was.
    """
    name = path.name.lower()
    if any(part in name for part in ATTESTATION_PARTS):
        return "attestation"
    if path.suffix.lower() in SIGNATURE_SUFFIXES or name in SIGNATURE_NAMES:
        return "signature"
    if path.suffix.lower() in KEY_MATERIAL_SUFFIXES or name == "cosign.pub":
        return "key"
    if name in MANIFEST_NAMES:
        try:
            if SHA256_RE.search(path.read_text(encoding="utf-8", errors="replace")[:200_000]):
                return "manifest"
        except OSError:
            return None
    return None


def check_provenance(root: Path) -> dict:
    """Walk the same tree the scanner walks, so results cannot disagree."""
    base = root if root.is_dir() else root.parent
    found: dict[str, list[str]] = {"signature": [], "attestation": [], "key": [], "manifest": []}
    for path in iter_files(base):
        kind = classify_provenance_file(path)
        if kind:
            found[kind].append(relative_name(base, path))

    if found["signature"] or found["attestation"]:
        state = "signed"
    elif found["manifest"]:
        state = "hashed"
    else:
        state = "none"
    return {
        "state": state,
        "signatures": sorted(found["signature"] + found["attestation"]),
        "manifests": sorted(found["manifest"]),
        "keys_without_signatures": sorted(found["key"]) if state == "none" else [],
    }


def decide(report: dict) -> str:
    severities = {f["severity"] for f in report["findings"]}
    if report["trifecta"] or "critical" in severities:
        return "stop"
    if "high" in severities:
        return "review"
    # Nothing was read, so nothing was cleared. An empty directory, a mistyped
    # path and a folder of binaries all land here, and all three would otherwise
    # come back "no flagged patterns found" with exit 0 -- a green light from a
    # scan that never happened. It sits above read-it because a result nobody
    # can rely on is worse than a result that merely reaches the network.
    if report["files_scanned"] == 0:
        return "nothing-read"
    if "medium" in severities or report["external_hosts"] or len(report["legs_present"]) >= 2:
        return "read-it"
    return "ok"


# -------------------------------------------------------------------- output

VERDICT_TEXT = {
    "stop": ("STOP", "Do not install this until someone explains it."),
    "review": ("REVIEW", "Read the flagged lines yourself before installing."),
    "nothing-read": ("NOTHING READ", "No file here could be read. This is not a clean result, it is no result."),
    "read-it": ("READ IT", "Nothing alarming, but it reaches outside your machine."),
    "ok": ("LOOKS PLAIN", "No outbound reach and no flagged patterns found."),
}
COLORS = {
    "stop": "\033[31m",
    "review": "\033[33m",
    "nothing-read": "\033[33m",
    "read-it": "\033[36m",
    "ok": "\033[32m",
}
SEV_MARK = {"critical": "!!", "high": "! ", "medium": "~ ", "low": ". "}


def render(report: dict, color: bool) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}\033[0m" if color else text

    verdict = report["verdict"]
    label, advice = VERDICT_TEXT[verdict]
    unread = len(report["files_unread"])
    dropped = len(report.get("files_dropped", []))
    tally = f"  {report['files_scanned']} files read, {report['files_hashed']} hashed"
    if unread:
        tally += f", {unread} too large to read"
    if dropped:
        tally += f", {dropped} could not be read at all"
    out = [
        "",
        f"  trust-me-bro  {report['target']}",
        tally,
        "",
        f"  {paint(label, COLORS[verdict])}  {advice}",
        "",
    ]

    legs = report["legs_present"]
    # "not seen" is a claim about text that was read. With nothing read it would
    # be a claim about nothing, which is the reassurance this tool must not give.
    absent = "not seen" if verdict != "nothing-read" else "nothing read"
    out.append("  Lethal trifecta")
    for leg in ("private", "untrusted", "exfil"):
        mark = "x" if leg in legs else " "
        detail = ", ".join(sorted({e["title"] for e in report["legs"][leg]})[:3]) or absent
        out.append(f"    [{mark}] {LEG_LABEL[leg]:<18} {detail}")
    if report["trifecta"]:
        out.append(
            paint("    all three legs present: this skill can read your secrets, be told what to do", COLORS["stop"])
        )
        out.append(paint("    by someone else, and send the result away", COLORS["stop"]))
    out.append("")

    prov = report["provenance"]
    if prov["state"] == "signed":
        out.append(f"  Provenance      signed ({', '.join(prov['signatures'][:3])})")
        out.append("                  the signature exists; verifying it is a separate step")
    elif prov["state"] == "hashed":
        out.append(f"  Provenance      hashes only, no signature ({', '.join(prov['manifests'][:3])})")
    else:
        out.append("  Provenance      none: unsigned, unattested, no publisher identity")
        if prov["keys_without_signatures"]:
            out.append(
                f"                  ships key material but nothing signed: {', '.join(prov['keys_without_signatures'][:3])}"
            )
    out.append("")

    if report["findings"]:
        out.append("  Findings")
        for finding in report["findings"]:
            mark = SEV_MARK[finding["severity"]]
            out.append(f"    {mark} {finding['id']}  {finding['title']}")
            if finding["hits"]:
                for hit in finding["hits"]:
                    note = "  (padding compressed)" if hit.get("compressed") else ""
                    out.append(f"         {finding['file']}:{hit['line']}  {hit['text']}{note}")
            elif finding["file"] != "-":
                out.append(f"         {finding['file']}")
            out.append(f"         why: {finding['why']}")
        out.append("")

    if report["mentions"]:
        titles = sorted({m["title"] for m in report["mentions"]})
        out.append(f"  Mentioned in prose only, not counted: {', '.join(titles[:6])}")
        out.append("")

    if report["external_hosts"]:
        out.append("  Talks to")
        for host, count in list(report["external_hosts"].items())[:12]:
            out.append(f"    {host}  ({count})")
        out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------- lock


def lock_path(root: Path) -> Path:
    return (root if root.is_dir() else root.parent) / LOCK_NAME


def write_lock(root: Path, report: dict) -> Path:
    path = lock_path(root)
    payload = {
        "approved_verdict": report["verdict"],
        "files": {k: v for k, v in sorted(report["digests"].items()) if k != LOCK_NAME},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def check_lock(root: Path, report: dict) -> tuple[int, str]:
    path = lock_path(root)
    if not path.exists():
        return 2, f"no {LOCK_NAME} here. Run --pin first to record what you approved."
    approved = json.loads(path.read_text(encoding="utf-8"))["files"]
    current = {k: v for k, v in report["digests"].items() if k != LOCK_NAME}
    added = sorted(set(current) - set(approved))
    removed = sorted(set(approved) - set(current))
    changed = sorted(k for k in set(approved) & set(current) if approved[k] != current[k])
    if not (added or removed or changed):
        return 0, "unchanged since you approved it."
    lines = ["changed since you approved it:"]
    lines += [f"    changed  {name}" for name in changed]
    lines += [f"    added    {name}" for name in added]
    lines += [f"    removed  {name}" for name in removed]
    lines.append("  Re-read it. You approved a different version.")
    return 1, "\n  ".join(lines)


# ---------------------------------------------------------------------- main

EXIT = {"stop": 2, "review": 1, "nothing-read": 1, "read-it": 0, "ok": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit an agent skill or plugin before installing it.")
    parser.add_argument("target", help="path to a skill directory or a single file")
    parser.add_argument("--version", action="version", version=f"trust-me-bro {__version__}")
    parser.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--pin", action="store_true", help=f"write {LOCK_NAME} recording the version you approved")
    mode.add_argument("--check", action="store_true", help=f"compare against {LOCK_NAME} and report drift")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    # resolve() dereferences the last component, so this has to run first. A
    # skill can ship `SKILL.md -> ~/.aws/credentials`, and the single-file
    # invocation is the one the README puts in front of people. Resolving it
    # would read and print the target's contents, which is exactly the failure
    # the walk's own symlink handling exists to prevent.
    named = Path(args.target)
    named_link = None
    if named.is_symlink():
        named_link = os.readlink(named)
        if not named.is_dir():
            # A single file reached through a link is the attack: the report
            # would quote lines from whatever it points at. Nothing legitimate
            # needs it, unlike a skills directory linked to a dotfiles checkout,
            # which is how most people install skills and is followed below.
            print(f"trust-me-bro: {args.target} is a symlink to {named_link}.", file=sys.stderr)
            print("  Not following it. Point at the real file if that is what you meant.", file=sys.stderr)
            return 3

    root = named.resolve()
    if not root.exists():
        print(f"trust-me-bro: no such path: {root}", file=sys.stderr)
        return 3

    try:
        rules = load_rules()
    except (OSError, json.JSONDecodeError, re.error) as error:
        print(f"trust-me-bro: cannot load rules: {error}", file=sys.stderr)
        return 3

    report = scan(root, rules, named_link=named_link)
    report["verdict"] = decide(report)

    if args.check:
        code, message = check_lock(root, report)
        if args.as_json:
            print(
                json.dumps(
                    {"target": str(root), "drift": code != 0, "status": code, "message": message},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"\n  trust-me-bro  {root}\n  {message}\n")
        return code

    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        color = not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        print(render(report, color))

    if args.pin:
        path = write_lock(root, report)
        if not args.as_json:
            print(f"  pinned {len(report['digests'])} files to {path.name}\n")

    return EXIT[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
