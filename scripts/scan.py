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

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.json"
LOCK_NAME = ".trustmebro.lock"
IGNORE_NAME = ".trustmebro.ignore"

TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".py", ".sh", ".bash", ".zsh", ".fish",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".jsonc",
    ".yaml", ".yml", ".toml", ".rb", ".go", ".rs", ".ps1", ".bat", ".cmd",
    ".env", ".cfg", ".ini", ".conf", ".xml", ".html",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache"}
MAX_BYTES = 2_000_000

SIGNATURE_GLOBS = ["*.sig", "*.asc", "*.pem", "*.bundle", "*.intoto.jsonl", "*.sigstore", "cosign.pub", "*.att"]
MANIFEST_NAMES = {"manifest.yaml", "manifest.yml", "manifest.json", "sha256sums", "sha256sum.txt", "checksums.txt", LOCK_NAME}

URL_RE = re.compile(r"https?://([a-zA-Z0-9._-]+)")
# "Never use sudo" should not be reported as using sudo. Applied only to rules
# marked negation_safe, because some rules are themselves about negative phrasing.
NEGATION_RE = re.compile(r"\b(never|do not|don't|dont|avoid|refuse to|must not|no need to|instead of|rather than|without)\b[^.;]{0,40}$", re.IGNORECASE)
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


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.resolve() == RULES_PATH or name in (LOCK_NAME, IGNORE_NAME):
                continue  # the detector's own bookkeeping is not a target
            if path.suffix.lower() in TEXT_SUFFIXES or name.lower() in MANIFEST_NAMES or not path.suffix:
                yield path


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def trim(line: str, limit: int = 120) -> str:
    line = line.strip()
    return line if len(line) <= limit else line[: limit - 1] + "…"


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


def scan(root: Path, rules: dict) -> dict:
    findings: list[dict] = []
    mentions: list[dict] = []
    legs: dict[str, list[dict]] = {"private": [], "untrusted": [], "exfil": []}
    hosts: dict[str, int] = {}
    digests: dict[str, str] = {}
    seen_allowed_tools = False
    scanned = 0

    allowlist = set(rules["host_allowlist"])

    for path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        scanned += 1
        rel = str(path.relative_to(root)) if root.is_dir() else path.name
        digests[rel] = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

        if re.search(r"^\s*allowed[-_]tools\s*:", text, re.IGNORECASE | re.MULTILINE):
            seen_allowed_tools = True

        for host in URL_RE.findall(text):
            if host not in allowlist:
                hosts[host] = hosts.get(host, 0) + 1

        lines = text.splitlines()
        mask = code_mask(path, lines)

        for entry in rules["legs"]:
            # Legs are capability claims, so "never read ~/.ssh" is not a claim.
            hits = match_lines(entry["_re"], lines, mask=mask, negation_safe=True)
            code_hits = [h for h in hits if h["context"] == "code"]
            if code_hits:
                legs[entry["leg"]].append({"id": entry["id"], "title": entry["title"], "file": rel, "hits": code_hits})
            elif hits:
                mentions.append({"id": entry["id"], "title": entry["title"], "file": rel, "hits": hits[:1]})

        for entry in rules["rules"]:
            if entry["_re"] is None:
                continue
            hits = match_lines(entry["_re"], lines, mask=mask, negation_safe=entry.get("negation_safe", False))
            if not hits:
                continue
            # For injection and permission rules the prose *is* the payload: a
            # skill is instructions, so a sentence aimed at the agent runs.
            prose_only = not entry.get("prose_is_code") and all(h["context"] == "prose" for h in hits)
            findings.append({
                "id": entry["id"],
                "severity": demote(entry["severity"]) if prose_only else entry["severity"],
                "title": entry["title"] + (" (described, not run)" if prose_only else ""),
                "why": entry["why"],
                "file": rel,
                "hits": hits,
            })

    if not seen_allowed_tools and scanned:
        meta = next(e for e in rules["rules"] if e["id"] == "META-NO-ALLOWED-TOOLS")
        findings.append({
            "id": meta["id"], "severity": meta["severity"], "title": meta["title"],
            "why": meta["why"], "file": "-", "hits": [],
        })

    ignored = load_ignores(root)
    if ignored:
        findings = [f for f in findings if f["id"] not in ignored]
        for leg in legs:
            legs[leg] = [e for e in legs[leg] if e["id"] not in ignored]

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"], f["file"]))
    present = [leg for leg in ("private", "untrusted", "exfil") if legs[leg]]

    return {
        "target": str(root),
        "files_scanned": scanned,
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


def match_lines(pattern: re.Pattern, lines: list[str], mask: list[bool],
                cap: int = 3, negation_safe: bool = False) -> list[dict]:
    hits = []
    for index, line in enumerate(lines):
        match = pattern.search(line)
        if not match:
            continue
        if negation_safe and NEGATION_RE.search(line[: match.start()]):
            continue
        is_code = mask[index] or in_inline_code(line, match.start())
        hits.append({"line": index + 1, "text": trim(line), "context": "code" if is_code else "prose"})
        if len(hits) == cap and any(h["context"] == "code" for h in hits):
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


def check_provenance(root: Path) -> dict:
    if root.is_file():
        root = root.parent
    signatures, manifests = [], []
    for pattern in SIGNATURE_GLOBS:
        signatures += [str(p.relative_to(root)) for p in root.rglob(pattern) if p.is_file()]
    for path in root.rglob("*"):
        if path.is_file() and path.name.lower() in MANIFEST_NAMES:
            manifests.append(str(path.relative_to(root)))
    if signatures:
        state = "signed"
    elif manifests:
        state = "hashed"
    else:
        state = "none"
    return {"state": state, "signatures": sorted(set(signatures)), "manifests": sorted(set(manifests))}


def decide(report: dict) -> str:
    severities = {f["severity"] for f in report["findings"]}
    if report["trifecta"] or "critical" in severities:
        return "stop"
    if "high" in severities:
        return "review"
    if "medium" in severities or report["external_hosts"] or len(report["legs_present"]) >= 2:
        return "read-it"
    return "ok"


# -------------------------------------------------------------------- output

VERDICT_TEXT = {
    "stop": ("STOP", "Do not install this until someone explains it."),
    "review": ("REVIEW", "Read the flagged lines yourself before installing."),
    "read-it": ("READ IT", "Nothing alarming, but it reaches outside your machine."),
    "ok": ("LOOKS PLAIN", "No outbound reach and no flagged patterns found."),
}
COLORS = {"stop": "\033[31m", "review": "\033[33m", "read-it": "\033[36m", "ok": "\033[32m"}
SEV_MARK = {"critical": "!!", "high": "! ", "medium": "~ ", "low": ". "}


def render(report: dict, color: bool) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}\033[0m" if color else text

    verdict = report["verdict"]
    label, advice = VERDICT_TEXT[verdict]
    out = [
        "",
        f"  trust-me-bro  {report['target']}",
        f"  {report['files_scanned']} files read",
        "",
        f"  {paint(label, COLORS[verdict])}  {advice}",
        "",
    ]

    legs = report["legs_present"]
    out.append("  Lethal trifecta")
    for leg in ("private", "untrusted", "exfil"):
        mark = "x" if leg in legs else " "
        detail = ", ".join(sorted({e["title"] for e in report["legs"][leg]})[:3]) or "not seen"
        out.append(f"    [{mark}] {LEG_LABEL[leg]:<18} {detail}")
    if report["trifecta"]:
        out.append(paint("    all three legs present: this skill can read your secrets, be told what to do", COLORS["stop"]))
        out.append(paint("    by someone else, and send the result away", COLORS["stop"]))
    out.append("")

    prov = report["provenance"]
    if prov["state"] == "signed":
        out.append(f"  Provenance      signed ({', '.join(prov['signatures'][:3])})")
    elif prov["state"] == "hashed":
        out.append(f"  Provenance      hashes only, no signature ({', '.join(prov['manifests'][:3])})")
    else:
        out.append("  Provenance      none: unsigned, unattested, no publisher identity")
    out.append("")

    if report["findings"]:
        out.append("  Findings")
        for finding in report["findings"]:
            mark = SEV_MARK[finding["severity"]]
            out.append(f"    {mark} {finding['id']}  {finding['title']}")
            for hit in finding["hits"]:
                out.append(f"         {finding['file']}:{hit['line']}  {hit['text']}")
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

EXIT = {"stop": 2, "review": 1, "read-it": 0, "ok": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit an agent skill or plugin before installing it.")
    parser.add_argument("target", help="path to a skill directory or a single file")
    parser.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")
    parser.add_argument("--pin", action="store_true", help=f"write {LOCK_NAME} recording the version you approved")
    parser.add_argument("--check", action="store_true", help=f"compare against {LOCK_NAME} and report drift")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.target).resolve()
    if not root.exists():
        print(f"trust-me-bro: no such path: {root}", file=sys.stderr)
        return 3

    report = scan(root, load_rules())
    report["verdict"] = decide(report)

    if args.check:
        code, message = check_lock(root, report)
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
