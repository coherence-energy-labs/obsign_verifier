"""Scan commit MESSAGES for credentials. Not files -- messages.

WHY THIS EXISTS

On 2026-08-01 a live ANTHROPIC_API_KEY reached this repository's history, and every
scanner we had walked straight past it. The key was never in a file. It was in a
commit message.

The mechanism is worth writing down because it will happen again to someone. A commit
message was authored through an UNQUOTED bash heredoc containing the literal text:

    and recording `env` must not move the receipt hash

Backticks inside an unquoted heredoc are command substitution. Bash ran `env` and
spliced ~100 lines of environment -- session id, machine name, PATH, and the API key --
into the middle of that sentence. The commit was pushed. `git grep` across every commit
found nothing, because `git grep` searches trees. Nothing was wrong with any file.

TWO RULES FALL OUT OF THAT

1. A guard must read what the consumer reads. GitHub stores and serves the message, so
   the guard reads `git log --format=%B`, which is exactly those bytes.

2. Never author a commit message through an unquoted heredoc. Quote the delimiter
   (<<'EOF') or pass -F a file. This gate cannot enforce that, so it catches the result.

FAIL-CLOSED. Scanning zero commits must not read as success -- an assertion over an
empty set passes for any input. If the range resolves to nothing, that is an error.

    python tools/check_commit_messages.py               # everything reachable from HEAD
    python tools/check_commit_messages.py --range A..B  # a push range, for CI
    python tools/check_commit_messages.py --self-test   # prove the detector can say NO
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# Credential shapes. Each is a prefix a vendor actually issues, so a hit is a real
# finding rather than an entropy guess -- this gate is meant to be trusted enough that
# a red run stops a push, and a detector that cries wolf is one people learn to skip.
CREDENTIAL_PATTERNS: list[tuple[str, str]] = [
    (r"sk-ant-api\d{2}-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI-style API key"),
    (r"ghp_[A-Za-z0-9]{36,}", "GitHub personal access token"),
    (r"gho_[A-Za-z0-9]{36,}", "GitHub OAuth token"),
    (r"github_pat_[A-Za-z0-9_]{50,}", "GitHub fine-grained PAT"),
    (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}", "PyPI upload token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack token"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "private key block"),
]

# The environment-dump signature. This is the class that actually bit us, and it is
# worth catching even when the dump happens to contain no credential today -- an env
# dump in a message is always an accident, and the next one may not be so lucky.
ENV_DUMP_PATTERNS: list[tuple[str, str]] = [
    (r"^[A-Z_][A-Z0-9_]*=.*\n^[A-Z_][A-Z0-9_]*=", "shell environment dump (>=2 VAR= lines)"),
    (r"CLAUDE_CODE_SESSION_ID=", "agent session id"),
    (r"ANTHROPIC_API_KEY=", "credential-shaped assignment"),
    (r"AWS_SECRET_ACCESS_KEY=", "credential-shaped assignment"),
]


def _git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if proc.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed:\n{proc.stderr.strip()}")
    return proc.stdout


def commits_in(rev_range: str) -> list[str]:
    # NO `--no-walk`. The first cut of this function used it for single-rev arguments,
    # so the default invocation resolved `HEAD` to exactly ONE commit and then printed
    # "clean" -- having read 1 message out of 11. A gate that scans the tip and reports
    # on the history is worse than no gate, because it is believed.
    #
    # Plain `rev-list` walks ancestors for a single rev and honours A..B for a range,
    # which is both behaviours we want. The printed count is what exposed this; it stays
    # in the output so the next person can see the gate's reach rather than assume it.
    out = _git("rev-list", "--topo-order", rev_range)
    return [line for line in out.split() if line]


def scan(rev_range: str) -> int:
    shas = commits_in(rev_range)

    # An empty range is not a pass. It is a broken invocation, and treating it as green
    # is how a gate becomes decorative.
    if not shas:
        print(f"FAIL: '{rev_range}' resolved to zero commits -- nothing was scanned.")
        return 2

    findings: list[str] = []
    for sha in shas:
        message = _git("log", "-1", "--format=%B", sha)
        subject = message.splitlines()[0] if message.strip() else "(empty)"
        for pattern, label in CREDENTIAL_PATTERNS + ENV_DUMP_PATTERNS:
            if re.search(pattern, message, re.MULTILINE):
                findings.append(f"  {sha[:12]}  {label}\n      in: {subject[:70]}")

    print(f"scanned {len(shas)} commit message(s) in '{rev_range}'")
    if findings:
        print(f"\nFAIL: credential-shaped content in {len(findings)} commit message(s):\n")
        print("\n".join(findings))
        print(
            "\nThe value is already on the server; rewriting history does NOT unpublish it.\n"
            "Rotate the credential first, then scrub the message."
        )
        return 1

    print("clean -- no credential or environment dump in any message.")
    return 0


def self_test() -> int:
    """Prove the detector can say NO. A scanner never shown a positive is a scanner
    whose green result means nothing."""
    must_catch = [
        ("sk-ant-api03-" + "A" * 40, "Anthropic key"),
        ("ghp_" + "b" * 36, "GitHub PAT"),
        ("AKIA" + "C" * 16, "AWS key id"),
        ("PATH=/usr/bin\nSHELL=/bin/bash\n", "env dump"),
        ("ANTHROPIC_API_KEY=redacted", "credential-shaped assignment"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private key"),
    ]
    must_pass = [
        "fix(core): handle the empty range\n\nCo-Authored-By: someone <a@b.c>",
        "docs: explain why `env` output must not move the receipt hash",
        "chore: bump numpy>=1.24 and note sk- prefixes are not matched bare",
    ]

    every = CREDENTIAL_PATTERNS + ENV_DUMP_PATTERNS
    failures = []
    for sample, label in must_catch:
        if not any(re.search(p, sample, re.MULTILINE) for p, _ in every):
            failures.append(f"MISSED a real positive: {label}")
    for sample in must_pass:
        hit = [lbl for p, lbl in every if re.search(p, sample, re.MULTILINE)]
        if hit:
            failures.append(f"FALSE POSITIVE on an ordinary message ({hit}): {sample[:50]!r}")

    if failures:
        print("self-test FAILED:\n  " + "\n  ".join(failures))
        return 1
    print(
        f"self-test passed: {len(must_catch)} known-bad messages caught, "
        f"{len(must_pass)} ordinary messages left alone."
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--range", default="HEAD", help="git rev-range (default: HEAD)")
    ap.add_argument("--self-test", action="store_true", help="prove the detector can say no")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return scan(args.range)


if __name__ == "__main__":
    sys.exit(main())
