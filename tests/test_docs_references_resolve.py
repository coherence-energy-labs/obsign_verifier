"""A normative pointer that points at nothing is worse than no pointer.

`canonical.py` said "Canonical JSON exactly as docs/SPEC.md defines it" for the whole
life of this package, and `docs/SPEC.md` did not exist. That sentence is not a comment:
it is the source telling a reimplementer where the rule lives, and it sent them
nowhere. `rust/README.md` records the cost -- the third implementation had to read
`src/obsign_verify/*.py` for thirteen separate rules because the documents did not say.

So every `docs/<Name>.md` written anywhere in the source, the documents or the READMEs
must resolve to a file that is actually in the repository, and every `#anchor` on one
of those links must resolve to a heading that is actually in that file. Both halves can
fail and both halves can pass, which is the only kind of check worth having: a dangling
link is a red test, and a section link that survives a heading rename is not silently
allowed to rot into a link to the top of the page.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Where a normative pointer may be written. `src/`, `js/src/` and `rust/src/` are the
#: three implementations; `docs/` and the READMEs are what a stranger reads first.
SCAN_ROOTS = ("src", "js/src", "rust/src", "docs", ".github")
SCAN_FILES = ("README.md", "js/README.md", "rust/README.md")

#: Build artifacts and caches. A generated file's references are not authored, and a
#: `.pyc` is not text.
SKIP_PARTS = {"__pycache__", "node_modules", "target", ".git", ".pytest_cache"}
SKIP_SUFFIX_DIRS = (".egg-info",)

#: `docs/NAME.md`, optionally followed by a GitHub-style `#anchor`.
REFERENCE = re.compile(r"docs/([A-Za-z0-9_.-]+\.md)(#[A-Za-z0-9_-]+)?")

#: A markdown ATX heading, with its level.
HEADING = re.compile(r"(?m)^(#{1,6})\s+(.*?)\s*$")

#: A markdown link into the SAME document: `[text](#anchor)`.
SAME_DOC_LINK = re.compile(r"\]\(#([A-Za-z0-9_-]+)\)")


def _skip(path: Path) -> bool:
    parts = path.relative_to(ROOT).parts
    if any(p in SKIP_PARTS for p in parts):
        return True
    return any(p.endswith(SKIP_SUFFIX_DIRS) for p in parts)


def _text_files():
    seen = set()
    for rel in SCAN_ROOTS:
        base = ROOT / rel
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and not _skip(path):
                seen.add(path)
    for rel in SCAN_FILES:
        path = ROOT / rel
        if path.is_file():
            seen.add(path)
    return sorted(seen)


def _read_text(path: Path) -> str | None:
    raw = path.read_bytes()
    if b"\x00" in raw[:8192]:
        return None                      # a compiled artifact, not a document
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _headings(text: str) -> list[str]:
    """Every ATX heading OUTSIDE a fenced code block.

    A bare `# pass 1 -- the per-input verdict` inside a ``` fence is a comment in
    pseudocode, not a heading, and no anchor points at it. Counting it would let a
    dangling link resolve against a code comment -- a check that passes for the wrong
    reason is worse than one that fails.
    """
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```") or line.lstrip().startswith("~~~"):
            fenced = not fenced
            continue
        if fenced:
            continue
        m = HEADING.match(line)
        if m:
            out.append(m.group(2))
    return out


def _slug(heading: str) -> str:
    """GitHub's heading slug, closely enough for a link inside this repository.

    Code ticks, asterisks and tildes are dropped, everything that is not a letter,
    digit, space, hyphen or underscore is removed, and spaces become hyphens.
    Underscores SURVIVE, because GitHub's slugger keeps them -- a heading named after
    a field like `tau_field_fixed` must anchor the same way here and there, or this
    check would go green on links a reader clicks and lands at the top of the page.
    """
    text = re.sub(r"[`*~]", "", heading).strip().lower()
    text = re.sub(r"[^a-z0-9 \-_]", "", text)
    # ONE hyphen per space character, not per RUN of them. GitHub does not collapse
    # them, so a heading whose punctuation left a double space anchors with a double
    # hyphen -- and a slugger that collapsed it would call a working link broken and
    # a broken one working.
    return re.sub(r"\s", "-", text).strip("-")


def _collect():
    """Every (source file, line, target, anchor) reference in the scanned tree."""
    found = []
    for path in _text_files():
        text = _read_text(path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in REFERENCE.finditer(line):
                anchor = (m.group(2) or "")[1:]
                found.append((path.relative_to(ROOT).as_posix(), lineno,
                              m.group(1), anchor))
    return found


def test_the_scan_actually_finds_references():
    """A resolver that scanned nothing would pass forever."""
    found = _collect()
    assert len(found) >= 15, (
        f"only {len(found)} docs/*.md reference(s) found across {SCAN_ROOTS} and "
        f"{SCAN_FILES} -- the scan is not reaching the tree it is supposed to check")
    targets = {t for _, _, t, _ in found}
    assert len(targets) >= 3, f"only {sorted(targets)} referenced; the scan is too narrow"


def test_every_docs_reference_resolves_to_a_file():
    dangling = []
    for source, lineno, target, _ in _collect():
        if not (ROOT / "docs" / target).is_file():
            dangling.append(f"{source}:{lineno} -> docs/{target}")
    assert not dangling, (
        "normative pointers that resolve to nothing:\n  " + "\n  ".join(sorted(dangling)))


def test_every_section_link_resolves_to_a_heading():
    """`docs/SPEC.md#the-wire-contract` must name a heading that exists there."""
    anchors: dict[str, set[str]] = {}
    broken = []
    checked = 0
    for source, lineno, target, anchor in _collect():
        if not anchor:
            continue
        checked += 1
        doc = ROOT / "docs" / target
        if not doc.is_file():
            continue                      # reported by the test above
        if target not in anchors:
            text = doc.read_text(encoding="utf-8")
            anchors[target] = {_slug(h) for h in _headings(text)}
        if anchor.lower() not in anchors[target]:
            broken.append(f"{source}:{lineno} -> docs/{target}#{anchor}")
    assert not broken, (
        "section links pointing at headings that do not exist:\n  "
        + "\n  ".join(sorted(broken)))
    # The whole audit-row closure in rust/README.md is section links into docs/SPEC.md.
    # If none are found, this check went dark rather than green.
    assert checked >= 12, (
        f"only {checked} section link(s) found -- the audit rows point into "
        f"docs/SPEC.md by section, and a resolver that sees none is not a check")


def test_every_internal_section_link_resolves():
    """`[Conformance](#conformance)` inside a document must name one of its headings.

    A cross-document link that dangles is a 404 a reader notices. A SAME-document
    anchor that dangles silently lands them at the top of the page, which reads as
    working -- so the navigation of the one document a reimplementer works from is held
    to the same standard as the pointers into it.
    """
    broken = []
    checked = 0
    for path in sorted((ROOT / "docs").rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        anchors = {_slug(h) for h in _headings(text)}
        rel = path.relative_to(ROOT).as_posix()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for anchor in SAME_DOC_LINK.findall(line):
                checked += 1
                if anchor.lower() not in anchors:
                    broken.append(f"{rel}:{lineno} -> #{anchor}")
    assert not broken, (
        "internal links pointing at headings that do not exist:\n  "
        + "\n  ".join(sorted(broken)))
    assert checked >= 20, (
        f"only {checked} internal link(s) found across docs/ -- docs/SPEC.md navigates "
        f"by section, and a resolver that sees none is not a check")
