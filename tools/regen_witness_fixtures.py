"""Regenerate `js/test/fixtures/witness_corpus.json` from the live Python producer.

The fixtures carry a corpus of witness documents AND Python's verdicts on them, so the
JavaScript port can be checked in CI where the coherence_compute producer checkout does
not exist. Without them that check SKIPS, and a skip is never a pass.

THE BYTE DIFF IS ALWAYS TOTAL, so do not read it. Every regeneration mints fresh keys,
timestamps and temp paths, so signatures and hashes change wholesale even when nothing
about the behaviour did. A tool that shouts CHANGED on every run is one nobody reads, so
this compares the VERDICT SHAPE instead -- per case, the answers that do not depend on
which key signed or when -- and reports only real drift.

When it does report drift: a fixture regenerated to make a test go green is how a
regression becomes the expected answer. Say which behaviour changed and why that is
correct before committing it.

    python tools/regen_witness_fixtures.py
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
PRODUCER = Path(r"C:\Users\Josh\Projects\coherence_compute")
OUT = HERE / "js" / "test" / "fixtures" / "witness_corpus.json"

COMMENT = (
    "FROZEN CORPUS + PYTHON VERDICTS. The live cross-implementation differential "
    "(tests/test_the_two_ports_agree_about_a_witness.py) needs the coherence_compute "
    "producer checkout, which CI does not have -- so there it SKIPS, and a skip is "
    "never a pass. These fixtures let the JS port be checked against Python's actual "
    "answers anywhere, with no producer present. Regenerate with "
    "tools/regen_witness_fixtures.py; test_the_frozen_fixtures_still_match_live_python "
    "fails if they go stale."
)


def _shape(verdicts: dict) -> dict:
    """The part of a verdict that does NOT depend on which key signed, or when.

    Chain node maps are keyed by receipt hash, which changes on every regeneration, so
    the nodes reduce to a SORTED multiset of their answers. What survives is exactly
    what a behavioural drift would show up in.
    """
    out = {}
    for name, v in verdicts.items():
        if v.get("kind") == "single":
            out[name] = {k: v.get(k) for k in
                         ("kind", "verified", "integrity", "reproduced",
                          "assurance", "derived", "signature_valid")}
        else:
            out[name] = {
                "kind": v.get("kind"), "ok": v.get("ok"),
                # `complete` is a verdict field, not bookkeeping: a chain is only
                # verified when nothing referenced is missing, because withholding a
                # weaker parent is how a chain is made to look stronger. Leaving it out
                # of the shape would let exactly that regression pass unreported.
                # `missing` is COUNTED rather than listed -- the hashes change on every
                # regeneration, so listing them would reintroduce the churn this
                # function exists to filter out.
                "complete": v.get("complete"),
                "missing_count": len(v.get("missing") or []),
                "effective_assurance": v.get("effective_assurance"),
                "nodes": sorted(
                    (str(n.get("verified")), str(n.get("links_ok")),
                     str(n.get("assurance")))
                    for n in (v.get("nodes") or {}).values()),
            }
    return out


def main() -> int:
    if not PRODUCER.is_dir():
        print(f"error: producer checkout not found at {PRODUCER}", file=sys.stderr)
        return 2
    sys.path.insert(0, str(PRODUCER))

    spec = importlib.util.spec_from_file_location(
        "diff", HERE / "tests" / "test_the_two_ports_agree_about_a_witness.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    tmp = Path(tempfile.mkdtemp())
    cases = m._corpus(tmp)
    verdicts = m._python_verdicts(cases)

    before = None
    if OUT.is_file():
        try:
            before = _shape(json.loads(OUT.read_text(encoding="utf-8"))["python_verdicts"])
        except (json.JSONDecodeError, KeyError, TypeError):
            before = None
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(
        {"_comment": COMMENT, "cases": cases, "python_verdicts": verdicts}, indent=2),
        encoding="utf-8")

    singles = {n: v for n, v in verdicts.items() if v["kind"] == "single"}
    print(f"wrote {OUT}")
    print(f"  cases  : {len(cases)}")
    print(f"  rungs  : {sorted({v['derived'] for v in singles.values()})}")
    print(f"  verify : {sum(1 for v in singles.values() if v['verified'])} pass, "
          f"{sum(1 for v in singles.values() if not v['verified'])} fail")
    after = _shape(verdicts)
    if before is not None and before != after:
        print("\nTHE VERDICTS MOVED -- real drift, not the usual key/timestamp churn:")
        for name in sorted(set(before) | set(after)):
            if before.get(name) != after.get(name):
                print(f"  {name}")
                print(f"    was: {before.get(name)}")
                print(f"    now: {after.get(name)}")
        print("\nSay which behaviour changed and why it is correct before committing.")
    elif before is not None:
        print("\nverdict shapes unchanged (the byte diff is key/timestamp churn only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
