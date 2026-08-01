#!/usr/bin/env python3
"""The Wave-3 control mapping, as DATA -- and the gate that keeps the doc honest.

PROGRAM.md §4.4: *"Wave 3 -- the people whose job is to say no. Artifacts, not sales
calls: the compliance mapping doc. GRC buys mappings, not cryptography."*

This is the Profile-B (computed claims / replay) mapping. It is a different artifact
from `omega_one`'s, which maps Profile-D decision receipts -- reusing that module here
would map the wrong product, and both would drift.

WHY IT IS A MODULE AND NOT PROSE

The same lesson, twice in one estate: `omega_one`'s hand-written COMPLIANCE.md had
gone stale against its own code, listing neither SOC 2 nor the ISO/IEC 42001 Annex A
controls that existed in the mapping. Derive, never transcribe. The tables in
`docs/COMPLIANCE.md` are rendered from here, and `--check` fails the build if they
disagree.

WHAT THIS MAPPING IS NOT

Technical-evidence mapping to support an audit. **Not a legal compliance
certification, and not advice.** Control identifiers are edition-sensitive: article
numbers, Annex A controls and Trust Services Criteria are cited as of the editions
named below, and an auditor working from a different edition must re-check the
numbering. The mapping's value is the capability-to-requirement argument, which is
stable; the identifier is a pointer, and a pointer can go stale.

    python tools/compliance_map.py            # verify the doc matches
    python tools/compliance_map.py --fix      # regenerate the tables
    python tools/compliance_map.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "COMPLIANCE.md"
BEGIN = "<!-- BEGIN GENERATED: {name} -- edit tools/compliance_map.py, not this block -->"
END = "<!-- END GENERATED: {name} -->"

#: Frameworks, named EXACTLY as they appear in the rendered tables so a reader can
#: grep for the string they see. Editions are parenthetical.
FRAMEWORKS = {
    "EU AI Act": "Reg. (EU) 2024/1689, as amended by the 2026 Digital Omnibus",
    "NIST AI RMF": "1.0",
    "ISO/IEC 42001": "2023",
    "SOC 2": "AICPA Trust Services Criteria",
    "SR 11-7": "Fed/OCC supervisory guidance on model risk management",
}

#: What a REPLAY receipt evidences. The left column is the capability, not the
#: product -- a control is evidenced by a property, and naming the property is what
#: lets an auditor argue it.
CONTROLS = {
    "tamper-evident record of the operation": [
        ("EU AI Act", "Art. 12", "Automatic recording of events over the system's lifetime"),
        ("EU AI Act", "Art. 26(6)", "Deployer retains automatically generated logs"),
        ("NIST AI RMF", "GOVERN 1.5", "Traceability and accountability for system decisions"),
        ("ISO/IEC 42001", "A.6.2.8", "Recording of event logs for AI system operation"),
        ("SOC 2", "CC7.2", "System operation is monitored and anomalies detected"),
        ("SR 11-7", "Documentation", "Audit trail sufficient for independent review"),
    ],
    "independent re-derivation of the claimed value": [
        # The strongest row in the table, and the one worth leading a GRC call with.
        ("SOC 2", "PI1.4", "Output is complete and accurate -- evidenced by re-derivation "
                           "rather than by attestation"),
        ("SR 11-7", "Model Validation", "Results are replicable by a party independent of "
                                        "the model's developer"),
        ("NIST AI RMF", "MEASURE 2.5", "Validity and reliability demonstrated and documented"),
        ("ISO/IEC 42001", "A.6.2.4", "AI system verification and validation of intended behaviour"),
        ("EU AI Act", "Annex IV(2)", "Technical documentation of the system's development "
                                     "and validation"),
    ],
    "exact identification of what produced the value": [
        ("EU AI Act", "Annex IV(1)", "Identification of the AI system and its exact version"),
        ("SR 11-7", "Model Development", "Model versioning bound to each result"),
        ("SOC 2", "PI1.3", "Processing is authorised and attributable to a defined version"),
    ],
    "declared accuracy that can be checked": [
        ("EU AI Act", "Art. 15(1)", "Declared level of accuracy, with the metric stated"),
        ("NIST AI RMF", "MEASURE 2.5", "Uncertainty and performance quantified per claim"),
        ("SR 11-7", "Outcomes Analysis", "Decisions carry a quantified, checkable claim"),
    ],
    "resilience of the record against alteration": [
        ("EU AI Act", "Art. 15(5)", "Cybersecurity; resilience against data or model manipulation"),
        ("NIST AI RMF", "MEASURE 2.7", "Robustness and security of the system evaluated"),
        ("SOC 2", "PI1.5", "Stored output is protected from unauthorised change"),
    ],
}

#: Controls a receipt does NOT address. This list is the reason the rest is credible.
#: Every one of these is process-level or organisational, and a mapping that quietly
#: omitted them would be the kind of overreach that loses an auditor's trust in the
#: rows that ARE evidenced.
NOT_COVERED = [
    ("EU AI Act", "Art. 9", "Risk-management system across the lifecycle (process)"),
    ("EU AI Act", "Art. 10", "Data and data governance; training-data quality and "
                             "representativeness"),
    ("EU AI Act", "Art. 14", "Human oversight design (a computed-claim receipt evidences "
                             "no oversight step)"),
    ("NIST AI RMF", "MEASURE 2.11", "Fairness and harmful-bias evaluation (needs a bias audit)"),
    ("ISO/IEC 42001", "A.5.2", "AI system impact assessment (process-level)"),
    ("ISO/IEC 42001", "A.7.2", "Data governance for AI systems"),
    ("SOC 2", "CC6.x", "Logical access controls over the issuing system (organisational)"),
    ("SOC 2", "CC8.1", "Change management for the model and its deployment (process)"),
    ("SOC 2", "A1.x", "Availability commitments and capacity management (organisational)"),
    ("SR 11-7", "Conceptual Soundness", "Justification of model design and assumptions"),
]


def render_frameworks() -> str:
    rows = ["| Framework | Edition cited |", "|---|---|"]
    rows += [f"| **{k}** | {v} |" for k, v in sorted(FRAMEWORKS.items())]
    return "\n".join(rows)


def render_evidenced() -> str:
    rows = ["| Capability | Framework | Control | Requirement |", "|---|---|---|---|"]
    for cap in sorted(CONTROLS):
        for fw, cid, req in sorted(CONTROLS[cap]):
            rows.append(f"| {cap} | {fw} | `{cid}` | {req} |")
    return "\n".join(rows)


def render_not_covered() -> str:
    rows = ["| Framework | Control | Why a receipt does not address it |", "|---|---|---|"]
    rows += [f"| {fw} | `{cid}` | {why} |" for fw, cid, why in sorted(NOT_COVERED)]
    return "\n".join(rows)


BLOCKS = {"frameworks": render_frameworks,
          "controls-evidenced": render_evidenced,
          "controls-not-covered": render_not_covered}


def _rx(name: str) -> re.Pattern:
    return re.compile(re.escape(BEGIN.format(name=name)) + r"(?P<body>.*?)"
                      + re.escape(END.format(name=name)), re.S)


def apply(text: str, *, fix: bool) -> tuple[str, list[str], list[str]]:
    drifted, unfixable = [], []
    for name, render in BLOCKS.items():
        m = _rx(name).search(text)
        if m is None:
            unfixable.append(f"{name}: marker pair MISSING from docs/COMPLIANCE.md")
            continue
        want = "\n" + render().strip() + "\n"
        if m.group("body").replace("\r\n", "\n") != want:
            drifted.append(f"{name}: table disagrees with tools/compliance_map.py")
            if fix:
                text = text[:m.start("body")] + want + text[m.end("body"):]
    return text, drifted, unfixable


def self_test() -> int:
    """Both directions, plus the two ways this mapping could quietly become dishonest."""
    probes = []
    used = {fw for rows in CONTROLS.values() for fw, _c, _r in rows}
    used |= {fw for fw, _c, _r in NOT_COVERED}
    probes.append(("every framework used is declared with an edition",
                   used <= set(FRAMEWORKS)))
    probes.append(("every declared framework is actually used", set(FRAMEWORKS) <= used))
    # A mapping with no NOT-COVERED rows is advocacy, not a mapping.
    probes.append(("the not-covered list is non-empty", len(NOT_COVERED) >= 5))
    # Each framework must appear in BOTH lists, or it is being oversold.
    evidenced = {fw for rows in CONTROLS.values() for fw, _c, _r in rows}
    uncovered = {fw for fw, _c, _r in NOT_COVERED}
    probes.append(("no framework is claimed without also stating its limits",
                   evidenced <= uncovered))
    # And the gate must refuse a corrupted table.
    if DOC.is_file():
        text = DOC.read_text(encoding="utf-8")
        _, clean, missing = apply(text, fix=False)
        if not clean and not missing:
            tampered = text.replace("| SOC 2 | `PI1.4` |", "| SOC 3 | `PI1.4` |", 1)
            _, drifted, _m = apply(tampered, fix=False)
            probes.append(("a corrupted control table is refused",
                           tampered != text and bool(drifted)))
    for label, ok in probes:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if all(ok for _, ok in probes):
        print("SELF-TEST GREEN - the mapping is internally consistent and the gate can say no.")
        return 0
    print("SELF-TEST FAILED.")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fix", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not DOC.is_file():
        print(f"missing {DOC}", file=sys.stderr)
        return 1
    text = DOC.read_text(encoding="utf-8")
    updated, drifted, unfixable = apply(text, fix=args.fix)
    if unfixable:
        print("COMPLIANCE DOC UNFIXABLE:", *unfixable, sep="\n  ")
        return 1
    if args.fix:
        if updated != text:
            DOC.write_text(updated, encoding="utf-8", newline="")
            print(f"REWROTE {len(drifted)} block(s)")
        else:
            print("docs/COMPLIANCE.md already matches")
        return 0
    if drifted:
        print("COMPLIANCE DOC DRIFT:", *drifted, sep="\n  ")
        return 1
    n = sum(len(v) for v in CONTROLS.values())
    print(f"COMPLIANCE DOC GREEN - {n} evidenced controls across {len(FRAMEWORKS)} "
          f"frameworks, {len(NOT_COVERED)} stated limits, rendered from "
          f"tools/compliance_map.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
