"""Python, JavaScript and Rust must reach the SAME verdict on the same bytes.

WHY A THIRD LEG. `tests/test_replayc_js_parity.py` and `tests/test_graph_fuzz.py`
already hold Python and JavaScript to each other. Both were written by the same author
in the same sitting, so they can share one misreading of the spec and agree perfectly
about it -- and a shared misreading is invisible to any number of two-way differentials.
The Rust crate in `rust/` is a third reading, and it fails DIFFERENTLY: Python and
JavaScript both compute in arbitrary-precision integers (`int`, `BigInt`) and narrow to
int64 with an explicit `wrap`, so a mistake in that shared strategy would be invisible
to both. Rust computes in native `i64`, with `overflow-checks` on.

BE CLEAR ABOUT WHAT THIS DOES NOT ESTABLISH. All three implementations were written by
the same hands. Agreement here is evidence that the spec is unambiguous ENOUGH to be
re-read consistently by one person; it is not the independent third-party review
docs/AUDIT_SCOPE.md asks for, and it must never be cited as one.

KNOWN DIVERGENCES ARE FROZEN, NOT SKIPPED. Every disagreement this harness found is
recorded in `KNOWN_DIVERGENCES` with the side docs/ supports. Each entry is asserted to
STILL diverge, so the day one is fixed this test fails and says the entry is stale --
the freeze runs in both directions, which is the only way a known-issue list stays
honest.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RUST = REPO / "rust"
sys.path.insert(0, str(RUST / "harness"))

import corpus  # noqa: E402

_HAS_NODE = shutil.which("node") is not None
_HAS_CARGO = shutil.which("cargo") is not None
_REQUIRED = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}


# --------------------------------------------------------------------------- runners

def _write_job(cases) -> Path:
    fd, name = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    p = Path(name)
    p.write_text(json.dumps(cases), encoding="utf-8")
    return p


def _run(argv, job: Path) -> dict:
    proc = subprocess.run([*argv, str(job)], capture_output=True, text=True,
                          timeout=1800, check=False)
    if proc.returncode != 0:
        raise AssertionError(f"{argv[0]} failed: {proc.stdout[-4000:]}\n{proc.stderr[-4000:]}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


def js_leg(mode: str, cases) -> dict:
    job = _write_job(cases)
    try:
        return _run(["node", str(RUST / "harness" / "js_runner.mjs"), mode], job)
    finally:
        job.unlink(missing_ok=True)


def rust_leg(mode: str, cases) -> dict:
    job = _write_job(cases)
    try:
        return _run([str(_rust_binary()), "--harness", mode], job)
    finally:
        job.unlink(missing_ok=True)


_BINARY: list[Path] = []


def _rust_binary() -> Path:
    if _BINARY:
        return _BINARY[0]
    exe = RUST / "target" / "release" / "obsign-verify-rs"
    build = subprocess.run(["cargo", "build", "--release", "--offline"], cwd=RUST,
                           capture_output=True, text=True, timeout=900, check=False)
    if not exe.exists():
        raise AssertionError(f"cargo build failed:\n{build.stdout}\n{build.stderr}")
    _BINARY.append(exe)
    return exe


def python_leg(mode: str, cases) -> dict:
    """The reference leg, run in process. Mirrors rust/harness/js_runner.mjs exactly."""
    from obsign_verify.canonical import canonical_bytes, load_receipt
    from obsign_verify.graph import verify_graph
    from obsign_verify import replay as replaymod
    from obsign_verify.verify import verify

    def outputs_of(receipt):
        try:
            params = receipt["params"]
            out = replaymod.run(params["program"], list(params["inputs"]))
            return [str(v) for v in out]
        except Exception:
            return None

    out = {}
    for name, payload in cases:
        if mode == "load":
            try:
                load_receipt(payload)
                out[name] = True
            except Exception:
                out[name] = False
        elif mode == "canon":
            try:
                out[name] = canonical_bytes(load_receipt(payload)).decode("utf-8")
            except Exception:
                out[name] = None
        elif mode == "verify":
            try:
                r = load_receipt(payload)
            except Exception:
                out[name] = {"loaded": False, "verdict": None}
                continue
            v = verify(r)
            s = v.get("signature")
            out[name] = {"loaded": True, "verdict": {
                "integrity": v["integrity"],
                "reproduced": v["reproduced"],
                "verified": v["verified"],
                "input_liveness": v.get("input_liveness"),
                "input_liveness_by_input": v.get("input_liveness_by_input", []),
                "signature": None if s is None else {
                    "present": s["present"], "valid": s["valid"],
                    "identity_bound": s["identity_bound"],
                    "attributed_signer": s["attributed_signer"],
                    "claimed_signer": s["claimed_signer"],
                    "bound_metadata": s["bound_metadata"],
                    "unbound_metadata": s["unbound_metadata"]},
                "output": outputs_of(r),
                "notes": v["notes"]}}
        elif mode == "graph":
            try:
                receipts = [load_receipt(t) for t in payload]
            except Exception:
                out[name] = {"loaded": False}
                continue
            g = verify_graph(receipts)
            out[name] = {
                "loaded": True, "graph_verified": g["graph_verified"],
                "complete": g["complete"], "missing": sorted(g["missing"]),
                "roots": sorted(g["roots"]),
                "nodes": {d: {"verified": n["verified"], "links_ok": n["links_ok"],
                              "envelopes": n["envelopes"]} for d, n in g["nodes"].items()}}
        elif mode == "vm":
            try:
                prog = json.loads(payload["program"])
                inputs = [int(x) for x in payload["inputs"]]
                o = replaymod.run(prog, inputs)
                out[name] = {"ok": True, "out": [str(v) for v in o],
                             "output_sha256": replaymod.output_sha256(o),
                             "program_sha256": replaymod.program_sha256(prog)}
            except replaymod.Trap as t:
                out[name] = {"ok": False, "trap": str(t)}
            except Exception as e:  # a malformed program text is also a refusal
                out[name] = {"ok": False, "trap": f"load: {e}"}
        else:
            raise AssertionError(f"unknown mode {mode}")
    return out


# ------------------------------------------------------------------ known divergences
#
# Each entry is a measured disagreement between the shipped implementations, with the
# reading docs/ supports. They are asserted to STILL diverge: when one is fixed, this
# test fails and tells you the entry is stale. See rust/README.md for the full write-up.

KNOWN_DIVERGENCES: dict[tuple[str, str], str] = {
    # --- what LOADS -------------------------------------------------------------
    ("load", "edge:string-past-limit"):
        "MAX_STRING_BYTES is declared in js/src/canonical.js and never used; Python and "
        "Rust enforce it. JavaScript loads a receipt they refuse.",
    ("load", "edge:key-past-limit"):
        "Same dead constant: the 65536-byte cap on object KEYS is unenforced in "
        "JavaScript.",
    ("load", "edge:lone-high-surrogate"):
        "CPython measures string size with .encode('utf-8'), which RAISES on a lone "
        "surrogate, so Python refuses it -- by accident, not by rule. Rust reproduces "
        "the refusal; JavaScript loads it. docs/ never adjudicates lone surrogates, "
        "though docs/AUDIT_SCOPE.md names them as a target.",
    ("load", "edge:lone-low-surrogate"):
        "As above, for an unpaired low surrogate.",
    # The same five findings surface again in `canon`, which loads before it
    # serialises. Listed per mode rather than inferred, so the stale check runs on each.
    ("canon", "edge:string-past-limit"): "see ('load', 'edge:string-past-limit')",
    ("canon", "edge:key-past-limit"): "see ('load', 'edge:key-past-limit')",
    ("canon", "edge:lone-high-surrogate"): "see ('load', 'edge:lone-high-surrogate')",
    ("canon", "edge:lone-low-surrogate"): "see ('load', 'edge:lone-low-surrogate')",
    ("canon", "edge:depth-33-empty-innermost"): "see ('load', 'edge:depth-33-empty-innermost')",

    ("load", "edge:depth-33-empty-innermost"):
        "MAX_DEPTH means two different things: CPython caps the depth a VALUE sits at "
        "(so an empty container has no member to reject), JavaScript caps how many "
        "containers were opened. 33 containers with an empty innermost loads in "
        "Python and Rust, and is refused in JavaScript.",
    # --- the bare machine, where a digest divergence is separated from a ladder one -
    ("verify", "suspect:output-length-is-json-true"):
        "`True == 1` in Python, so `output.length: true` compares equal to a "
        "one-element output and the reference VERIFIES it. docs/COMPAT.md's own "
        "'structural scalars are JSON integers' refusal says no; JavaScript and Rust "
        "refuse it.",
    ("verify", "suspect:output-length-is-json-float"):
        "The same `in (None, len(out))` membership test: `1.0 == 1` in Python too, so "
        "`output.length: 1.0` VERIFIES in the reference and is refused by the other "
        "two. Two spellings of the same defect, and the reason the fix is a type check "
        "rather than a special case for booleans.",
    ("verify", "sig:sig-member-is-number"):
        "`sig` of the wrong TYPE falls through to the `signature` member in JavaScript "
        "and is a malformed block in Python and Rust.",
    ("verify", "sig:sig-member-is-true"):
        "As above, with a boolean.",
}

# Receipts whose kernel the JavaScript and Rust implementations deliberately do not
# implement. Python re-executes `tau_field_fixed` with numpy; the other two report
# `reproduced: not attempted` and never `verified`. This is documented in both
# READMEs, is not a divergence about the FORMAT, and is asserted rather than skipped.
def _is_non_replay(text: str) -> bool:
    try:
        return json.loads(text).get("kernel") != "obsign/replay/1"
    except ValueError:
        return True


# --------------------------------------------------------------------------- helpers

def _skip_unless_all_three():
    if not _HAS_NODE and "node" not in _REQUIRED:
        pytest.skip("node not installed")
    if not _HAS_CARGO and "rust" not in _REQUIRED:
        pytest.skip("cargo not installed")
    assert _HAS_NODE, "OBSIGN_REQUIRE=node was set but node is not installed"
    assert _HAS_CARGO, "OBSIGN_REQUIRE=rust was set but cargo is not installed"


def _compare(mode: str, cases, project, *, known=KNOWN_DIVERGENCES):
    """Run one corpus through all three legs and require identical projections.

    `project` reduces a leg's raw answer to the part that carries MEANING, so a
    disagreement is reported about a verdict rather than about prose.
    """
    py = python_leg(mode, cases)
    js = js_leg(mode, cases)
    rs = rust_leg(mode, cases)

    disagreements = []
    stale = []
    for name, _ in cases:
        p, j, r = project(py[name]), project(js[name]), project(rs[name])
        agreed = (p == j == r)
        if (mode, name) in known:
            if agreed:
                stale.append(f"{mode}:{name} -- recorded as diverging, now agrees ({p!r})")
            continue
        if not agreed:
            disagreements.append(f"{mode}:{name}\n    python={p!r}\n    javascript={j!r}\n    rust={r!r}")

    assert not disagreements, (
        f"{len(disagreements)} case(s) DIVERGE across implementations. Every one is a "
        f"finding: whichever side the spec does not support can be farmed by a forger "
        f"who hands the receipt to the implementation that accepts it.\n\n"
        + "\n".join(disagreements[:25]))
    assert not stale, (
        "KNOWN_DIVERGENCES is stale -- these now agree, so the entry (and the "
        "corresponding note in rust/README.md) should be removed:\n" + "\n".join(stale))


# ----------------------------------------------------------------------------- tests

def test_the_three_parsers_agree_on_what_loads():
    """Agreement on what a receipt IS, not merely on what a receipt hashes to.

    A document one implementation reads and another refuses is the split that lets a
    forger choose his verifier, and it is the highest-value target named in
    docs/AUDIT_SCOPE.md.
    """
    _skip_unless_all_three()
    cases = (corpus.wire_format_edges() + corpus.committed_receipts()
             + corpus.suspected_divergences() + corpus.signed_cases()
             + corpus.random_receipts(count=60) + corpus.random_live_receipts(count=25))
    _compare("load", cases, lambda v: v)


def test_the_three_canonicalisers_produce_identical_bytes():
    """Byte-for-byte, character for character -- floats included.

    docs/COMPAT.md defines the canonical form as CPython's `json.dumps`, so Python is
    the authority here by construction and the other two are held to it.
    """
    _skip_unless_all_three()
    cases = (corpus.random_canonical_values() + corpus.wire_format_edges()
             + corpus.committed_receipts())
    _compare("canon", cases, lambda v: v)


def test_the_three_machines_agree_value_for_value_and_trap_for_trap():
    """The `obsign/replay/1` contract: same outputs, and the same inputs TRAP.

    Trap-for-trap is part of the contract (docs/AUDIT_SCOPE.md item 3) even though the
    trap's REASON is not, so the projection keeps `ok` and the values and drops the
    message.
    """
    _skip_unless_all_three()
    cases = (corpus.arithmetic_grid_cases()
             + corpus.random_vm_cases()
             + corpus.vm_cases_from_receipts(corpus.committed_receipts())
             + corpus.vm_cases_from_receipts(corpus.suspected_divergences())
             + corpus.vm_cases_from_receipts(corpus.random_receipts()))

    def project(v):
        if not v.get("ok"):
            return ("trap",)
        return ("ok", tuple(v["out"]), v["output_sha256"], v["program_sha256"])

    _compare("vm", cases, project)


def test_the_three_ladders_reach_the_same_verdict():
    """`verified`, and every field a reader would act on."""
    _skip_unless_all_three()
    cases = (corpus.committed_receipts() + corpus.suspected_divergences()
             + corpus.signed_cases() + corpus.random_receipts()
             + corpus.random_live_receipts())
    replay_only = [(n, t) for n, t in cases if not _is_non_replay(t)]

    def project(v):
        if not v["loaded"]:
            return ("not-loaded",)
        d = v["verdict"]
        s = d["signature"] or {}
        return (
            d["verified"],
            d["integrity"],
            # A three-valued `reproduced` is spelled differently in the reference
            # (False for "not attempted") than in the two ports (null). What a reader
            # acts on is whether re-derivation SUCCEEDED, and that is unambiguous.
            d["reproduced"] is True,
            d["input_liveness"],
            tuple(d["input_liveness_by_input"] or ()),
            s.get("present"), s.get("valid"), s.get("identity_bound"),
            s.get("attributed_signer"), tuple(s.get("bound_metadata") or ()),
            tuple(s.get("unbound_metadata") or ()),
            tuple(d["output"]) if d["output"] is not None else None,
        )

    _compare("verify", replay_only, project)


def test_a_kernel_two_of_three_cannot_execute_is_reported_the_same_by_those_two():
    """`tau_field_fixed` is out of scope for JavaScript and Rust, and stays HONEST.

    Neither may report such a receipt verified, and both must say "not attempted"
    rather than "failed": collapsing "I cannot check this" into either pass or fail is
    how a verifier starts lying. Python re-executes it and may legitimately say
    verified -- that difference is about scope, not about the format.
    """
    _skip_unless_all_three()
    cases = [(n, t) for n, t in corpus.committed_receipts() if _is_non_replay(t)]
    if not cases:
        pytest.skip("no non-replay receipts in the corpus")
    js = js_leg("verify", cases)
    rs = rust_leg("verify", cases)
    for name, _ in cases:
        j, r = js[name], rs[name]
        assert j["loaded"] == r["loaded"], name
        if not j["loaded"]:
            continue
        assert j["verdict"]["reproduced"] is None, f"{name}: JavaScript must say NOT ATTEMPTED"
        assert r["verdict"]["reproduced"] is None, f"{name}: Rust must say NOT ATTEMPTED"
        assert j["verdict"]["verified"] is False, f"{name}: JavaScript must not claim verified"
        assert r["verdict"]["verified"] is False, f"{name}: Rust must not claim verified"
        for field in ("integrity",):
            assert j["verdict"][field] == r["verdict"][field], f"{name}: {field}"
        assert (j["verdict"]["signature"] or {}).get("valid") == \
               (r["verdict"]["signature"] or {}).get("valid"), f"{name}: signature validity"


def test_the_three_graph_verifiers_agree_node_for_node():
    """docs/GRAPHS.md's chain rule, including the verdicts it insists stay split."""
    _skip_unless_all_three()
    cases = corpus.graph_cases()
    if not cases:
        pytest.skip("no chain fixtures shipped")

    def project(v):
        if not v.get("loaded"):
            return ("not-loaded",)
        return (v["graph_verified"], v["complete"], tuple(v["missing"]), tuple(v["roots"]),
                tuple(sorted((d, n["verified"], str(n["links_ok"]), n["envelopes"])
                             for d, n in v["nodes"].items())))

    _compare("graph", cases, project)


def test_the_shipped_chain_verifies_in_all_three():
    """The frozen four-node chain is not merely agreed on -- it is VERIFIED, in three
    languages. Agreement on a refusal would be much cheaper to achieve."""
    _skip_unless_all_three()
    cases = [c for c in corpus.graph_cases() if c[0] == "graph:full-chain"]
    if not cases:
        pytest.skip("no chain fixtures shipped")
    for leg in (python_leg, js_leg, rust_leg):
        got = leg("graph", cases)["graph:full-chain"]
        assert got["graph_verified"] is True, f"{leg.__name__} did not verify the shipped chain"
