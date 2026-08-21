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

KNOWN DIVERGENCES ARE FROZEN, NOT SKIPPED -- AND THE TABLE IS NOW EMPTY. Every
disagreement this harness found used to be recorded in `KNOWN_DIVERGENCES` with the
side docs/ supports, and each entry is asserted to STILL diverge, so the day one is
fixed this test fails and says the entry is stale. The freeze runs in both directions,
which is the only way a known-issue list stays honest -- but a known-issue list is a
place a defect SITS, not a place it LIVES, and the two entries and the one softened
column class that were here are closed rather than documented. See the note above
`KNOWN_DIVERGENCES` for what they were.
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
    # `encoding="utf-8"`, explicitly. `text=True` alone decodes with the LOCALE
    # codec, which on a Windows runner is cp1252: a corpus that deliberately carries
    # astral characters and escaped surrogates then dies in the reader thread with
    # `UnicodeDecodeError: 'charmap' codec can't decode byte 0x90`, before any
    # comparison happens. The three legs emit UTF-8 JSON; read it as UTF-8.
    proc = subprocess.run([*argv, str(job)], capture_output=True, text=True,
                          encoding="utf-8", timeout=1800, check=False)
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


#: The built binary's name. `.exe` on Windows, and not naming it is not a cosmetic
#: slip: `exe.exists()` was False after a PERFECTLY SUCCESSFUL build, so this raised
#: "cargo build failed" with the compiler's own green output pasted underneath it, and
#: three other test files silently reported "rust binary is not built" -- a skip that
#: reads like a pass in every summary line -- on the platform the CI matrix declares.
RUST_BIN = "obsign-verify-rs" + (".exe" if sys.platform == "win32" else "")


def _rust_binary() -> Path:
    if _BINARY:
        return _BINARY[0]
    exe = RUST / "target" / "release" / RUST_BIN
    build = subprocess.run(["cargo", "build", "--release", "--offline"], cwd=RUST,
                           capture_output=True, text=True, encoding="utf-8",
                           timeout=900, check=False)
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
                "unsupported": v.get("unsupported", False),
                "approved_program": v.get("approved_program"),
                "input_liveness": v.get("input_liveness"),
                "input_liveness_by_input": v.get("input_liveness_by_input", []),
                "output_liveness_by_cell": v.get("output_liveness_by_cell", []),
                "signature": None if s is None else {
                    "present": s["present"], "valid": s["valid"],
                    "unsupported": s.get("unsupported", False),
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
# THIS TABLE IS EMPTY, AND THAT IS THE POINT. It is not a place to record disagreements;
# it is a place a disagreement may sit while it is being fixed, and every entry is
# asserted to STILL diverge -- so the day one is repaired this test fails and says the
# entry is stale. An empty table means every case in the corpus gets ONE answer from
# three implementations, which is the product.
#
# WHAT USED TO BE HERE, so that nobody re-adds it:
#
#   ("verify", "sig:sig-member-is-number") and ("verify", "sig:sig-member-is-true")
#   -- `js/src/signature.js` read `str(sig,'sig') || str(sig,'signature')`, so a `sig`
#   of the wrong TYPE fell through to the alternate spelling. `{"sig": 5, "signature":
#   "<valid 128-hex>"}` therefore VERIFIED in JavaScript and attributed the signer,
#   while Python and Rust called the block malformed and refused. An executed witness,
#   in a signature envelope, on a field a forger controls: the synonym is deleted in
#   all three (RULE SIG-MEMBER), so both entries are gone rather than documented.
#
#   SOFTENED_VERIFY_COLUMNS = (3, 4) -- a divergence too broad to freeze case by case,
#   so it was frozen as a CLASS: `rust/src/verify.rs` still carried the pre-fix
#   liveness probe (seven fixed absolute perturbations capped at 1,000,000, and a
#   budget denominated in VM steps) and disagreed with the other two on 37 of the 364
#   replay receipts. Blanking two columns of a projection is a dark gate wearing a
#   comment: whatever else those columns might have caught was equally invisible. The
#   probe is ported value-for-value now, the columns are compared like every other one,
#   and there is no softening mechanism left in `_compare` to reach for.

KNOWN_DIVERGENCES: dict[tuple[str, str], str] = {}


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

    THERE IS NO SOFTENING PARAMETER ANY MORE. `soft=` blanked named projection columns
    for the whole corpus so a frozen CLASS of disagreement could stay green; whatever
    else those columns might have caught was blanked with it, and a gate that cannot
    fail is not a gate. Every column is compared on every case; the only tolerance left
    is the per-case `known` table, which is empty and which is asserted in BOTH
    directions.
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
    # The reference leg's projections, so a caller can assert what the corpus actually
    # EXERCISED. Three implementations that all refuse everything agree perfectly, and
    # a corpus that lost the cases carrying a column would pass this function in
    # silence -- which is the same dark gate the softened columns were.
    return {name: project(py[name]) for name, _ in cases}


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
            # COMPARED AS THE THREE-VALUED FIELD IT IS, not as `is True`.
            #
            # This projected to a bool with the note that the reference spelled "not
            # attempted" as False and the two ports as null, and that a reader only
            # acts on whether re-derivation SUCCEEDED. Both halves were wrong. The
            # spelling difference was a REAL divergence -- `js/src/verify.js` and
            # `rust/src/verify.rs` both document `reproduced: null` and the reference
            # contradicted its own ports on the same bytes -- and a reader does act on
            # the difference: the CLIs print "not attempted" for null and "FAIL" for
            # false, which is an accusation. The reference now initialises to None,
            # all three agree, and the softening that hid it is gone. A gate with a
            # projection that cannot fail is not a gate.
            d["reproduced"],
            d["input_liveness"],
            tuple(d["input_liveness_by_input"] or ()),
            # Compared like every other column: `graph.py` refuses a chain link whose
            # whole source slice is dead, so a per-cell disagreement is a chain that
            # verifies in one implementation and is refused in another.
            tuple(d.get("output_liveness_by_cell") or ()),
            # "I do not implement this format" is a THIRD answer, and three
            # implementations that spell it three ways have not agreed about anything.
            d.get("unsupported"),
            s.get("present"), s.get("valid"), s.get("unsupported"),
            s.get("identity_bound"),
            s.get("attributed_signer"), tuple(s.get("bound_metadata") or ()),
            tuple(s.get("unbound_metadata") or ()),
            tuple(d["output"]) if d["output"] is not None else None,
        )

    got = _compare("verify", replay_only, project)

    # WHAT THE CORPUS ACTUALLY EXERCISED. Agreement is cheap when everything is
    # refused -- three implementations that all crash agree perfectly -- and a column
    # nothing in the corpus ever sets is a column no comparison can test. The two
    # protocol fields added for the audit findings are named explicitly, so deleting
    # the vectors that carry them fails here instead of quietly halving the check.
    # A case that did not LOAD projects to the 1-tuple ("not-loaded",), so columns are
    # read by a guard rather than by index: an IndexError here would be this census
    # failing, which reads exactly like the corpus failing.
    def col(p, i, want):
        return len(p) > i and p[i] == want

    verified = sum(1 for p in got.values() if col(p, 0, True))
    unsupported_receipts = sum(1 for p in got.values() if col(p, 6, True))
    unsupported_sigs = sum(1 for p in got.values() if col(p, 9, True))
    live = sum(1 for p in got.values() if col(p, 3, "live"))
    assert len(replay_only) > 300, f"only {len(replay_only)} replay receipts in the corpus"
    assert verified > 80, (
        f"only {verified} receipts VERIFY in all three -- agreement on refusal is much "
        f"cheaper to achieve than agreement on a pass")
    assert live > 80, f"only {live} receipts reach a 'live' liveness verdict"
    assert unsupported_receipts >= 6, (
        f"only {unsupported_receipts} receipts exercise an unsupported receipt `spec` "
        f"-- the column is compared but nothing sets it")
    assert unsupported_sigs >= 6, (
        f"only {unsupported_sigs} receipts exercise an unsupported signature `spec` "
        f"-- the column is compared but nothing sets it")

    # `reproduced` USED TO BE PROJECTED TO A BOOL HERE, which is how the reference
    # spelling "not attempted" as False while both ports spelled it null survived with
    # every suite green. It is compared as the three-valued field it is now, so the
    # census has to prove the corpus reaches all THREE values -- a comparison that only
    # ever sees True and False is exactly as dark as the projection it replaced.
    # Measured on this corpus: 212 True, 8 False, 176 None.
    for value, floor in ((True, 80), (False, 4), (None, 40)):
        n = sum(1 for p in got.values() if col(p, 2, value))
        assert n >= floor, (
            f"only {n} receipts reach `reproduced == {value!r}` in all three -- the "
            f"column is compared but that value is never set, so a split in it would "
            f"be invisible")


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
