"""The Python and JavaScript witness verifiers must return the SAME verdict.

WHY THIS FILE IS THE POINT OF HAVING TWO PORTS. A suite in which every implementation
is checked only against itself cannot see the one failure that matters here: two
verdicts from one vendor on the same bytes. That split is what a forger farms -- present
the document to whichever port says yes. This repository has been bitten by it before,
which is why the receipt path already has a cross-language differential; the witness
path had none, because until now there was only one implementation.

THE SPECIFIC RISK. The assurance ladder is duplicated: `obsign/witness.py`
`derive_assurance` and `js/src/witness.js` `deriveAssurance` are the same decision tree
written twice. A drift is not cosmetic -- it is one port calling a document `witnessed`
while the other calls it `asserted`, i.e. disagreeing about whether the operation was
independently identified.

DOCUMENTS CROSS AS TEXT. Both sides parse from the same bytes rather than being handed
the same already-parsed object, so a canonicalisation difference SURFACES instead of
being normalised away before either side looks. A witness carries no floats by
construction; this is the harness that would notice if one crept back in.

The corpus deliberately includes documents that must FAIL. A differential over
exclusively valid inputs proves the ports agree about the easy half.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "witness_js_runner.mjs"

# The producer package holds the witness builder. It is a sibling checkout; when it is
# absent this differential cannot run, and it must say so rather than pass quietly.
PRODUCER = Path(r"C:\Users\Josh\Projects\coherence_compute")

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not PRODUCER.is_dir(),
    reason="needs node and the coherence_compute producer checkout",
)


def _producer():
    if str(PRODUCER) not in sys.path:
        sys.path.insert(0, str(PRODUCER))
    from obsign import runner, witness  # noqa: PLC0415
    return runner, witness


def _corpus(tmp_path):
    """Documents at every rung, plus the ones that must be refused."""
    runner, witness = _producer()
    from obsign.signing import generate_keypair, sign_receipt

    src = tmp_path / "a.txt"
    src.write_text("the genuine evidence", encoding="utf-8")
    dst = tmp_path / "b.txt"
    other = tmp_path / "c.txt"
    other.write_text("a doctored intermediate", encoding="utf-8")
    key = generate_keypair()

    upper = [sys.executable, "-c",
             "import pathlib,sys;"
             "pathlib.Path(sys.argv[2]).write_text(pathlib.Path(sys.argv[1]).read_text().upper())"]
    step, _ = runner.run_witnessed([*upper, str(src), str(dst)],
                                   inputs=[src], outputs=[dst])
    intake = witness.custody_record([src])
    signed = sign_receipt(dict(step), key, signer="Lab")

    with runner.witness_run(inputs=[src], outputs=[other], tool="opencv",
                            version="4.10") as w:
        other.write_text("ASSERTED", encoding="utf-8")
    in_process = w.doc

    tampered = dict(signed)
    tampered["observed"] = dict(tampered["observed"], exit_code=99)

    overclaim = dict(step, assurance=witness.ENVIRONMENT_PINNED)

    # THE DECISION THE MUTATION TEST FOUND UNCOVERED: an argv WITH a binary that could
    # not be hashed. Every other document either has both or neither, so a port that
    # dropped the hashed-binary requirement would agree with the other on all of them.
    # Built properly rather than by editing `step`, so integrity still holds and the
    # comparison is about the rung rather than about a broken hash.
    unhashable = witness.build_witness(
        inputs=step["inputs"], outputs=step["outputs"],
        tool={"name": "ffmpeg", "argv": ["ffmpeg", "-i", "in.mp4", "out.mp4"],
              "binary": {"path": "/usr/bin/ffmpeg", "version": "n8.1",
                         "sha256_unavailable": "OSError: simulated"}},
        environment={"kind": "host", "os": "Linux"})

    # ...and its counterpart, identical except that the binary IS hashed, so the pair
    # differs in exactly one field and isolates the decision.
    hashable = witness.build_witness(
        inputs=step["inputs"], outputs=step["outputs"],
        tool={"name": "ffmpeg", "argv": ["ffmpeg", "-i", "in.mp4", "out.mp4"],
              "binary": {"path": "/usr/bin/ffmpeg", "version": "n8.1",
                         "sha256": "ab" * 32}},
        environment={"kind": "host", "os": "Linux"})

    forged_sig = dict(signed)
    forged_sig["signature"] = dict(signed["signature"], sig="00" * 64)

    swapped_signer = dict(signed)
    swapped_signer["signature"] = dict(signed["signature"], signer="Reuters")

    linked, _ = runner.run_witnessed(
        [*upper, str(src), str(dst)], inputs=[src], outputs=[dst],
        prior=[{"receipt_sha256": intake["receipt_sha256"], "spec": intake["spec"]}])

    laundered, _ = runner.run_witnessed(
        [*upper, str(other), str(dst)], inputs=[other], outputs=[dst],
        prior=[{"receipt_sha256": intake["receipt_sha256"], "spec": intake["spec"]}])

    j = lambda d: json.dumps(d)  # noqa: E731
    return [
        ("witnessed_unsigned", [j(step)]),
        ("witnessed_signed", [j(signed)]),
        ("custody", [j(intake)]),
        ("asserted_in_process", [j(in_process)]),
        ("tampered_claim", [j(tampered)]),
        ("overclaimed_rung", [j(overclaim)]),
        ("argv_with_unhashable_binary", [j(unhashable)]),
        ("argv_with_hashed_binary", [j(hashable)]),
        ("forged_signature", [j(forged_sig)]),
        ("signer_swapped_after_signing", [j(swapped_signer)]),
        ("not_a_witness", [j({"spec": "obsign/receipt/v1", "receipt_sha256": "ab" * 32})]),
        ("chain_good", [j(intake), j(linked)]),
        ("chain_laundered", [j(intake), j(laundered)]),
        ("chain_missing_parent", [j(linked)]),
    ]


def _python_verdicts(cases):
    _, witness = _producer()
    out = {}
    for name, texts in cases:
        docs = [json.loads(t) for t in texts]
        if len(docs) == 1:
            v = witness.verify_witness(docs[0])
            sig = v.get("signature")
            out[name] = {
                "kind": "single",
                "verified": v["verified"], "integrity": v["integrity"],
                "reproduced": v["reproduced"],
                "assurance": v.get("assurance"),
                "derived": witness.derive_assurance(docs[0]),
                "signature_valid": None if sig is None else sig.get("valid"),
            }
        else:
            c = witness.verify_chain(docs)
            out[name] = {
                "kind": "chain", "ok": c["ok"],
                "effective_assurance": c["effective_assurance"],
                "nodes": {h: {"verified": n["verified"], "links_ok": n["links_ok"],
                              "assurance": n["assurance"]}
                          for h, n in c["nodes"].items()},
            }
    return out


def _js_verdicts(cases, tmp_path):
    p = tmp_path / "cases.json"
    p.write_text(json.dumps(cases), encoding="utf-8")
    r = subprocess.run(["node", str(RUNNER), str(p)],
                       capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise AssertionError(f"the JS runner failed: {r.stderr[:2000]}")
    return json.loads(r.stdout)


@pytest.fixture(scope="module")
def verdicts(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("witness_diff")
    cases = _corpus(tmp)
    return cases, _python_verdicts(cases), _js_verdicts(cases, tmp)


def test_the_corpus_covers_both_outcomes(verdicts):
    """CALIBRATION. A differential over only-valid documents proves the ports agree
    about the easy half."""
    _, py, _ = verdicts
    singles = [v for v in py.values() if v["kind"] == "single"]
    assert any(v["verified"] for v in singles), "no document in the corpus verifies"
    assert any(not v["verified"] for v in singles), "no document in the corpus fails"
    chains = [v for v in py.values() if v["kind"] == "chain"]
    assert any(c["ok"] for c in chains) and any(not c["ok"] for c in chains)


def test_every_rung_is_represented(verdicts):
    """The ladder is the duplicated logic; a differential that never exercises a rung
    cannot detect a drift on it."""
    _, py, _ = verdicts
    seen = {v["derived"] for v in py.values() if v["kind"] == "single"}
    _, witness = _producer()
    for rung in (witness.CUSTODY, witness.ASSERTED, witness.WITNESSED):
        assert rung in seen, f"the corpus never produces a {rung!r} document: {seen}"


def test_every_rung_DECISION_is_exercised_not_merely_every_rung(verdicts):
    """RUNG COVERAGE IS NOT DECISION COVERAGE, and this distinction was not theoretical.

    A mutant that dropped the hashed-binary requirement from the JS ladder SURVIVED the
    differential: every document in the corpus had either both an argv and a hashed
    binary, or neither, so both ports agreed on all of them and the drift was invisible.
    The pair below differs in exactly one field and pins the decision itself.
    """
    _, py, _ = verdicts
    _, witness = _producer()
    assert py["argv_with_unhashable_binary"]["derived"] == witness.ASSERTED, (
        "an argv whose binary could not be hashed must not reach `witnessed`: nothing "
        "identifies what actually ran")
    assert py["argv_with_hashed_binary"]["derived"] == witness.WITNESSED, (
        "the counterpart must reach `witnessed`, or the pair does not isolate the "
        "hashed-binary decision")


def test_the_two_ports_return_identical_verdicts(verdicts):
    """THE WHOLE POINT. Field for field, on the same bytes."""
    cases, py, js = verdicts
    assert set(py) == set(js), (
        f"the ports disagree about WHICH cases exist: "
        f"python-only={set(py) - set(js)} js-only={set(js) - set(py)}")
    mismatches = []
    for name in sorted(py):
        if py[name] != js[name]:
            mismatches.append(
                f"\n  {name}:\n    python: {json.dumps(py[name], sort_keys=True)}"
                f"\n    js    : {json.dumps(js[name], sort_keys=True)}")
    assert not mismatches, (
        "the Python and JavaScript witness verifiers disagree. Two verdicts from one "
        "vendor on the same bytes is the split a forger farms -- present the document "
        "to whichever port says yes." + "".join(mismatches))


def test_the_ladders_are_the_same_ladder(tmp_path):
    """The rung ORDER is the semantics: comparisons are by index, so a reordering in
    one port silently changes what counts as an overclaim there."""
    _, witness = _producer()
    r = subprocess.run(
        ["node", "-e",
         "process.stdout.write(JSON.stringify(require("
         "'../js/src/witness.js').LADDER))"],
        cwd=str(HERE), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == list(witness.LADDER), (
        "the two ports order the assurance ladder differently")


def test_the_frozen_fixtures_still_match_live_python(verdicts):
    """FIXTURES GO STALE, AND A STALE FIXTURE FREEZES A BUG AS THE EXPECTED ANSWER.

    `js/test/fixtures/witness_corpus.json` carries Python's verdicts so the JS port can
    be checked in CI, where this producer checkout is absent and everything above SKIPS.
    That file is only trustworthy while it still describes what Python actually does, so
    this is the direction that catches drift: recompute the recorded cases with the
    CURRENT Python implementation and require the frozen verdicts to match.

    The two checks are a pair. Fixtures alone freeze whatever was true the day they were
    written; the live differential alone runs on one workstation.
    """
    fixtures = Path(__file__).resolve().parent.parent / "js" / "test" / "fixtures" / "witness_corpus.json"
    assert fixtures.is_file(), f"{fixtures} is missing; the JS port has nothing to check against"
    frozen = json.loads(fixtures.read_text(encoding="utf-8"))

    live = _python_verdicts(frozen["cases"])
    stale = [n for n in frozen["python_verdicts"] if frozen["python_verdicts"][n] != live.get(n)]
    assert not stale, (
        f"the frozen fixtures no longer match this Python implementation for: {stale}. "
        f"Regenerate them (tools/regen_witness_fixtures.py) and re-read the diff before "
        f"accepting it -- a fixture updated without being read is how a regression "
        f"becomes the expected answer.")
