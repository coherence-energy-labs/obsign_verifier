"""An unknown format is a THIRD ANSWER, and `verified` must stop carrying four meanings.

Four audit findings meet here, and they are one shape: a verifier answering a question
it was never asked.

P1-3  THE RECEIPT SPEC IS NOT AN EXECUTION GATE. The ladder dispatched on `kernel`,
      with no top-level `spec` check anywhere in the generic path. A document declaring
      `obsign/receipt/v99` -- a format whose claim boundary, whose params schema and
      whose output block nobody has implemented -- was interpreted under today's v1
      semantics, and, re-sealed, could reach VERIFIED. "Unknown format" means "I do not
      know what these bytes mean", not "I will interpret them as whatever my current
      implementation does".

P1-4  UNKNOWN SIGNATURE SPECS FELL THROUGH TO LEGACY v1. `if spec == v2 ... else v1`
      in all three implementations, so an unknown envelope inherited the WEAKEST
      historical semantics -- v1 signs the bare receipt hash and covers neither the
      signer nor the case block. The fixtures below make that concrete: the same real
      v1 signature, relabelled `obsign/signature/v9`, used to be reported valid.

P1-5  `indeterminate` LIVENESS STILL PRODUCED VERIFIED. It still does, on purpose -- a
      verifier that refused an honest receipt for being expensive to probe would be
      accusing a producer of forgery on a timing measurement. What was missing is that
      the reader could not SEE it: the headline said VERIFIED and the detail line said
      "unproven" in lower case. Now the verdict line is tagged, the rung reads UNPROVEN,
      `--strict-liveness` refuses it outright, and `approved_program` -- the pin that
      actually bounds semantics -- is a field of the result rather than CLI decoration
      three implementations each did their own way.

P1-6  ONE FIELD, ONE SPELLING. `sig.get("sig") or sig.get("signature")` let a `sig` of
      the wrong TYPE fall through to a synonym in JavaScript, so `{"sig": 5,
      "signature": "<valid 128-hex>"}` VERIFIED there and was refused by the other two.

Every fixture in `data/conformance/unsupported/` declares its own expected verdict in a
`_conformance` block, and the same block is read by the JavaScript and Rust suites, so
the three implementations are held to ONE written expectation rather than to each
other's behaviour. Agreement between three implementations that are all wrong is
perfect agreement.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from obsign_verify import data_path, load_receipt, mint, verify
from obsign_verify.canonical import canonical_sha256, claim_of
from obsign_verify.replayc import compile_source

#: `obsign_verify.verify` is rebound to the FUNCTION by the package's __init__, so the
#: module itself has to come out of sys.modules.
verifymod = sys.modules["obsign_verify.verify"]

FIXTURES = sorted(data_path("conformance", "unsupported").glob("*.json"))
_HAS_CRYPTO = True
try:
    import cryptography  # noqa: F401
except ImportError:                                    # pragma: no cover
    _HAS_CRYPTO = False


def _load(path):
    return load_receipt(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------- the shipped fixtures

def test_the_unsupported_fixture_set_is_present_and_describes_itself():
    """A fixture directory that quietly emptied would make every test below vacuous."""
    names = sorted(p.name for p in FIXTURES)
    assert names == ["receipt_spec_v1_control.json", "receipt_spec_v99.json",
                     "signature_spec_absent.json", "signature_spec_v1.json",
                     "signature_spec_v9.json"], names
    for path in FIXTURES:
        doc = json.loads(path.read_text(encoding="utf-8"))
        block = doc.get("_conformance")
        assert block and block.get("note"), f"{path.name} does not say what it proves"
        for field in ("verified", "unsupported", "signature_present", "signature_valid",
                      "signature_unsupported", "identity_bound", "attributed_signer",
                      "reproduced", "requires_crypto"):
            assert field in block["expect"], f"{path.name} declares no {field}"
    # ...and the expectations must not all be the same, or the reader below is a
    # constant function wearing a parametrize decorator.
    verdicts = {json.loads(p.read_text(encoding="utf-8"))["_conformance"]["expect"]
                ["verified"] for p in FIXTURES}
    assert verdicts == {True, False}, verdicts


def test_the_unsupported_fixtures_are_byte_clean():
    """These are byte-pinned package data. `.gitattributes` marks
    `src/obsign_verify/data/** -text`, and a path-based rule is a dangling pointer the
    moment the path moves -- which has already broken two byte-pins in this estate in a
    single day. Asserting the bytes is cheaper than trusting the attribute."""
    for path in FIXTURES:
        raw = path.read_bytes()
        assert bytes([13, 10]) not in raw, f"CRLF in {path.name}"
        assert bytes([0]) not in raw, f"NUL byte in {path.name}"
        json.loads(raw.decode("utf-8"))


@pytest.mark.parametrize("path", FIXTURES, ids=[p.stem for p in FIXTURES])
def test_every_unsupported_fixture_gets_the_verdict_it_declares(path):
    """The declared verdict, field for field. Fails if a rung moves in either
    direction -- an accepted forgery and a refused honest receipt are both news."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    want = doc["_conformance"]["expect"]
    if want["requires_crypto"] and not _HAS_CRYPTO:
        pytest.skip("cryptography is not installed; a signed receipt is REFUSED here, "
                    "which is correct behaviour but not evidence about the spec gate")

    res = verify(_load(path))
    sig = res["signature"] or {}
    got = {
        "verified": res["verified"],
        "unsupported": res["unsupported"],
        # NOT `bool(...)`. `reproduced` is three-valued -- None is "nothing was
        # attempted", which is a different fact from False ("re-derived, did not
        # match") -- and coercing it here is what let the reference say `false` and
        # both ports say `null` on the same bytes with every suite green. A shared
        # corpus that projects a column away cannot see a split in it.
        "reproduced": res["reproduced"],
        "signature_present": sig.get("present", False),
        "signature_valid": sig.get("valid", False),
        "signature_unsupported": sig.get("unsupported", False),
        "identity_bound": sig.get("identity_bound", False),
        "attributed_signer": sig.get("attributed_signer"),
    }
    expected = {k: v for k, v in want.items() if k != "requires_crypto"}
    assert got == expected, f"{path.name}: {doc['_conformance']['note']}"


# ---------------------------------------------------- P1-4, made impossible to argue

@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography is not installed")
def test_the_only_difference_between_valid_and_unsupported_is_the_spec_string():
    """THE FALL-THROUGH, EXECUTED.

    `signature_spec_v1.json` and `signature_spec_v9.json` carry the same claim, the
    same key and the SAME 128 hex characters of signature. That signature really does
    verify under v1 rules -- which is what made the old `else: legacy v1` dispatch
    report an envelope nobody has implemented as a valid, checked signature.

    If someone reinstates the fall-through, the two assertions below say so in one
    line: identical bytes, one word apart, must not both be accepted.
    """
    v1 = json.loads((data_path("conformance", "unsupported")
                     / "signature_spec_v1.json").read_text(encoding="utf-8"))
    v9 = json.loads((data_path("conformance", "unsupported")
                     / "signature_spec_v9.json").read_text(encoding="utf-8"))
    assert v1["signature"]["sig"] == v9["signature"]["sig"], "precondition: same bytes"
    assert v1["receipt_sha256"] == v9["receipt_sha256"], "precondition: same claim"
    assert (v1["signature"]["spec"], v9["signature"]["spec"]) == (
        "obsign/signature/v1", "obsign/signature/v9")

    a, b = verify(load_receipt(json.dumps(v1))), verify(load_receipt(json.dumps(v9)))
    assert a["signature"]["valid"] is True, "the v1 signature must really verify"
    assert a["verified"] is True
    assert b["signature"]["valid"] is False
    assert b["signature"]["unsupported"] is True
    assert b["verified"] is False, (
        "an unknown signature envelope inherited legacy v1 semantics and was reported "
        "as a checked signature")


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography is not installed")
@pytest.mark.parametrize("spec", [
    "obsign/signature/v3", "obsign/signature/v9", "obsign/signature/v2 ",
    "OBSIGN/SIGNATURE/V2", "", "obsign/signature/", 9, True, None, ["v1"], {"v": 1},
], ids=["v3", "v9", "trailing-space", "uppercased", "empty", "truncated",
        "number", "true", "json-null", "array", "object"])
def test_no_spelling_but_the_two_tokens_reaches_a_signature_check(spec):
    """A protocol identifier has ONE spelling, and a non-string is not a spelling.

    `json-null` is the one case that is NOT unsupported: the reference reads an absent
    key and a `null` value as the same thing and cannot tell them apart, so all three
    implementations must treat `null` as absent -- which is legacy v1, which is valid.
    Pinned here so the equivalence is a decision rather than an accident.
    """
    v1 = json.loads((data_path("conformance", "unsupported")
                     / "signature_spec_v1.json").read_text(encoding="utf-8"))
    v1["signature"] = dict(v1["signature"], spec=spec)
    res = verify(load_receipt(json.dumps(v1)))
    if spec is None:
        assert res["signature"]["valid"] is True and res["verified"] is True
        return
    assert res["signature"]["unsupported"] is True, res["signature"]["detail"]
    assert res["signature"]["valid"] is False
    assert res["signature"]["attributed_signer"] is None
    assert res["verified"] is False


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography is not installed")
def test_a_signature_member_is_not_a_synonym_for_sig():
    """P1-6's concrete witness, from the audit, verbatim.

    `{"sig": 5, "signature": "<a signature that really verifies>"}`. JavaScript read
    `str(sig,'sig') || str(sig,'signature')`, so a non-string `sig` produced null and
    the alternate member was used: the receipt VERIFIED there and attributed its
    signer, while Python and Rust called the block malformed. Same file, two verdicts,
    forger's choice of verifier.

    The `signature` spelling is deleted, not harmonised -- no receipt ever carried it.
    """
    doc = json.loads((data_path("conformance", "unsupported")
                      / "signature_spec_v1.json").read_text(encoding="utf-8"))
    real = doc["signature"]["sig"]

    # The control: the same hex in `sig` DOES verify, so what fails below is the
    # synonym and not the signature.
    assert verify(load_receipt(json.dumps(doc)))["signature"]["valid"] is True

    for bad in (5, True, "", None):
        forged = dict(doc)
        forged["signature"] = {k: v for k, v in doc["signature"].items()}
        forged["signature"]["sig"] = bad
        forged["signature"]["signature"] = real
        res = verify(load_receipt(json.dumps(forged)))
        assert res["signature"]["valid"] is False, (
            f"sig={bad!r} beside a valid `signature` member was accepted -- the "
            f"synonym fallback is back")
        assert res["signature"]["attributed_signer"] is None
        assert res["verified"] is False


# ---------------------------------------------------- P1-3, and the control beside it

def test_an_unknown_receipt_spec_is_unsupported_while_the_same_claim_under_v1_verifies():
    """The pair. Without the control this proves only that something was refused."""
    control = verify(_load(data_path("conformance", "unsupported")
                           / "receipt_spec_v1_control.json"))
    assert control["verified"] is True and control["unsupported"] is False
    assert control["reproduced"] is True

    unknown = verify(_load(data_path("conformance", "unsupported")
                           / "receipt_spec_v99.json"))
    assert unknown["integrity"] is True, (
        "precondition: the v99 fixture is RE-SEALED, so its claim hash is correct -- "
        "the only thing between it and a verified verdict is the spec gate")
    assert unknown["unsupported"] is True
    assert unknown["verified"] is False
    # NOT False. False means "it was re-derived and it did not match" -- an
    # accusation. Nothing was attempted here, and both ports have always said null;
    # the reference said false, and every harness coerced the field to a bool so no
    # suite could see the split.
    assert unknown["reproduced"] is None, (
        "nothing may be re-executed under an unknown format, and the verdict must say "
        "NOT ATTEMPTED rather than accuse the receipt of failing to re-derive")
    assert any("not supported by this verifier" in n for n in unknown["notes"])


@pytest.mark.parametrize("spec", ["obsign/receipt/v2", "obsign/receipt/v99",
                                  "obsign/receipt/v1 ", "OBSIGN/RECEIPT/V1", "",
                                  None, 1, True, {"v": 1}],
                         ids=["v2", "v99", "trailing-space", "uppercased", "empty",
                              "absent", "number", "true", "object"])
def test_only_the_exact_receipt_spec_token_reaches_the_ladder(spec):
    """Re-sealed each time, so integrity is never the reason for the refusal."""
    receipt = mint.replay_receipt(compile_source("input a; output a + 1;"), [41])
    if spec is None:
        receipt.pop("spec")
    else:
        receipt["spec"] = spec
    receipt.pop("receipt_sha256")
    receipt["receipt_sha256"] = canonical_sha256(claim_of(receipt))

    res = verify(load_receipt(json.dumps(receipt)))
    assert res["integrity"] is True, "precondition: re-sealed"
    assert res["unsupported"] is True, res["notes"]
    assert res["verified"] is False
    assert res["reproduced"] is None, "not attempted, which is not the same as failed"


def test_the_spec_gate_does_not_silence_the_signature():
    """An unknown format still has a signer, and "who handed me this" is answerable
    without knowing what the file means. The gate must not turn the attribution off --
    only the re-derivation."""
    receipt = mint.replay_receipt(compile_source("input a; output a + 1;"), [41])
    receipt["spec"] = "obsign/receipt/v99"
    receipt.pop("receipt_sha256")
    receipt["receipt_sha256"] = canonical_sha256(claim_of(receipt))
    res = verify(load_receipt(json.dumps(receipt)))
    assert res["signature"] is not None, "the signature gate did not run at all"
    assert res["signature"]["present"] is False


# ------------------------------------------------- P1-5: liveness, strictness, pinning

def _indeterminate(monkeypatch):
    """Force the probe budget to zero, so every input reports `indeterminate`.

    The budget rather than the program: a program contrived to be expensive would be
    measuring the machine this runs on, and `_probe_cost` plus `_LIVENESS_FLOOR` are
    exactly the two numbers that decide the verdict.
    """
    monkeypatch.setattr(verifymod, "_LIVENESS_FLOOR", 0)
    monkeypatch.setattr(verifymod, "_probe_cost", lambda *a, **k: 0)


def _honest():
    return mint.replay_receipt(compile_source("input a, b; output a * 3 + b;"), [5, 7])


def test_an_indeterminate_probe_still_verifies_by_default(monkeypatch):
    """The default is deliberately permissive, and that is the decision, not an
    oversight: a verifier must not refuse an honest receipt for being expensive to
    probe. Pinned so nobody "fixes" it into an accusation by accident."""
    receipt = _honest()
    assert verify(receipt)["input_liveness"] == "live", "precondition: honestly live"

    _indeterminate(monkeypatch)
    res = verify(receipt)
    assert res["input_liveness"] == "indeterminate"
    assert res["verified"] is True
    assert any("hit its budget" in n for n in res["notes"])


def test_strict_liveness_refuses_what_the_default_accepts(monkeypatch):
    """The same receipt, the same probe, one argument apart."""
    receipt = _honest()
    _indeterminate(monkeypatch)
    assert verify(receipt, strict_liveness=True)["verified"] is False
    assert any("only 'live' is accepted in strict mode" in n
               for n in verify(receipt, strict_liveness=True)["notes"])


def test_strict_liveness_does_not_refuse_a_receipt_that_is_actually_live():
    """A flag that refuses everything is not a stricter check, it is a broken one."""
    res = verify(_honest(), strict_liveness=True)
    assert res["input_liveness"] == "live"
    assert res["verified"] is True


def test_strict_liveness_refuses_a_program_that_declares_no_inputs():
    """`n/a` is weaker than `live`, so strict mode refuses it. A program with no
    declared inputs demonstrates nothing about any, which is precisely the thing
    strict mode exists to require."""
    receipt = mint.replay_receipt(compile_source("output 7;"), [])
    assert verify(receipt)["input_liveness"] == "n/a"
    assert verify(receipt)["verified"] is True, "the default is unchanged"
    assert verify(receipt, strict_liveness=True)["verified"] is False


def test_approved_program_is_three_valued_through_the_library():
    """`--expect-program` was CLI post-processing in three implementations, so every
    caller that imported the package instead of shelling out silently got the weaker
    question and no field saying so. None / True / False, and None means NO
    EXPECTATION WAS SUPPLIED -- a different fact from "not the approved program"."""
    receipt = _honest()
    digest = receipt["params"]["program_sha256"]

    assert verify(receipt)["approved_program"] is None
    assert verify(receipt, expect_program=digest)["approved_program"] is True
    assert verify(receipt, expect_program=digest)["verified"] is True

    wrong = verify(receipt, expect_program="0" * 64)
    assert wrong["approved_program"] is False
    assert wrong["verified"] is False
    assert any("not the approved one" in n for n in wrong["notes"])


def test_the_pin_compares_the_COMPUTED_digest_not_the_stated_one():
    """A forger who types the approved digest into `params.program_sha256` beside a
    different program must not thereby own the approval. The stated field is a
    convenience; the computed one is what ran."""
    receipt = _honest()
    approved = receipt["params"]["program_sha256"]
    other = mint.replay_receipt(compile_source("input a; output 424242;"), [5])
    swapped = dict(other)
    swapped["params"] = dict(other["params"], program_sha256=approved)
    swapped.pop("receipt_sha256")
    swapped["receipt_sha256"] = canonical_sha256(claim_of(swapped))

    res = verify(load_receipt(json.dumps(swapped)), expect_program=approved)
    assert res["approved_program"] is False, (
        "the pin read the STATED digest, so writing the approved value beside a "
        "different program satisfied it")
    assert res["verified"] is False


def test_the_pin_answers_even_on_a_receipt_that_cannot_be_re_executed():
    """A receipt whose format this verifier cannot read is not thereby the approved
    program. Returning None there would say "no expectation was supplied" to a caller
    who supplied one."""
    receipt = _honest()
    receipt["spec"] = "obsign/receipt/v99"
    receipt.pop("receipt_sha256")
    receipt["receipt_sha256"] = canonical_sha256(claim_of(receipt))
    res = verify(load_receipt(json.dumps(receipt)), expect_program="0" * 64)
    assert res["unsupported"] is True
    assert res["approved_program"] is False


# ------------------------------------------------------------------------- the CLI

def _cli(argv, capsys):
    from obsign_verify.cli import main
    code = main(argv)
    return code, capsys.readouterr().out


def test_the_cli_renders_an_unproven_probe_as_UNPROVEN_and_tags_the_headline(
        tmp_path, monkeypatch, capsys):
    """THE READER WHO SCANS ONE LINE AND STOPS.

    `verified` still accepts an indeterminate probe, so the headline still says
    VERIFIED -- and it must not leave a reader believing the inputs were shown to
    reach the output when the probe ran out of budget before proving anything either
    way. The old detail line said "unproven (probe budget reached)" in lower case
    beside an untagged VERIFIED.
    """
    path = tmp_path / "r.json"
    path.write_text(json.dumps(_honest()), encoding="utf-8")

    _indeterminate(monkeypatch)
    code, out = _cli([str(path)], capsys)
    assert code == 0, out
    assert "inputs      UNPROVEN (probe budget reached) - semantic validity not " \
           "established" in out, out
    assert "[VERIFIED] r.json  (inputs unproven)" in out, out


def test_the_cli_headline_is_not_tagged_when_the_probe_actually_proved_something(
        tmp_path, capsys):
    """The negative control for the test above: a tag on every line is not a signal."""
    path = tmp_path / "r.json"
    path.write_text(json.dumps(_honest()), encoding="utf-8")
    code, out = _cli([str(path)], capsys)
    assert code == 0, out
    assert "(inputs unproven)" not in out
    assert "UNPROVEN" not in out
    assert "inputs      ok - the output depends on the declared inputs" in out


def test_the_cli_strict_liveness_flag_changes_the_exit_code(tmp_path, monkeypatch,
                                                            capsys):
    """The exit code is the interface. A flag that only changes prose is decoration."""
    path = tmp_path / "r.json"
    path.write_text(json.dumps(_honest()), encoding="utf-8")
    _indeterminate(monkeypatch)
    assert _cli([str(path)], capsys)[0] == 0
    code, out = _cli(["--strict-liveness", str(path)], capsys)
    assert code == 1, out
    assert "[REFUSED" in out


def test_the_cli_reports_an_unsupported_receipt_spec_by_name(tmp_path, capsys):
    receipt = _honest()
    receipt["spec"] = "obsign/receipt/v99"
    receipt.pop("receipt_sha256")
    receipt["receipt_sha256"] = canonical_sha256(claim_of(receipt))
    path = tmp_path / "v99.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    code, out = _cli([str(path)], capsys)
    assert code == 1, out
    assert "(unsupported format - NOT verified)" in out, out
    assert "obsign/receipt/v99" in out, out


def test_the_cli_pin_goes_through_the_library_and_is_reported(tmp_path, capsys):
    receipt = _honest()
    path = tmp_path / "r.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    digest = receipt["params"]["program_sha256"]

    code, out = _cli(["--expect-program", digest, str(path)], capsys)
    assert code == 0, out
    assert "program     ok - matches the approved digest" in out

    code, out = _cli(["--expect-program", "0" * 64, str(path)], capsys)
    assert code == 1, out
    assert "program     FAIL - not the approved program" in out


# -------------------------------------------------------- the other two CLIs, briefly
#
# The full three-way comparison lives in `test_cross_language_differential.py`; what is
# checked here is that the two ports grew the same FLAGS, because a flag that exists in
# one CLI and not another is exactly the split this work exists to close.

import os          # noqa: E402
import shutil      # noqa: E402

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}


_HAS_CARGO = shutil.which("cargo") is not None


def _rust_binary():
    from pathlib import Path
    repo = Path(__file__).resolve().parent.parent
    name = "obsign-verify-rs" + (".exe" if sys.platform == "win32" else "")
    exe = repo / "rust" / "target" / "release" / name
    return exe if exe.is_file() else None


@pytest.mark.parametrize("impl", ["python", "javascript", "rust"])
def test_chain_list_is_the_argument_list_in_every_cli(impl, tmp_path):
    """A CHAIN OF THOUSANDS OF NODES CANNOT BE NAMED IN ARGV.

    Windows caps a command line at 8,191 characters, so `--chain --quiet <3000 paths>`
    died with `[WinError 206] The filename or extension is too long` -- a refusal to
    RUN, which is not a verdict either. `--chain-list FILE` is the same argument list
    through a channel with no limit, and it must exist in ALL THREE CLIs: an option in
    one and not another is the split this work exists to close.

    The property checked here is that the file is not a second, LAXER door -- a
    transport that silently dropped receipts would make the deep-chain test pass by
    verifying a shorter chain. So a small set is run both ways and compared.
    """
    from pathlib import Path
    repo = Path(__file__).resolve().parent.parent

    names = []
    for i in range(4):
        receipt = mint.replay_receipt(compile_source("input a; output a + 1;"), [i + 1])
        p = tmp_path / f"n{i}.json"
        p.write_text(json.dumps(receipt), encoding="utf-8")
        names.append(p.name)
    (tmp_path / "list.txt").write_text(
        "# a comment and a blank line must be ignored\n\n" + "\n".join(names) + "\n",
        encoding="utf-8")

    if impl == "python":
        argv = [sys.executable, "-m", "obsign_verify.cli"]
    elif impl == "javascript":
        if not _HAS_NODE and "node" not in _REQUIRED:
            pytest.skip("node not installed")
        argv = ["node", str(repo / "js" / "bin" / "obsign-verify.js")]
    else:
        exe = _rust_binary()
        if exe is None:
            if "rust" in _REQUIRED:
                raise AssertionError("OBSIGN_REQUIRE=rust was set but the release "
                                     "binary is not built -- a skip reads like a pass")
            pytest.skip("rust/target/release binary is not built")
        argv = [str(exe)]

    def run(extra):
        return subprocess.run([*argv, *extra], cwd=tmp_path, capture_output=True,
                              text=True, encoding="utf-8", timeout=600, check=False)

    direct = run(names)
    listed = run(["--chain-list", "list.txt"])
    assert direct.returncode == 0, direct.stdout + direct.stderr
    assert direct.returncode == listed.returncode, listed.stdout + listed.stderr
    assert listed.stdout.count("VERIFIED") == len(names), (
        f"--chain-list reached {listed.stdout.count('VERIFIED')} of {len(names)} "
        f"receipts; a transport that drops receipts makes a deep-chain test pass by "
        f"verifying a shorter chain\n{listed.stdout}")
    # Same receipts, same order, same verdicts -- compared on the file names the report
    # prints, because the three CLIs word their prose differently by design.
    for name in names:
        assert name in listed.stdout, f"{name} never reached the {impl} verifier"


@pytest.mark.skipif(not _HAS_NODE and "node" not in _REQUIRED, reason="node not installed")
def test_the_javascript_cli_carries_the_same_two_flags(tmp_path):
    from pathlib import Path
    repo = Path(__file__).resolve().parent.parent
    receipt = _honest()
    path = tmp_path / "r.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")

    def run(*extra):
        return subprocess.run(["node", str(repo / "js" / "bin" / "obsign-verify.js"),
                               *extra, str(path)], capture_output=True, text=True,
                              encoding="utf-8", timeout=600, check=False)

    assert run().returncode == 0
    # `--strict-liveness` on an honestly live receipt must still pass: a flag that
    # refuses everything is not a stricter check.
    assert run("--strict-liveness").returncode == 0
    assert run("--expect-program", receipt["params"]["program_sha256"]).returncode == 0
    bad = run("--expect-program", "0" * 64)
    assert bad.returncode == 1
    assert "not the approved program" in bad.stdout, bad.stdout
