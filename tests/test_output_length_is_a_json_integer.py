"""`output.length` is a COUNT, and a count is a JSON integer.

`output.length` rides OUTSIDE the byte hash, exactly as `shape` and `dtype` do for
the array kernel, so `verify()` compares it against the re-executed result rather
than trusting it. The Python comparison was

    len_ok = declared.get("length") in (None, len(out))

and `in` is `==`, which in Python says `True == 1` and `1.0 == 1`. So a receipt
declaring `"length": true` or `"length": 1.0` over a one-element output passed the
check here -- while `js/src/verify.js` requires `typeof declaredLen === 'bigint'`
and `rust/src/verify.rs` requires `v.as_i64()`, and both REFUSE it.

That is the split this format says it cannot absorb, with the REFERENCE
implementation on the lenient side:

    canonical.py  -- "every place two parsers disagree about what LOADS is a place
                     one implementation verifies a document the other cannot read"
    replay.py     -- "`{"mem": true}` was a program that loaded in the reference and
                     nowhere else ... a forger hands the receipt to whichever
                     implementation loads it"

The replay VM's own structural scalars closed this (`_struct_int` excludes bool
before `isinstance(x, int)`); the receipt's own `output` block had not.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from obsign_verify import replay
from obsign_verify.canonical import canonical_sha256, claim_of, load_receipt
from obsign_verify.replayc import compile_source
from obsign_verify.verify import verify

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_needs_node = pytest.mark.skipif(
    not _HAS_NODE and "node" not in _REQUIRED,
    reason="node not available (set OBSIGN_REQUIRE=node to make this leg mandatory)")

_PROGRAM = compile_source("input a; output a * 3;")
_INPUTS = [5]


def _receipt(length) -> dict:
    """A receipt that is honest in every respect except the type of `output.length`.
    Sentinel `...` omits the field entirely (the one shape allowed to skip)."""
    out = replay.run(_PROGRAM, _INPUTS)
    block = {"sha256": replay.output_sha256(out), "dtype": "int64"}
    if length is not ...:
        block["length"] = length
    claim = {"spec": "obsign/receipt/v1", "kernel": replay.SPEC,
             "params": {"program": _PROGRAM,
                        "program_sha256": replay.program_sha256(_PROGRAM),
                        "inputs": list(_INPUTS)},
             "output": block}
    return dict(claim, receipt_sha256=canonical_sha256(claim_of(claim)))


def test_the_honest_integer_length_still_verifies():
    assert verify(_receipt(1))["verified"] is True


def test_an_omitted_length_is_still_allowed():
    assert verify(_receipt(...))["verified"] is True


@pytest.mark.parametrize("length", [True, 1.0],
                         ids=["true-is-not-one", "float-is-not-an-integer"])
def test_a_length_that_is_not_an_integer_is_refused(length):
    """THE SPLIT. Both of these verify in Python today and are refused by the
    JavaScript and Rust verifiers."""
    receipt = _receipt(length)
    # It really is a well-formed document that survives the wire-format loader --
    # this is not a parse-level rejection anyone else would make first.
    load_receipt(json.dumps(receipt))
    res = verify(receipt)
    assert res["verified"] is False, (
        f"output.length {length!r} is not a count, and reading it as one accepts a "
        f"receipt the JavaScript and Rust verifiers refuse")
    assert any("length" in n for n in res["notes"]), res["notes"]


@pytest.mark.parametrize("length", [0, 2, "1", None],
                         ids=["zero", "wrong-count", "string", "null"])
def test_other_wrong_lengths_keep_their_existing_verdicts(length):
    """`null` is the documented "no length declared" spelling and still passes;
    everything else is a mismatch."""
    expected = length is None
    assert verify(_receipt(length))["verified"] is expected


@_needs_node
@pytest.mark.parametrize("length", [1, True, 1.0, 2, ...],
                         ids=["one", "true", "float", "wrong-count", "absent"])
def test_python_and_javascript_agree_on_every_length_shape(tmp_path, length):
    receipt = _receipt(length)
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    proc = subprocess.run(["node", "js/bin/obsign-verify.js", "--json", str(path)],
                          capture_output=True, text=True, timeout=600, check=False)
    assert proc.stdout.strip(), proc.stderr[-2000:]
    js = json.loads(proc.stdout)[0]["verified"]
    py = verify(receipt)["verified"]
    assert py == js, (f"output.length {length!r}: python verified={py}, "
                      f"javascript verified={js} -- a forger picks the verifier")
