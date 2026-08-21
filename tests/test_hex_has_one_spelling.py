"""A signature has ONE textual spelling, and all four implementations agree on it.

`bytes.fromhex` is not the strict reader it looks like: it skips ASCII whitespace.
So `"ab cd" + rest` decodes to the same 64 bytes as `"abcd" + rest`, and this
reference implementation called such a receipt VALID while `Buffer.from(s, 'hex')`
in the JavaScript port and the Rust decoder both called the same file INVALID.

The decoded bytes were always identical, so no forged signature ever verified. The
defect was the DISAGREEMENT: one file, two verdicts, from the estate whose entire
argument is that a stranger's verifier reaches the same answer as ours. It was found
by the agent writing docs/SPEC.md, which had to state the rule and discovered the
reference was the non-conforming side.

The rule, now shared by all four: decode, then require the re-encoded form to equal
the input lowercased. Every honest receipt is admitted; every alternative spelling of
one is refused.
"""
from __future__ import annotations

import copy
import json

import pytest

from obsign_verify import data_path, load_receipt
from obsign_verify.verify import verify

pytest.importorskip("cryptography")

CORPUS = "producer_signed_replay.json"


def _honest() -> dict:
    return json.loads(data_path("conformance", CORPUS).read_text(encoding="utf-8"))


def test_the_honest_receipt_still_verifies():
    """The counterweight. FAILS IF the strict rule is too strict -- a refusal that
    also refuses genuine receipts is not a fix, and without this assertion every
    refusal below could be produced by simply breaking the verifier."""
    res = verify(load_receipt(json.dumps(_honest())))
    assert res["signature"]["valid"] is True, res["signature"]["detail"]
    assert res["verified"] is True, res["notes"]


@pytest.mark.parametrize("mutate,label", [
    (lambda s: s[:8] + " " + s[8:], "one embedded space"),
    (lambda s: " " + s, "a leading space"),
    (lambda s: s + " ", "a trailing space"),
    (lambda s: s[:8] + "\t" + s[8:], "an embedded tab"),
    (lambda s: s[:8] + "\n" + s[8:], "an embedded newline"),
])
def test_an_alternative_spelling_of_a_valid_signature_is_refused(mutate, label):
    """FAILS IF `bytes.fromhex` is called on the raw member again without the
    round-trip check. Every case here decodes to the SAME 64 bytes as the honest
    signature, so a lenient reader reports each of them valid."""
    r = _honest()
    r["signature"]["sig"] = mutate(r["signature"]["sig"])
    res = verify(load_receipt(json.dumps(r)))
    assert res["signature"]["valid"] is False, f"{label} was accepted"
    assert res["signature"]["attributed_signer"] is None
    assert res["verified"] is False


def test_the_same_rule_applies_to_the_public_key():
    """The key is hex too, and a reader that is strict about one member and lenient
    about the other still lets two implementations disagree. FAILS IF only `sig` is
    checked."""
    r = _honest()
    key = r["signature"]["public_key"]
    r["signature"]["public_key"] = key[:8] + " " + key[8:]
    res = verify(load_receipt(json.dumps(r)))
    assert res["signature"]["valid"] is False, "a spaced public_key was accepted"


def test_hex_is_CASE_INSENSITIVE_and_both_ports_agree_that_it_is():
    """Uppercase hex is ACCEPTED, deliberately, by this implementation and by the
    JavaScript port -- both lowercase before the round-trip comparison. That is a
    contract, not an oversight, and it is written down here because the first draft
    of this file asserted the opposite from intuition and had to be corrected by
    measuring both ports. FAILS IF either side becomes case-sensitive without the
    other, which would be a fresh cross-implementation split.

    ONLY `sig` is respelled here, and the reason is worth stating: under
    `obsign/signature/v2` the `public_key` is one of the ATTRIBUTES THE SIGNATURE
    COVERS, so its spelling is inside the hashed message. Uppercasing it changes the
    signed bytes and the signature correctly stops verifying -- a cryptographic
    refusal, not an encoding one. `sig` carries no such role: it IS the signature,
    and is never hashed, so its spelling is purely a wire question.
    """
    r = _honest()
    r["signature"]["sig"] = r["signature"]["sig"].upper()
    res = verify(load_receipt(json.dumps(r)))
    assert res["signature"]["valid"] is True, res["signature"]["detail"]


def test_uppercasing_the_public_key_breaks_the_v2_signature_cryptographically():
    """The other half of the pair above, pinned so the distinction cannot be lost:
    `public_key` is a COVERED attribute, so respelling it changes the message that
    was signed. FAILS IF the covered-attribute set stops including public_key --
    which would let a signature be replayed under a differently-spelled key."""
    r = _honest()
    r["signature"]["public_key"] = r["signature"]["public_key"].upper()
    res = verify(load_receipt(json.dumps(r)))
    assert res["signature"]["valid"] is False
    assert res["signature"]["attributed_signer"] is None


def test_the_decoded_bytes_really_are_identical():
    """Proves these cases are about SPELLING, not about corrupted input -- otherwise
    the refusals above would be uninteresting. FAILS IF Python stops skipping
    whitespace (then this test, not the verifier, is what needs updating)."""
    hexed = _honest()["signature"]["sig"]
    spaced = hexed[:8] + " " + hexed[8:]
    assert bytes.fromhex(spaced) == bytes.fromhex(hexed)
    assert spaced != hexed


def test_the_javascript_port_reaches_the_same_verdict():
    """The whole point: this is a CROSS-IMPLEMENTATION rule, and a Python-only test
    cannot see a Python-only fix. FAILS IF the two ports drift apart again."""
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    if shutil.which("node") is None:
        pytest.skip("node is not installed, so the JavaScript leg cannot be run")

    repo = Path(__file__).resolve().parents[1]
    cli = repo / "js" / "bin" / "obsign-verify.js"
    if not cli.is_file():
        pytest.skip(f"the JavaScript port is not present at {cli}")

    r = _honest()
    hexed = r["signature"]["sig"]
    r["signature"]["sig"] = hexed[:8] + " " + hexed[8:]
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "spaced.json"
        p.write_text(json.dumps(r), encoding="utf-8")
        proc = subprocess.run(["node", str(cli), "--json", str(p)],
                              capture_output=True, text=True, encoding="utf-8",
                              timeout=120)
        payload = json.loads(proc.stdout)
        js_valid = payload[0]["signature"]["valid"]
        py_valid = verify(load_receipt(p.read_text(encoding="utf-8")))["signature"]["valid"]
    assert js_valid is False, "the JavaScript port accepted a respelled signature"
    assert py_valid == js_valid, f"python={py_valid} javascript={js_valid}"
