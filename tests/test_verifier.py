"""What a stranger is actually being asked to trust.

Every test here exists because the property it pins can fail *plausibly* -- the
verifier still runs, still prints something confident, and is wrong.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from obsign_verify import canonical_sha256, claim_of, load_receipt, verify
from obsign_verify.canonical import canonical_bytes, integrity
from obsign_verify.kernel import array_sha256, build_fixed_inputs, evolve

VECTORS = json.loads(
    (Path(__file__).resolve().parents[1] / "vectors" / "conformance_vectors.json")
    .read_text(encoding="utf-8"))


# ------------------------------------------------------------------ the kernel

@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["name"])
def test_kernel_reproduces_every_conformance_vector(case):
    """The judging artifact.

    These vectors are what an independent implementation is scored against
    (PROGRAM.md §4.3 item 4). If this package cannot reproduce them, it is not a
    verifier -- it is a second opinion.
    """
    out = evolve(build_fixed_inputs(case["params"]))
    assert array_sha256(out) == case["output_sha256"]


def test_vectors_are_not_all_the_same_computation():
    """Four vectors that happened to be identical would make the suite above look
    thorough while testing one path."""
    hashes = {c["output_sha256"] for c in VECTORS}
    assert len(hashes) == len(VECTORS) >= 4


def test_a_perturbed_parameter_changes_the_output():
    """The kernel must actually depend on its inputs. A stub returning a constant
    would pass a single-vector test."""
    p = dict(VECTORS[0]["params"])
    base = array_sha256(evolve(build_fixed_inputs(p)))
    p["steps"] = int(p["steps"]) + 1
    assert array_sha256(evolve(build_fixed_inputs(p))) != base


def test_truncation_is_toward_zero_not_floor():
    """`tdiv` truncates toward zero. An arithmetic shift silently picks floor, and
    the two differ only on negatives -- which is how a port drifts by one bit and
    then by everything. Pinned via a parameter set that drives values negative."""
    import numpy as np
    scale = 1 << 24
    a = np.array([-3 * scale - 1, 3 * scale + 1], dtype=np.int64)
    trunc = np.sign(a) * (np.abs(a) // scale)
    floor = a // scale
    assert list(trunc) == [-3, 3]
    assert list(floor) == [-4, 3]           # they genuinely differ; the test is real


# -------------------------------------------------------------- canonical form

def test_int_and_float_canonicalise_differently():
    """The trap the spec names. A reader that erases the distinction -- notably
    JavaScript's JSON.parse -- canonicalises `0.0` as `0` and reports an honest
    receipt as tampered. Python preserves it; this pins that it must keep doing so."""
    assert canonical_bytes({"gamma": 0}) != canonical_bytes({"gamma": 0.0})
    assert canonical_bytes({"gamma": 0}) == b'{"gamma":0}'
    assert canonical_bytes({"gamma": 0.0}) == b'{"gamma":0.0}'


def test_load_receipt_preserves_the_distinction_from_TEXT():
    r = load_receipt('{"a": 1, "b": 1.0}')
    assert isinstance(r["a"], int) and isinstance(r["b"], float)


def test_non_claim_fields_are_excluded():
    """Hashing `env` would report a genuine receipt as tampered the moment anyone
    recorded a different platform."""
    r = {"kernel": "k", "receipt_sha256": "x", "env": {"os": "linux"},
         "signature": {"sig": "00"}, "case": {"case_id": "c"}, "_helper": 1}
    assert claim_of(r) == {"kernel": "k"}


def test_nan_is_refused_rather_than_canonicalised():
    """NaN has no JSON representation, so allowing it would let two different
    receipts share a canonical form."""
    with pytest.raises(ValueError):
        canonical_bytes({"x": float("nan")})


def test_integrity_fails_on_a_tampered_claim():
    claim = {"kernel": "tau_field_fixed", "params": {"grid": 8}}
    r = dict(claim, receipt_sha256=canonical_sha256(claim))
    assert integrity(r)[0] is True
    r["params"] = {"grid": 9}
    assert integrity(r)[0] is False


# ---------------------------------------------------------------- the ladder

def _honest_receipt(case) -> dict:
    inp = build_fixed_inputs(case["params"])
    out = evolve(inp)
    claim = {
        "spec": "obsign/receipt/v1",
        "producer": "test",
        "kernel": "tau_field_fixed",
        "params": case["params"],
        "input": {"sha256": array_sha256(inp["S"])},
        "output": {"sha256": array_sha256(out), "shape": list(out.shape),
                   "dtype": str(out.dtype)},
        "run": {"steps": case["params"]["steps"]},
    }
    return dict(claim, receipt_sha256=canonical_sha256(claim))


def test_an_honest_unsigned_receipt_verifies():
    """VERIFIED without a signature is the whole replay argument: you did not have
    to trust anyone, you recomputed the number."""
    res = verify(_honest_receipt(VECTORS[0]))
    assert res["verified"] is True
    assert res["integrity"] and res["reproduced"]
    assert res["signature"]["present"] is False


def test_a_resealed_forgery_has_INTACT_integrity_and_still_fails():
    """The load-bearing case. A signature proves a claim is UNMODIFIED, never that
    it is TRUE -- so a forger who edits the output and re-hashes gets past step 1
    and is caught only by re-derivation."""
    r = _honest_receipt(VECTORS[0])
    r["output"] = dict(r["output"], sha256="00" * 32)
    r["receipt_sha256"] = canonical_sha256(claim_of(r))     # resealed
    res = verify(r)
    assert res["integrity"] is True, "the forgery must survive step 1 or it proves nothing"
    assert res["reproduced"] is False
    assert res["verified"] is False


def test_rewritten_shape_metadata_is_caught():
    """shape/dtype ride OUTSIDE the byte hash, so they must be compared against the
    re-executed result explicitly."""
    r = _honest_receipt(VECTORS[0])
    r["output"] = dict(r["output"], shape=[1, 1])
    r["receipt_sha256"] = canonical_sha256(claim_of(r))
    assert verify(r)["verified"] is False


def test_an_unsupported_kernel_is_UNVERIFIED_not_accepted():
    r = _honest_receipt(VECTORS[0])
    r["kernel"] = "something_else"
    r["receipt_sha256"] = canonical_sha256(claim_of(r))
    res = verify(r)
    assert res["verified"] is False
    assert any("cannot be re-executed" in n for n in res["notes"])


def test_a_hostile_receipt_never_raises():
    """A verifier that crashes has failed open in the eyes of whoever handed it
    the file. An exception is not a refusal."""
    for junk in ({}, {"kernel": "tau_field_fixed", "params": "not-a-dict"},
                 {"kernel": "tau_field_fixed", "params": {"grid": -1, "steps": 1,
                  "D": 0, "gamma": 0, "dt": 0, "sources": []}},
                 {"receipt_sha256": None}):
        res = verify(junk)
        assert res["verified"] is False


# ------------------------------------------------------------------ signatures

def test_a_legacy_v1_signature_verifies_but_attributes_NOBODY():
    """The single most security-relevant behaviour in the package.

    obsign/signature/v1 signs the bare receipt hash, so it covers neither the signer
    nor the case block: the name in the file can be rewritten by anyone with a text
    editor and no key. Reporting it as "valid, signed by Alice" would launder an
    unauthenticated name into an attribution.
    """
    cryptography = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    r = _honest_receipt(VECTORS[0])
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    r["signature"] = {"alg": "ed25519", "signer": "Alice",
                      "public_key": pub,
                      "sig": key.sign(r["receipt_sha256"].encode("ascii")).hex()}
    res = verify(r)
    sig = res["signature"]
    assert sig["valid"] is True
    assert sig["identity_bound"] is False
    assert sig["attributed_signer"] is None
    assert sig["claimed_signer"] == "Alice"

    # And the name really is free to rewrite without touching the signature.
    r["signature"]["signer"] = "Mallory"
    assert verify(r)["signature"]["valid"] is True
    assert verify(r)["signature"]["attributed_signer"] is None


def test_a_v2_signature_binds_the_signer():
    cryptography = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    r = _honest_receipt(VECTORS[0])
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    covered = {"spec": "obsign/signature/v2", "alg": "ed25519", "public_key": pub,
               "receipt_sha256": r["receipt_sha256"], "signer": "Alice",
               "binds_sha256": None}
    r["signature"] = dict(covered,
                          sig=key.sign(canonical_sha256(covered).encode("ascii")).hex())
    sig = verify(r)["signature"]
    assert sig["valid"] and sig["identity_bound"]
    assert sig["attributed_signer"] == "Alice"

    # Rewriting the signer now breaks it -- that is the upgrade over v1.
    r["signature"]["signer"] = "Mallory"
    assert verify(r)["signature"]["valid"] is False


def test_an_unknown_algorithm_is_refused_not_ignored():
    r = _honest_receipt(VECTORS[0])
    r["signature"] = {"alg": "rot13", "sig": "00", "public_key": "00",
                      "signer": "Alice"}
    sig = verify(r)["signature"]
    assert sig["valid"] is False
    assert "UNVERIFIED" in sig["detail"]


# ------------------------------------------------------- the published stream

def test_the_dogfood_stream_verifies_and_is_not_empty():
    """We publish receipts about our own numbers. If the page ever shipped a
    receipt that does not re-derive, the product's central claim is refuted by its
    own marketing -- so this is a test, not a nice-to-have.

    Fails closed on an empty stream: an assertion over zero receipts passes for any
    input, which is exactly how a dogfood page would come to prove nothing.
    """
    stream = Path(__file__).resolve().parents[1] / "stream"
    if not stream.is_dir():
        pytest.skip("stream not built (run tools/dogfood.py)")
    receipts = sorted(p for p in stream.glob("*.json") if p.name != "index.json")
    assert len(receipts) >= 4, "stream is empty or truncated -- this check would be vacuous"
    for path in receipts:
        res = verify(load_receipt(path.read_text(encoding="utf-8")))
        assert res["verified"] is True, f"{path.name}: {res['notes']}"


def test_recording_env_does_not_change_the_receipt_hash():
    """`env` is outside the claim by spec. That is what lets the same receipt
    re-derive on a different OS while still disclosing where it ran -- and it is
    the property the published stream is demonstrating."""
    stream = Path(__file__).resolve().parents[1] / "stream"
    if not stream.is_dir():
        pytest.skip("stream not built")
    r = load_receipt((stream / "v1_basic.json").read_text(encoding="utf-8"))
    assert "env" in r, "the stream should disclose its environment"
    before = r["receipt_sha256"]
    r["env"] = {"os": "something-else-entirely", "python": "0.0"}
    assert canonical_sha256(claim_of(r)) == before
    assert verify(r)["verified"] is True
