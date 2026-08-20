"""The signature algorithm token has ONE spelling, in every implementation.

`check()` used to lowercase `alg` before comparing while the producer and the
browser verifier compared the exact token. A receipt carrying "ED25519" was
therefore ACCEPTED by this package and called unsupported by the other two -- a
split-brain over a field that lives INSIDE the signed attribute set, so it is not
cosmetic normalization. One implementation verifying what another refuses is the
precise failure this project keeps hunting, and it was introduced by the very
change that made the producer strict.

A protocol identifier is bytes, not prose. Anything but the exact token is a
different receipt, and "I do not support this" is its own verdict -- never
"invalid" (which would accuse an honest future format) and never a pass.
"""
from __future__ import annotations

import pytest

from obsign_verify.signature import SUPPORTED_ALGS, check



def _receipt_with_alg(alg):
    """A structurally complete signed receipt whose `alg` is under test.

    The signature itself need not verify: every case here must be refused BEFORE
    any Ed25519 work happens, so what is pinned is that an unknown token never
    reaches the cryptography at all.
    """
    from obsign_verify.canonical import canonical_sha256, claim_of
    claim = {"spec": "obsign/receipt/v1", "kernel": "replay/1", "params": {"x": 1}}
    r = dict(claim)
    r["receipt_sha256"] = canonical_sha256(claim_of(r))
    sig = {"spec": "obsign/signature/v2", "signer": "someone",
           "public_key": "ab" * 32, "sig": "cd" * 64, "binds_sha256": None}
    if alg is not _MISSING:
        sig["alg"] = alg
    r["signature"] = sig
    return r


_MISSING = object()


@pytest.mark.parametrize("alg", [
    "ED25519", "Ed25519", "eD25519", "ed25519 ", " ed25519", "ed25519\n",
    "ed448", "rsa", "none", "", 25519, 1.0, True, None, [], {}, _MISSING,
], ids=lambda a: repr(a) if a is not _MISSING else "missing")
def test_only_the_exact_token_is_supported(alg):
    """Everything that is not exactly `ed25519` is refused, and refused as
    UNSUPPORTED rather than as a valid signature."""
    out = check(_receipt_with_alg(alg))
    assert out["valid"] is not True, (
        f"alg={alg!r} was accepted -- a receipt this package verifies and the "
        f"producer refuses is a split-brain")
    # Assert the REASON, not just the refusal. These fixtures carry a signature
    # that would fail to verify anyway, so `valid is not True` would hold even with
    # the case-normalizing bug present -- the test would pass for the wrong reason
    # and pin nothing. Only the algorithm gate produces this detail, so requiring it
    # proves the token never reached the cryptography.
    assert "unsupported algorithm" in (out.get("detail") or ""), (
        f"alg={alg!r} was refused, but not as UNSUPPORTED -- it reached the Ed25519 "
        f"path instead of being rejected by the token gate: {out.get('detail')!r}")


def test_the_canonical_token_is_the_one_the_producer_writes():
    """A guard on the constant itself: if this list ever grows a cased variant,
    the divergence is back."""
    assert SUPPORTED_ALGS == ("ed25519",), SUPPORTED_ALGS


@pytest.mark.parametrize("alg", [25519, 1.0, True, None, [], {}])
def test_a_non_string_alg_never_raises(alg):
    """`check()` documents that it never raises. `.lower()` on a non-string did,
    and an exception is not a refusal -- to the caller holding the file, a verifier
    that crashes has failed open."""
    out = check(_receipt_with_alg(alg))          # must not raise
    assert out["valid"] is not True, out
