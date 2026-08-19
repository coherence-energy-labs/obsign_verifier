"""The boundary-crossing test. This file is the one that would have caught it.

WHAT SHIPPED, AND WHY EVERY GREEN TEST STAYED GREEN

`obsign/signature/v2` says the signed message is the domain tag `obsign/signature/v2`
followed by a NUL, followed by the canonical hash of the covered attribute set. The
producer implemented that. This verifier signed the BARE hash. So for three releases
the producer reported its own receipts valid, this package reported the SAME FILES
`InvalidSignature`, and every published v2 receipt failed in the tool customers are
told to run.

No assertion was missing in the ordinary sense. What was missing was an ARTIFACT.
Every signature test in `test_verifier.py` built its own signature with this package's
own code and then checked it with this package's own code -- so the suite proved the
verifier agreed with itself, which it always will, including about a mistake. The
package shipped ZERO producer-signed receipts, so the round trip was never once
executed in either direction.

The fixtures below were produced by running `obsign.signing.sign_receipt` in the
producer (`tools/emit_verifier_conformance.py` over there). They are bytes from the
other side of the boundary. Regenerate them whenever the spec changes; if this file
goes red, the two implementations have diverged and one of them is lying.

NOTE ON THE KEY. These are signed with a fixed, published, non-production TEST key.
A valid signature proves "signed by this key" and never "by someone you should
believe" -- which is exactly why issuer trust is out of scope. Nothing here should be
read as attested by Coherence Energy Labs.
"""

import copy
import json

import pytest

from obsign_verify import data_path, load_receipt, verify

CORPUS = ("producer_signed_tau_field_fixed.json",
          "producer_signed_replay.json",
          "producer_signed_case_unbound.json")


def _load(name):
    return load_receipt(data_path("conformance", name).read_text(encoding="utf-8"))


@pytest.fixture
def signed():
    """The bound-case fixture, re-derivable by this verifier's replay path."""
    return _load("producer_signed_replay.json")


def test_the_conformance_corpus_is_present_and_not_vacuous():
    """A corpus that quietly became empty would make every test below pass."""
    found = sorted(p.name for p in data_path("conformance").glob("*.json"))
    assert found == sorted(CORPUS), found


@pytest.mark.parametrize("name", CORPUS)
def test_a_receipt_the_PRODUCER_signed_is_accepted_here(name):
    """The whole point. Not "a signature we made verifies" -- one THEY made does."""
    pytest.importorskip("cryptography")
    res = verify(_load(name))
    assert res["integrity"] is True
    assert res["reproduced"] is True
    sig = res["signature"]
    assert sig["present"] is True
    assert sig["valid"] is True, sig["detail"]
    assert sig["identity_bound"] is True, "a v2 signature must bind the signer"
    assert sig["attributed_signer"] == sig["claimed_signer"]
    assert res["verified"] is True, res["notes"]


@pytest.mark.parametrize("name", ("producer_signed_tau_field_fixed.json",
                                  "producer_signed_replay.json"))
def test_the_producer_bound_the_case_block(name):
    """`case` is excluded from `receipt_sha256`, so if the signature does not bind it
    the examiner's name on a court report is attested by nothing."""
    pytest.importorskip("cryptography")
    sig = verify(_load(name))["signature"]
    assert sig["bound_metadata"] == ["case"]
    assert sig["unbound_metadata"] == []


def test_an_UNBOUND_case_still_verifies_but_is_reported_as_unattested():
    """`obsign.accountable.export_case` attaches `case` AFTER signing, so `binds` is
    empty and the block is genuinely uncovered. Refusing it would break an honest
    producer path; staying silent about it would launder an unattested name into a
    court report. It verifies, and it says so."""
    pytest.importorskip("cryptography")
    res = verify(_load("producer_signed_case_unbound.json"))
    assert res["verified"] is True
    assert res["signature"]["valid"] is True
    assert res["signature"]["bound_metadata"] == []
    assert res["signature"]["unbound_metadata"] == ["case"]
    assert any("NOT covered by the signature" in n for n in res["notes"])


# --------------------------------------------------------------- the forgeries
#
# Each of these was EXECUTED against the shipped verifier and returned
# `valid: True, identity_bound: True`. They are here so that can never be true again.

def test_deleting_the_binds_key_is_a_REJECT_not_a_skip(signed):
    """THE EXPLOIT. `binds` is attacker-supplied and was used to decide whether the
    staleness check ran at all (`binds = sig.get("binds")` / `if binds:`). Deleting one
    key from the JSON skipped the check instead of failing it -- and because `case` is
    excluded from `receipt_sha256`, `case.examiner` could then be rewritten to
    "Dr. J. Smith, FBI Digital Forensics" on a cryptographically valid receipt, which
    reported valid, identity_bound, attributed to the original examiner.

    The producer's verifier refused this exact file. The public one did not.
    """
    pytest.importorskip("cryptography")
    r = copy.deepcopy(signed)
    del r["signature"]["binds"]
    r["case"]["examiner"] = "Dr. J. Smith, FBI Digital Forensics"
    r["case"]["case_id"] = "FBI-2026-9911"

    res = verify(r)
    sig = res["signature"]
    assert sig["valid"] is False
    assert sig["identity_bound"] is False
    assert sig["attributed_signer"] is None
    assert res["verified"] is False
    # It must be refused BY THE BINDS CHECK. If the signature step refused it first,
    # this test would pass while the binds fix was absent.
    assert "binds_sha256" in sig["detail"], sig["detail"]


@pytest.mark.parametrize("binds,label", [
    (None, "null"), ([], "empty list"), (["nonexistent"], "a key that is not there"),
    (["case", "case"], "duplicated"), ("case", "a string, not a list"),
    ([1, 2], "a list of non-strings"),
])
def test_no_value_of_binds_can_suppress_the_check(signed, binds, label):
    """A security check must never be gated on attacker-supplied truthiness -- and
    `binds` is not covered by the signature, so EVERY value of it is attacker-supplied.
    `binds_sha256` is covered, so it is the authority: whatever `binds` says, the
    recomputation must reproduce the signed hash or the receipt is refused."""
    pytest.importorskip("cryptography")
    r = copy.deepcopy(signed)
    r["signature"]["binds"] = binds
    r["case"]["examiner"] = "Dr. J. Smith, FBI Digital Forensics"
    sig = verify(r)["signature"]
    assert sig["valid"] is False, f"binds={label} suppressed the check"
    assert sig["attributed_signer"] is None


def test_tampering_with_the_bound_case_is_a_REJECT(signed):
    pytest.importorskip("cryptography")
    r = copy.deepcopy(signed)
    r["case"]["examiner"] = "Dr. J. Smith, FBI Digital Forensics"
    sig = verify(r)["signature"]
    assert sig["valid"] is False
    assert "binds_sha256" in sig["detail"]


def test_deleting_the_whole_bound_block_is_a_REJECT(signed):
    """Removing the evidence is not the same as it never having existed: the signature
    committed to a hash of it."""
    pytest.importorskip("cryptography")
    r = copy.deepcopy(signed)
    del r["case"]
    sig = verify(r)["signature"]
    assert sig["valid"] is False


def test_rewriting_the_signer_is_a_REJECT(signed):
    pytest.importorskip("cryptography")
    r = copy.deepcopy(signed)
    r["signature"]["signer"] = "Dr. J. Smith, FBI Digital Forensics"
    sig = verify(r)["signature"]
    assert sig["valid"] is False
    assert sig["attributed_signer"] is None


def test_a_signature_from_a_DIFFERENT_KEY_is_a_REJECT(signed):
    """A well-formed signature by a key that is not the advertised one."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    r = copy.deepcopy(signed)
    other = Ed25519PrivateKey.generate()
    from obsign_verify.canonical import canonical_sha256
    from obsign_verify.signature import SIG_DOMAIN_V2
    covered = {"spec": "obsign/signature/v2", "alg": "ed25519",
               "public_key": r["signature"]["public_key"],
               "receipt_sha256": r["receipt_sha256"], "signer": r["signature"]["signer"],
               "binds_sha256": r["signature"]["binds_sha256"]}
    r["signature"]["sig"] = other.sign(
        SIG_DOMAIN_V2 + canonical_sha256(covered).encode("ascii")).hex()
    assert verify(r)["signature"]["valid"] is False

    # And swapping in the OTHER key's public half does not save it either: the public
    # key is inside the covered attributes, so the message changes with it.
    r["signature"]["public_key"] = other.public_key().public_bytes_raw().hex()
    assert verify(r)["signature"]["valid"] is False


def test_a_signature_over_a_DIFFERENT_BODY_is_a_REJECT(signed):
    """Lift a genuine signature block onto another receipt and reseal the claim, so
    integrity passes. `receipt_sha256` is inside the covered attributes."""
    pytest.importorskip("cryptography")
    from obsign_verify.canonical import canonical_sha256, claim_of

    r = copy.deepcopy(signed)
    r["params"] = dict(r["params"], note="a different number entirely")
    r["receipt_sha256"] = canonical_sha256(claim_of(r))     # resealed
    res = verify(r)
    assert res["integrity"] is True, "the forgery must survive step 1 or it proves nothing"
    assert res["signature"]["valid"] is False
    assert res["verified"] is False


def test_a_broken_claim_means_the_signature_ATTRIBUTES_NOBODY(signed):
    """A signature attributes a name to a CLAIM. If the claim no longer hashes to
    `receipt_sha256` there is no claim left to attribute, and a caller reading only the
    signature block must not be handed a real examiner's name over rewritten numbers."""
    pytest.importorskip("cryptography")
    r = copy.deepcopy(signed)
    r["output"] = dict(r["output"], sha256="00" * 32)       # NOT resealed
    sig = verify(r)["signature"]
    assert sig["valid"] is False
    assert sig["attributed_signer"] is None
    assert "NOT evaluated" in sig["detail"]


def test_the_corpus_is_byte_clean():
    """These are byte-pinned package data. A CRLF conversion has broken two pins in
    this estate already."""
    for name in CORPUS:
        raw = data_path("conformance", name).read_bytes()
        assert bytes([13, 10]) not in raw, f"CRLF in {name}"
        json.loads(raw.decode("utf-8"))


def test_self_check_runs_the_producer_signed_corpus_and_CAN_FAIL(monkeypatch):
    """`--self-check` is the one command a stranger runs on the wheel they installed,
    so it is the one place the boundary crossing cannot be faked by a test suite that
    talks to itself. It must accept the producer-signed corpus with the signer bound,
    AND it must go red on the 0.2.1 behaviour -- a check that cannot fail is as dark
    as one that cannot pass."""
    from obsign_verify import signature as sigmod
    from obsign_verify.cli import main

    assert main(["--self-check", "--quiet"]) == 0

    # Drive the verifier back to 0.1.0-0.2.1: sign/check the BARE canonical hash.
    # Every producer-signed receipt must now be refused, and so must the self-check.
    monkeypatch.setattr(sigmod, "SIG_DOMAIN_V2", bytes())
    assert main(["--self-check", "--quiet"]) == 1, (
        "self-check stayed green while the verifier checked a different message than "
        "the producer signed -- the corpus is not gating it")


def test_self_check_fails_if_the_binds_stripping_forgery_is_ACCEPTED(monkeypatch):
    """The other half: the forgery the public verifier once accepted is built inside
    the self-check and must be refused. Make the verifier accept it (skip the binds
    comparison whenever `binds` is absent, as 0.2.1 did) and the self-check must go
    red for THAT reason alone."""
    from obsign_verify import signature as sigmod
    from obsign_verify.cli import main

    real_check = sigmod.check

    def lenient(receipt):
        out = real_check(receipt)
        sig = receipt.get("signature") or {}
        if out["present"] and "binds" not in sig and not out["valid"] \
                and "binds_sha256" in out["detail"]:
            # 0.2.1: no `binds` key -> the comparison never ran -> valid, bound.
            out.update(valid=True, identity_bound=True,
                       attributed_signer=sig.get("signer"), detail="signature verifies")
        return out

    monkeypatch.setattr(sigmod, "check", lenient)
    assert main(["--self-check", "--quiet"]) == 1, (
        "self-check stayed green while a binds-stripped forgery was accepted")


def test_self_check_without_cryptography_names_the_skip_and_does_not_claim_acceptance(
        monkeypatch, capsys):
    """Signature checking is an optional extra. A bare install must not FAIL the
    self-check (refusing what it cannot check is correct), and it must not PASS the
    corpus either. It must say, by name, that the round trip was not exercised."""
    import sys

    from obsign_verify.cli import main

    for k in list(sys.modules):
        if k == "cryptography" or k.startswith("cryptography."):
            monkeypatch.setitem(sys.modules, k, None)    # import -> ImportError

    assert main(["--self-check"]) == 0
    out = capsys.readouterr().out
    assert out.count("NOT CHECKED") == 3, out
    assert "0/3 producer-signed receipt(s) exercised" in out
    assert "accepted with the signer bound" not in out, "claimed a round trip it never ran"
    assert "pip install 'obsign-verify[sig]'" in out
