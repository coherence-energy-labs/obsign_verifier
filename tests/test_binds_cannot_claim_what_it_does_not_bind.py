"""Two ways this verifier described a signature's coverage more generously than
the signature supports.

1. `binds` MAY NAME A KEY THAT IS NOT IN THE FILE.

   `binds_sha256` is computed over the keys actually PRESENT (`binds_hash` skips
   the rest, deliberately -- hashing a missing key as null would be a second
   canonical form). `binds` itself is NOT covered by the signature. Put those two
   facts together and a name for an absent key changes nothing about the hash, so
   the recomputation passes and the verifier then reports

       bound_metadata: ["case", "examiner", "chain_of_custody"]

   on a receipt containing none of them, from a list anyone can edit with no key.
   The module's own docstring says a lying `binds` "can only FAIL the comparison,
   never skip it" -- and this is the shape of lie that does neither: it passes.

   A producer never emits such a list, so there are only two ways to see one: the
   bound block was DELETED since signing (which must fail) or the list was padded
   (which must also fail). Both are refusals.

2. ONLY `case` WAS EVER REPORTED AS UNATTESTED.

   `OUT_OF_CLAIM_FACT` is a hardcoded one-element tuple, so `env` and every
   `_`-prefixed key rode outside the claim hash and outside the signature with no
   mention at all. That is not hypothetical: the producer stores its VERDICTS
   there -- `obsign authenticity` writes `_combined_verdict` ("AUTHENTIC
   PROVENANCE (certain) ...") and `_aigen` as `_`-prefixed annotations, exactly
   because they are outside the claim. A signed authenticity report can therefore
   have its printed verdict rewritten by anyone with a text editor, and the
   producer's own verifier says so out loud while this one said nothing.

   The producer computes that set rather than enumerating it (`signing.unbound_keys`,
   whose comment names this exact defect). This does too, as `unattested_metadata`.
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
sys.path.insert(0, str(REPO / "src"))

from obsign_verify.canonical import canonical_sha256
from obsign_verify.signature import SIG_DOMAIN_V2, check
from obsign_verify.verify import verify

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = "node" in {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}

pytest.importorskip("cryptography")


def _sign(receipt: dict, signer: str, binds=()):
    """Mint a genuine obsign/signature/v2 over `receipt`, byte-for-byte as the
    producer does."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw).hex()
    bound = {k: receipt[k] for k in binds if k in receipt}
    bh = canonical_sha256(bound) if bound else None
    covered = {"spec": "obsign/signature/v2", "alg": "ed25519", "public_key": pub,
               "receipt_sha256": receipt["receipt_sha256"], "signer": signer,
               "binds_sha256": bh}
    msg = SIG_DOMAIN_V2 + canonical_sha256(covered).encode("ascii")
    receipt["signature"] = {"spec": "obsign/signature/v2", "alg": "ed25519",
                            "signer": signer, "public_key": pub,
                            "binds": sorted(bound), "binds_sha256": bh,
                            "sig": key.sign(msg).hex()}
    return receipt


def _receipt(**extra):
    # a kernel this verifier cannot re-execute: the ladder then reports "not
    # verified by re-derivation" and still runs the signature gate, which is the
    # step under test here
    claim = {"spec": "obsign/receipt/v1", "kernel": "obsign/accountable/v1",
             "params": {"grid": 4, "steps": 1},
             "output": {"sha256": "b" * 64, "shape": [4], "dtype": "int64"}}
    r = dict(claim)
    r["receipt_sha256"] = canonical_sha256(claim)
    r.update(extra)             # env / case / _keys ride OUTSIDE the claim hash
    return r


# --------------------------------------------------------------------------- #
# 1. a `binds` list that names keys the receipt does not contain
# --------------------------------------------------------------------------- #
def test_binds_naming_an_absent_key_is_refused():
    r = _sign(_receipt(), "Alice", binds=())
    assert r["signature"]["binds"] == [] and r["signature"]["binds_sha256"] is None
    assert check(r)["identity_bound"] is True                # genuine, as minted

    r["signature"]["binds"] = ["case", "examiner", "chain_of_custody"]
    out = check(r)
    assert out["valid"] is False, (
        "an unsigned, attacker-supplied list made the verifier state that this "
        f"signature binds {out['bound_metadata']!r} on a receipt containing none "
        f"of them: {out['detail']!r}")
    assert "case" not in out["bound_metadata"]
    assert out["identity_bound"] is False
    assert out["attributed_signer"] is None


def test_padding_a_genuine_binds_list_is_refused():
    r = _sign(_receipt(case={"case_id": "C-1", "examiner": "Dr. Real"}),
              "Dr. Real", binds=("case",))
    assert check(r)["bound_metadata"] == ["case"]

    r["signature"]["binds"] = ["affidavit", "case"]
    out = check(r)
    assert out["valid"] is False, (
        f"`affidavit` was reported as bound by a signature that never saw it: "
        f"{out['bound_metadata']!r}")


def test_deleting_a_bound_block_is_still_refused():
    """The other reading of a name with no key behind it: the block was removed."""
    r = _sign(_receipt(case={"case_id": "C-1", "examiner": "Dr. Real"}),
              "Dr. Real", binds=("case",))
    del r["case"]
    out = check(r)
    assert out["valid"] is False and out["identity_bound"] is False


def test_a_genuine_receipt_is_untouched():
    """A refusal nothing can pass is an outage, not a control."""
    r = _sign(_receipt(case={"case_id": "C-1", "examiner": "Dr. Real"}, env={"python": "3.11"}),
              "Dr. Real", binds=("case",))
    out = check(r)
    assert out["valid"] is True and out["identity_bound"] is True
    assert out["attributed_signer"] == "Dr. Real"
    assert out["bound_metadata"] == ["case"]

    plain = _sign(_receipt(), "Alice", binds=())
    assert check(plain)["identity_bound"] is True


# --------------------------------------------------------------------------- #
# 2. every out-of-claim key must be reported, not just `case`
# --------------------------------------------------------------------------- #
def test_an_underscore_verdict_field_is_reported_as_unattested():
    """`obsign authenticity` writes its printed verdict into `_combined_verdict`,
    which is outside the claim hash by construction. On a genuine signed report
    anyone can rewrite it, and this verifier mentioned nothing."""
    r = _receipt(env={"python": "3.11"},
                 _combined_verdict="AUTHENTIC PROVENANCE (certain): trusted issuer",
                 _aigen={"ai_generated_likelihood": 0.01})
    _sign(r, "Coherence Energy Labs", binds=())
    out = check(r)
    assert out["valid"] is True and out["identity_bound"] is True

    unattested = set(out.get("unattested_metadata") or [])
    assert {"_combined_verdict", "_aigen", "env"} <= unattested, (
        "the printed verdict of a signed authenticity report rides outside the "
        "signature and this verifier did not say so: "
        f"unattested_metadata={sorted(unattested)}")
    assert "_combined_verdict" in out["detail"], (
        f"the reader is never shown the field: {out['detail']!r}")

    # and it reaches the ladder's notes, which is what a CLI user actually sees
    v = verify(r)
    assert any("_combined_verdict" in n for n in v["notes"]), v["notes"]


def test_a_bound_key_is_not_reported_as_unattested():
    r = _receipt(case={"case_id": "C-1", "examiner": "Dr. Real"})
    _sign(r, "Dr. Real", binds=("case",))
    out = check(r)
    assert "case" not in (out.get("unattested_metadata") or [])
    assert out["unbound_metadata"] == []


def test_structural_keys_are_never_called_unattested():
    """`receipt_sha256` and `signature` are the hash and the signature themselves."""
    r = _sign(_receipt(), "Alice", binds=())
    unattested = set(check(r).get("unattested_metadata") or [])
    assert not ({"receipt_sha256", "signature"} & unattested)


def test_a_v1_signature_reports_every_out_of_claim_key_as_unattested():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    r = _receipt(env={"python": "3.11"}, case={"examiner": "Dr. Real"},
                 _combined_verdict="AUTHENTIC")
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw).hex()
    r["signature"] = {"alg": "ed25519", "signer": "Dr. Real", "public_key": pub,
                      "sig": key.sign(r["receipt_sha256"].encode("ascii")).hex()}
    out = check(r)
    assert out["valid"] is True and out["identity_bound"] is False
    assert {"env", "case", "_combined_verdict"} <= set(out.get("unattested_metadata") or [])


# --------------------------------------------------------------------------- #
# 3. JavaScript must reach the same verdicts -- it is the same spec
# --------------------------------------------------------------------------- #
_JS = r"""
const path = require('path');
const { check } = require(path.join(process.argv[2], 'js', 'src', 'signature.js'));
const { loadReceipt } = require(path.join(process.argv[2], 'js', 'src', 'canonical.js'));
const cases = JSON.parse(require('fs').readFileSync(process.argv[3], 'utf8'));
const out = {};
for (const [name, text] of Object.entries(cases)) {
  try {
    const r = check(loadReceipt(text));
    out[name] = { valid: r.valid, identity_bound: r.identity_bound,
                  attributed_signer: r.attributed_signer,
                  bound_metadata: r.bound_metadata,
                  unbound_metadata: r.unbound_metadata,
                  unattested_metadata: r.unattested_metadata || null,
                  detail: r.detail };
  } catch (e) { out[name] = { threw: String(e && e.message || e) }; }
}
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(not _HAS_NODE and not _REQUIRED, reason="node not installed")
def test_javascript_refuses_and_reports_exactly_as_python_does():
    assert _HAS_NODE, "OBSIGN_REQUIRE=node was set but node is not installed"

    padded = _sign(_receipt(), "Alice", binds=())
    padded["signature"]["binds"] = ["case", "examiner"]

    genuine = _sign(_receipt(case={"case_id": "C-1", "examiner": "Dr. Real"}),
                    "Dr. Real", binds=("case",))

    verdicty = _receipt(env={"python": "3.11"}, _combined_verdict="AUTHENTIC (certain)")
    _sign(verdicty, "Coherence Energy Labs", binds=())

    cases = {"padded_binds": json.dumps(padded),
             "genuine_bound_case": json.dumps(genuine),
             "underscore_verdict": json.dumps(verdicty)}

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        (tmp / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
        (tmp / "run.js").write_text(_JS, encoding="utf-8")
        p = subprocess.run(["node", str(tmp / "run.js"), str(REPO), str(tmp / "cases.json")],
                           capture_output=True, text=True, timeout=120, check=False)
    assert p.returncode == 0, p.stdout + p.stderr
    js = json.loads(p.stdout.strip().splitlines()[-1])

    for name, text in cases.items():
        py = check(json.loads(text))
        assert "threw" not in js[name], f"{name}: JavaScript threw: {js[name]}"
        assert js[name]["valid"] == py["valid"], f"{name}: valid"
        assert js[name]["identity_bound"] == py["identity_bound"], f"{name}: identity_bound"
        assert js[name]["attributed_signer"] == py["attributed_signer"], f"{name}: signer"
        assert js[name]["bound_metadata"] == py["bound_metadata"], f"{name}: bound_metadata"
        assert sorted(js[name]["unattested_metadata"] or []) == \
               sorted(py.get("unattested_metadata") or []), f"{name}: unattested_metadata"
