"""Signature checking, and the distinction that actually matters.

`obsign/signature/v2` covers `{spec, alg, public_key, receipt_sha256, signer,
binds_sha256}`. Two properties follow:

* **The attributed signer is inside what the signature covers.** Rewriting
  `signer` invalidates the signature.
* **`binds_sha256` extends coverage to metadata that lives OUTSIDE the claim hash
  but is still presented as fact** -- specifically the forensic `case` block, which
  is rendered into a court-facing report. A valid signature over a *stale*
  `binds_sha256` is not a pass.

Legacy `obsign/signature/v1` signs the ASCII `receipt_sha256` alone. It therefore
covers neither the signer nor the case block, so the name it carries **can be
rewritten by anyone with a text editor and no key**.

v1 signatures still verify -- old receipts do not stop working -- but reporting
them as simply "valid, signed by Alice" would launder an unauthenticated name into
an attribution. The spec requires `identity_bound: false` and
`attributed_signer: null`, and this module refuses to collapse the two cases. That
refusal is the single most security-relevant line in the package.
"""

from __future__ import annotations

from .canonical import canonical_sha256

#: Only Ed25519 today. An unknown algorithm is UNVERIFIED, never "fine".
SUPPORTED_ALGS = ("ed25519",)


def _ed25519_ok(public_key_hex: str, signature_hex: str, message: bytes) -> tuple[bool, str]:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False, "cryptography not installed (pip install 'obsign-verify[sig]')"
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), message)
        return True, "signature verifies"
    except Exception as exc:                       # any failure is a refusal
        return False, f"signature does NOT verify ({type(exc).__name__})"


def binds_hash(receipt: dict, keys: list[str]) -> str:
    """Recompute the hash over the named out-of-claim keys, in the stated order."""
    return canonical_sha256({k: receipt.get(k) for k in keys})


def check(receipt: dict) -> dict:
    """Step 3 of the ladder. Returns a dict; never raises.

    `identity_bound` is reported separately from `valid` on purpose. A caller that
    reads only `valid` still cannot print a signer name, because `attributed_signer`
    is None unless the signature actually covered it.
    """
    out = {"present": False, "valid": False, "identity_bound": False,
           "attributed_signer": None, "claimed_signer": None, "detail": ""}

    sig = receipt.get("signature")
    if not isinstance(sig, dict):
        out["detail"] = "no signature (integrity and re-derivation still apply)"
        return out
    out["present"] = True
    out["claimed_signer"] = sig.get("signer")

    alg = (sig.get("alg") or "").lower()
    if alg not in SUPPORTED_ALGS:
        out["detail"] = f"unsupported algorithm {alg!r} - UNVERIFIED, not accepted"
        return out

    sig_hex = sig.get("sig") or sig.get("signature")
    pub_hex = sig.get("public_key")
    receipt_hash = receipt.get("receipt_sha256")
    if not (isinstance(sig_hex, str) and isinstance(pub_hex, str) and receipt_hash):
        out["detail"] = "signature block is missing sig/public_key/receipt_sha256"
        return out

    spec = sig.get("spec")
    if spec == "obsign/signature/v2":
        # The domain tag prevents a v2 signature being replayed as a v1 one.
        covered = {"spec": spec, "alg": sig.get("alg"), "public_key": pub_hex,
                   "receipt_sha256": receipt_hash, "signer": sig.get("signer"),
                   "binds_sha256": sig.get("binds_sha256")}
        message = canonical_sha256(covered).encode("ascii")
        ok, detail = _ed25519_ok(pub_hex, sig_hex, message)
        out["valid"], out["detail"] = ok, detail
        if not ok:
            return out

        # A valid signature over a STALE binds_sha256 is not a pass.
        binds = sig.get("binds")
        if binds:
            recomputed = binds_hash(receipt, list(binds))
            if recomputed != sig.get("binds_sha256"):
                out["valid"] = False
                out["detail"] = ("signature verifies but binds_sha256 is STALE - "
                                 "the bound metadata has changed since signing")
                return out
        out["identity_bound"] = True
        out["attributed_signer"] = sig.get("signer")
        return out

    # Legacy v1: signs the bare receipt hash. Verifies, attributes nothing.
    ok, detail = _ed25519_ok(pub_hex, sig_hex, receipt_hash.encode("ascii"))
    out["valid"] = ok
    out["identity_bound"] = False
    out["attributed_signer"] = None
    out["detail"] = (
        (detail + "; legacy obsign/signature/v1 covers NEITHER the signer NOR the "
                  "case block - the name in this file can be rewritten by anyone "
                  "with a text editor and no key")
        if ok else detail)
    return out
