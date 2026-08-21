"""Signature checking, and the distinction that actually matters.

`obsign/signature/v2` covers `{spec, alg, public_key, receipt_sha256, signer,
binds_sha256}`. Two properties follow:

* **The attributed signer is inside what the signature covers.** Rewriting
  `signer` invalidates the signature.
* **`binds_sha256` extends coverage to metadata that lives OUTSIDE the claim hash
  but is still presented as fact** -- specifically the forensic `case` block, which
  is rendered into a court-facing report. A valid signature over a *stale*
  `binds_sha256` is not a pass, and neither is one whose `binds` list has been
  deleted: the recomputation runs unconditionally, because `binds` is supplied by
  whoever hands you the file.

The v2 message is `b"obsign/signature/v2\\x00" + sha256(canonical(covered))`. The
domain tag is not decoration: without it the signed bytes are a bare 64-char hex
digest, which is exactly what a v1 signature covers. It is also a contract with the
producer -- the two must sign the SAME BYTES, and for three releases they did not.

Legacy `obsign/signature/v1` signs the ASCII `receipt_sha256` alone. It therefore
covers neither the signer nor the case block, so the name it carries **can be
rewritten by anyone with a text editor and no key**.

v1 signatures still verify -- old receipts do not stop working -- but reporting
them as simply "valid, signed by Alice" would launder an unauthenticated name into
an attribution. The spec requires `identity_bound: false` and
`attributed_signer: null`, and this module refuses to collapse the two cases. That
refusal is the single most security-relevant line in the package.

ANY OTHER SPEC IS UNSUPPORTED, WHICH IS A THIRD ANSWER

`spec` is exactly three cases: v2, absent-or-v1, and everything else. The third case
sets `unsupported: True` and returns without checking anything, because there is
nothing here that knows what those bytes cover. It used to fall through to the v1
branch -- so a receipt claiming `obsign/signature/v9` was verified under the weakest
envelope this format has ever had.
"""

from __future__ import annotations

from .canonical import canonical_sha256, claim_of, integrity

#: Only Ed25519 today. An unknown algorithm is UNVERIFIED, never "fine".
SUPPORTED_ALGS = ("ed25519",)

#: The two signature envelopes this verifier knows how to read, and NOTHING ELSE.
#:
#: THE FALL-THROUGH THAT USED TO BE HERE IS THE DEFECT. The dispatch read
#: `if spec == v2: ... else: legacy v1`, so `obsign/signature/v9` -- a spec this code
#: has never seen, whose covered attribute set nobody here can enumerate -- was
#: verified under the WEAKEST historical semantics: v1 signs the bare `receipt_sha256`
#: and covers neither the signer nor the case block. An unknown future version must
#: never inherit that. "I do not know what these bytes mean" is a third answer, and
#: collapsing it into either of the other two is how a verifier starts lying.
#:
#: An ABSENT spec still means v1, because receipts minted before the field existed are
#: real and still verify. A spec that is present and unrecognised -- including one that
#: is not even a string -- is `unsupported`.
SIG_SPEC_V1 = "obsign/signature/v1"
SIG_SPEC_V2 = "obsign/signature/v2"
SUPPORTED_SIG_SPECS = (SIG_SPEC_V1, SIG_SPEC_V2)

#: The v2 signature covers the canonical hash of the attribute set, PREFIXED with a
#: domain tag. The tag is what stops a v2 signature being replayed as a v1 one (v1
#: signs a bare 64-char hex digest, and a 64-char hex digest is exactly what the v2
#: hash is).
#:
#: THIS CONSTANT IS A CROSS-IMPLEMENTATION CONTRACT, NOT A LOCAL CHOICE. Through
#: 0.1.0-0.2.1 this verifier signed and checked the BARE hash while the producer
#: signed the tagged one, so producer and verifier were verifying different bytes:
#: every genuine v2 receipt reported InvalidSignature here while the producer
#: reported it valid. Nothing caught it for the same reason nothing could -- the
#: package shipped ZERO producer-signed receipts, so the round trip was never once
#: executed. `tests/test_producer_conformance.py` executes it against a receipt made
#: by the real producer, and is the only reason this constant cannot drift again.
SIG_DOMAIN_V2 = b"obsign/signature/v2\x00"

#: Keys that live OUTSIDE the claim hash but are still presented as fact. `case`
#: (case_id + examiner) is rendered into a court-facing report, so a signature that
#: does not bind it leaves the two lines a court reads first attested by nothing.
#: Not an automatic refusal -- the producer's post-hoc case export legitimately
#: emits an unbound `case` -- but never silent either.
OUT_OF_CLAIM_FACT = ("case",)

#: Keys that are STRUCTURAL rather than metadata: they are the hash and the signature
#: themselves, so "not covered by the signature" is not a fact about them.
_STRUCTURAL = ("receipt_sha256", "signature")


def unattested_keys(receipt: dict, bound=()) -> list:
    """Every key PRESENT in the receipt that the claim hash does not cover and the
    signature does not bind. COMPUTED, never enumerated.

    `OUT_OF_CLAIM_FACT` above lists `case` and nothing else, so for the whole life
    of this package `env` and every `_`-prefixed key rode outside both the claim
    hash and the signature with no mention at all. They are not obscure corners:
    the producer stores its VERDICTS in `_`-prefixed keys precisely because they are
    outside the claim -- `obsign authenticity` writes `_combined_verdict`
    ("AUTHENTIC PROVENANCE (certain) ...") and `_aigen` there -- so on a genuine,
    valid, identity-bound signed report, the sentence a reader acts on could be
    rewritten by anyone with a text editor while this verifier reported nothing.

    The producer computes this set (`signing.unbound_keys`) with a comment naming
    the same defect: enumerating only `case` meant a new out-of-claim field could be
    forgotten into invisibility. Two implementations of one rule must agree about
    what the signature does NOT cover as much as about what it does.
    """
    claim = claim_of(receipt)
    bound = set(bound or ())
    return sorted(k for k in receipt
                  if k not in claim and k not in _STRUCTURAL and k not in bound)


def _raw_hex(value: str, n_bytes: int) -> bytes | None:
    """Decode EXACTLY `n_bytes` of lowercase hex, or return None.

    `bytes.fromhex` is not the strict reader it looks like: it skips ASCII
    whitespace, so `"ab cd" + rest` decodes to the same bytes as `"abcd" + rest`.
    JavaScript's `Buffer.from(s, 'hex')` and Rust's decoder do not, so the SAME
    receipt reported `valid: true` here and `valid: false` in the other two
    implementations -- one file, two verdicts, which is the exact failure this
    package exists to make impossible. The decoded bytes were always identical, so
    no new signature ever verified; the defect was the disagreement itself.

    The rule is the one JavaScript already enforced: decode, then require the
    re-encoded form to equal the input, lowercased. That admits every honest
    receipt and refuses every alternative spelling of one.
    """
    if not isinstance(value, str):
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    if len(raw) != n_bytes or raw.hex() != value.lower():
        return None
    return raw


def _ed25519_ok(public_key_hex: str, signature_hex: str, message: bytes) -> tuple[bool, str]:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False, "cryptography not installed (pip install 'obsign-verify[sig]')"
    pub_raw = _raw_hex(public_key_hex, 32)
    if pub_raw is None:
        return False, "public key is not 32 raw Ed25519 bytes in hex"
    sig_raw = _raw_hex(signature_hex, 64)
    if sig_raw is None:
        return False, "signature is not 64 raw Ed25519 bytes in hex"
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, message)
        return True, "signature verifies"
    except Exception as exc:                       # any failure is a refusal
        return False, f"signature does NOT verify ({type(exc).__name__})"


def binds_hash(receipt: dict, keys) -> str | None:
    """Recompute the hash that a signature's `binds_sha256` commits to.

    Mirrors the producer exactly, and the two details that look cosmetic are not:

    * only keys actually PRESENT in the receipt enter the hashed object (hashing a
      missing key as `null` would be a second, silently different canonical form);
    * an empty selection is `None`, not the hash of `{}` -- so "this signature binds
      nothing" and "the bound block was deleted" stay distinguishable.

    Key order is irrelevant: the canonical form sorts keys.
    """
    bound = {k: receipt[k] for k in keys if k in receipt}
    return canonical_sha256(bound) if bound else None


def check(receipt: dict) -> dict:
    """Step 3 of the ladder. Returns a dict; never raises.

    `identity_bound` is reported separately from `valid` on purpose. A caller that
    reads only `valid` still cannot print a signer name, because `attributed_signer`
    is None unless the signature actually covered it.
    """
    out = {"present": False, "valid": False, "identity_bound": False,
           # True only when the envelope names a spec this verifier does not implement.
           # Distinct from `valid: False`, which means "I read it and it does not hold";
           # this means "I did not read it, and nothing here is a verdict about it".
           "unsupported": False,
           "attributed_signer": None, "claimed_signer": None, "detail": "",
           "bound_metadata": [], "unbound_metadata": [],
           # the COMPUTED set (see unattested_keys); `unbound_metadata` remains the
           # `case`-shaped answer the wire format and the other ports already carry
           "unattested_metadata": []}

    sig = receipt.get("signature")
    if not isinstance(sig, dict):
        out["detail"] = "no signature (integrity and re-derivation still apply)"
        return out
    out["present"] = True
    out["claimed_signer"] = sig.get("signer")

    # A signature attributes a NAME to a CLAIM. If the claim no longer hashes to
    # `receipt_sha256` there is no claim left to attribute, and reporting the
    # signature as valid would let a caller that reads only this block print a real
    # examiner's name over rewritten numbers. `verify()` already ANDs integrity into
    # its verdict, but `check()` is importable and this block is what gets quoted --
    # so it refuses here too, exactly as the producer's verifier always has.
    ok_integrity, integrity_detail = integrity(receipt)
    if not ok_integrity:
        out["detail"] = f"signature NOT evaluated - {integrity_detail}"
        return out

    # THE ALGORITHM TOKEN IS EXACT, NOT NORMALIZED. This lowercased before
    # comparing, so a receipt carrying "ED25519" was accepted HERE while the
    # producer and the browser verifier -- which both compare the exact token --
    # called the same bytes unsupported. That is a split-brain: one implementation
    # verifies what another refuses, over an `alg` value that is itself inside the
    # signed attribute set, so it is not display formatting to be tidied away.
    # A protocol identifier has one spelling. Anything else is a different receipt.
    #
    # `sig` is attacker-supplied, so `alg` may be any JSON type; comparing without
    # coercing means a number, object, or null simply is not the token, and no
    # `.lower()` can raise past a caller this function promises never to raise to.
    alg = sig.get("alg")
    if alg not in SUPPORTED_ALGS:
        out["detail"] = f"unsupported algorithm {alg!r} - UNVERIFIED, not accepted"
        return out

    # THE SPEC IS DECIDED BEFORE ANY OF THE BYTES IT DESCRIBES ARE READ.
    #
    # `sig`, `public_key` and `binds_sha256` only MEAN anything relative to a spec that
    # says what the signature covers. Reading them first and then discovering the spec
    # is unknown is the same mistake in a different order.
    #
    # A present-but-unrecognised spec (including a non-string one, which is certainly
    # neither of the two tokens) is UNSUPPORTED: not valid, not identity-bound, and
    # attributing nobody. An absent spec is the historical v1 envelope, which real
    # receipts still carry.
    spec = sig.get("spec")
    if spec is not None and spec not in SUPPORTED_SIG_SPECS:
        out["unsupported"] = True
        out["detail"] = f"unsupported signature spec {spec!r} - UNVERIFIED, not accepted"
        return out

    # ONE SPELLING PER FIELD. This read `sig.get("sig") or sig.get("signature")`, and a
    # synonym fallback in a security envelope is a forgery primitive: JavaScript's
    # `str(sig,'sig') || str(sig,'signature')` skipped a non-STRING `sig` and read the
    # alternate member, so `{"sig": 5, "signature": "<valid 128-hex>"}` VERIFIED there
    # and was refused by Python and Rust -- the same file, two verdicts, forger's
    # choice. No receipt ever produced by anything carried `signature` inside the
    # signature block, so the fallback is deleted rather than harmonised: the hex lives
    # in `sig`, it is a string, and anything else is a malformed block.
    # NON-EMPTY, in all three implementations. An empty string is not a 128-hex
    # signature and not a 64-hex key. Treating it as merely "present" split the
    # implementations: this branch fell through to the v1 code below, which populates
    # `unbound_metadata`, while the JavaScript port's falsy check returned early, which
    # does not -- the same refusal reporting two different signature blocks.
    sig_hex = sig.get("sig")
    pub_hex = sig.get("public_key")
    receipt_hash = receipt.get("receipt_sha256")
    if not (isinstance(sig_hex, str) and sig_hex
            and isinstance(pub_hex, str) and pub_hex and receipt_hash):
        out["detail"] = "signature block is missing sig/public_key/receipt_sha256"
        return out

    if spec == SIG_SPEC_V2:
        covered = {"spec": spec, "alg": sig.get("alg"), "public_key": pub_hex,
                   "receipt_sha256": receipt_hash, "signer": sig.get("signer"),
                   "binds_sha256": sig.get("binds_sha256")}
        # Domain-separated, byte-identical to the producer. See SIG_DOMAIN_V2.
        message = SIG_DOMAIN_V2 + canonical_sha256(covered).encode("ascii")
        ok, detail = _ed25519_ok(pub_hex, sig_hex, message)
        out["valid"], out["detail"] = ok, detail
        if not ok:
            return out

        # ---------------------------------------------------------------- binds
        # THE COMPARISON BELOW RUNS UNCONDITIONALLY, AND THAT IS THE ENTIRE POINT.
        #
        # This used to read `binds = sig.get("binds")` / `if binds:` -- a security
        # check gated on a value the attacker supplies. Deleting one key from the
        # JSON skipped the check rather than failing it, and `case` is excluded from
        # `receipt_sha256`, so `case.examiner` could be rewritten to any name at all
        # on a cryptographically valid receipt: `valid: True, identity_bound: True`,
        # attributed to the original examiner. The producer's verifier refused that
        # same file. The public one -- the one customers are told to run -- did not.
        #
        # `binds` is NOT covered by the signature; `binds_sha256` IS. So the signed
        # hash is the authority and the unsigned list is only a hint about how to
        # reproduce it. A missing, empty, or lying `binds` cannot suppress the
        # comparison -- it can only fail it.
        binds = sig.get("binds")
        if binds is None:
            binds = []                       # "binds nothing", and CHECKED as such
        if not isinstance(binds, list) or not all(isinstance(k, str) for k in binds):
            out["valid"] = False
            out["detail"] = ("signature `binds` is not a list of key names - REFUSED "
                             "(the bound metadata cannot be reproduced)")
            return out

        # A NAME THAT IS NOT IN THE FILE IS NOT A BOUND KEY.
        #
        # `binds_hash` hashes only the keys actually PRESENT -- deliberately, and the
        # docstring above says why. Combine that with `binds` being outside the
        # signature and there is a third shape of lie the comparison below cannot
        # catch: pad the list with names for keys the receipt does not contain. The
        # hash is unchanged, the recomputation passes, and this function then reports
        # `bound_metadata: ["case", "examiner"]` for a signature that bound neither
        # and a receipt that holds neither. A producer never emits such a list, so
        # the only readings are "the bound block was deleted since signing" and "the
        # list was padded". Both are refusals; neither is a pass.
        missing = [k for k in binds if k not in receipt]
        if missing:
            out["valid"] = False
            out["detail"] = (
                f"signature `binds` names {sorted(missing)}, which this receipt does "
                f"not contain - the bound block was removed since signing, or the list "
                f"was padded with keys no signature ever covered. REFUSED")
            return out

        recomputed = binds_hash(receipt, binds)
        if recomputed != sig.get("binds_sha256"):
            out["valid"] = False
            out["detail"] = (
                f"signature verifies but its bound metadata {sorted(binds)} does NOT "
                f"reproduce binds_sha256 - the bound block has been changed, removed, "
                f"or the `binds` list was stripped since signing")
            return out

        out["identity_bound"] = True
        out["attributed_signer"] = sig.get("signer")
        out["bound_metadata"] = sorted(binds)

        # Out-of-claim facts the signature does NOT cover. Reported, never assumed
        # harmless: the signature vouches for the signer and for what it bound, and
        # for nothing else that happens to be in the file.
        unbound = [k for k in OUT_OF_CLAIM_FACT if k in receipt and k not in binds]
        out["unbound_metadata"] = unbound
        out["unattested_metadata"] = unattested_keys(receipt, binds)
        if out["unattested_metadata"]:
            out["detail"] += (
                f"; WARNING: {', '.join(out['unattested_metadata'])} "
                f"{'is' if len(out['unattested_metadata']) == 1 else 'are'} present but "
                f"NOT covered by this signature - unattested annotation"
                f"{'' if len(out['unattested_metadata']) == 1 else 's'}, which must not "
                f"be printed as if the signature vouched for "
                f"{'it' if len(out['unattested_metadata']) == 1 else 'them'}")
        return out

    # Legacy v1 -- reached ONLY by `spec: "obsign/signature/v1"` and by an absent spec,
    # never by an unknown one (that returned above). Signs the bare receipt hash:
    # verifies, and attributes nothing.
    ok, detail = _ed25519_ok(pub_hex, sig_hex, receipt_hash.encode("ascii"))
    out["valid"] = ok
    out["identity_bound"] = False
    out["attributed_signer"] = None
    out["bound_metadata"] = []
    # v1 binds NOTHING outside the claim hash, so every out-of-claim fact in the file
    # is unattested. Saying so explicitly is the same refusal as `attributed_signer`.
    out["unbound_metadata"] = [k for k in OUT_OF_CLAIM_FACT if k in receipt]
    out["unattested_metadata"] = unattested_keys(receipt)
    out["detail"] = (
        (detail + "; legacy obsign/signature/v1 covers NEITHER the signer NOR the "
                  "case block - the name in this file can be rewritten by anyone "
                  "with a text editor and no key")
        if ok else detail)
    return out
