"""Canonical form and the claim hash.

The whole verifier stands on this file. If canonicalisation is off by one byte, a
genuine receipt reports as tampered and the product's central promise inverts.

THE INT/FLOAT TRAP, which the spec calls out by name

Python writes `1.0` for a float and `1` for an int, and the two canonicalise to
DIFFERENT bytes and therefore different hashes. A reader that erases the
distinction -- notably JavaScript's `JSON.parse`, where every number is a double --
will canonicalise `gamma: 0.0` as `0` and report an honest receipt as tampered.

Python's `json` preserves it, so this implementation can parse normally. That is
luck, not design, and `tests/` pins it so a future "cleanup" to a float-normalising
parser fails loudly instead of silently rejecting every receipt in the field.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: Fields the spec excludes from the claim. `env` is informational, `signature`
#: and `case` are post-hoc, `receipt_sha256` is the hash itself, `_`-prefixed keys
#: are helpers. A verifier that hashed these would report a genuine receipt as
#: tampered the moment anyone recorded a different platform.
NON_CLAIM = ("receipt_sha256", "env", "signature", "case")


def claim_of(receipt: dict) -> dict:
    """The subset of a receipt that its `receipt_sha256` covers."""
    return {k: v for k, v in receipt.items()
            if k not in NON_CLAIM and not k.startswith("_")}


def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON exactly as docs/SPEC.md defines it.

    `allow_nan=False` is load-bearing, not tidiness: NaN and Infinity have no JSON
    representation, so permitting them would let two different receipts share a
    canonical form.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def load_receipt(text: str) -> dict:
    """Parse receipt TEXT into a dict, preserving the int/float distinction.

    Takes text rather than a path so the caller controls I/O, and so a port to
    another language has an obvious seam at the only place the trap can bite.
    """
    # Reject the bare Infinity / -Infinity / NaN tokens. Python's json ACCEPTS them
    # by default; RFC 8259 forbids them, and both the npm and browser hand-parsers
    # reject them. Without this, a receipt carrying `"env": {"x": NaN}` still verified
    # in Python while the two JS verifiers could not even parse it -- an N-version
    # split. (env is excluded from the claim, so it does not otherwise change the
    # hash; the point is that all four implementations must agree on what LOADS.)
    def _no_constants(tok):
        raise ValueError(f"non-finite constant {tok!r} is not valid JSON")

    def _finite_float(s):
        # A literal like 1e400 does NOT go through parse_constant -- Python parses it
        # to float('1e400') = inf directly. npm and the browser both reject it at
        # parse (their float reader yields Infinity, which has no canonical form), so
        # reject it here too, or a receipt with 1e400 would load in Python and not in
        # the JS verifiers.
        f = float(s)
        if f != f or f in (float("inf"), float("-inf")):
            raise ValueError(f"non-finite float literal {s!r} is not valid JSON")
        return f

    obj = json.loads(text, parse_constant=_no_constants, parse_float=_finite_float)
    if not isinstance(obj, dict):
        raise ValueError("a receipt must be a JSON object")
    return obj


def integrity(receipt: dict) -> tuple[bool, str]:
    """Step 1 of the trust ladder: does `receipt_sha256` recompute from the claim?

    Returns (ok, detail). Never raises on a hostile receipt -- a verifier that
    crashes on malformed input has failed open in the eyes of whoever supplied it.
    """
    stated = receipt.get("receipt_sha256")
    if not isinstance(stated, str) or not stated:
        return False, "no receipt_sha256 to check against"
    try:
        recomputed = canonical_sha256(claim_of(receipt))
    except (ValueError, TypeError) as exc:
        return False, f"claim is not canonicalisable ({type(exc).__name__}: {exc})"
    if recomputed != stated:
        return False, (f"INTEGRITY FAIL - states {stated[:16]}.., "
                       f"recomputes {recomputed[:16]}..")
    return True, "integrity OK"
