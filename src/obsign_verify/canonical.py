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


# --------------------------------------------------------------------------- #
# WIRE-FORMAT LIMITS
#
# "Valid JSON" is not one thing across languages, and every place two parsers
# disagree about what LOADS is a place one implementation verifies a document the
# other cannot read. Two such splits were measured here:
#
#   integer literals -- CPython refuses a decimal integer over 4300 digits
#     (sys.set_int_max_str_digits); the hand-written JS parser built an unbounded
#     BigInt. A receipt carrying a 5000-digit literal loaded in JavaScript and
#     was refused in Python.
#   nesting depth -- 2000 levels raised RecursionError in Python and parsed
#     cleanly in Node.
#
# Both are the same class as the NaN / 1e400 divergence already closed above, and
# the fix is the same: state the limits, apply them identically everywhere, and
# refuse BEFORE any semantic verification. Duplicate object members are refused
# outright rather than resolved -- last-value-wins is a convention, not a
# guarantee, and downstream JSON readers (security appliances, log pipelines,
# other languages) do not all share it.
#
# The numbers are ~100x the largest shipped receipt (depth 5, 11 members, 35-element
# arrays, 128-byte strings, 10-digit integers, 3 KB) so they bound hostile input
# without coming near honest documents. They are part of the format: changing one
# is a spec decision, and js/src/canonical.js carries the same table.
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_MEMBERS_PER_OBJECT = 1024
MAX_ARRAY_LENGTH = 1 << 20
MAX_STRING_BYTES = 65536
MAX_INT_DIGITS = 4300          # exactly CPython's default, so both sides agree


class WireFormatError(ValueError):
    """The bytes are outside the receipt wire format. Refused before verification."""


#: Names that are not ordinary data fields in JavaScript: assigning them reparents
#: or shadows the receiving object. Python has no such problem, which is exactly why
#: this list must live here too -- a receipt that loads in one implementation and is
#: refused by another is the divergence this format spends its whole budget avoiding,
#: and a JS verifier once REPRODUCED a program carried entirely on a prototype while
#: this one could not read it at all.
_OBJECT_MODEL_KEYS = frozenset({"__proto__", "constructor", "prototype"})


def _no_duplicate_members(pairs):
    seen = set()
    for k, _ in pairs:
        if k in _OBJECT_MODEL_KEYS:
            raise WireFormatError(
                f"object member {k!r} is refused: it names a JavaScript "
                f"object-model slot, not a data field")
        if k in seen:
            raise WireFormatError(
                f"duplicate object member {k!r}: last-value-wins is a parser "
                f"convention, not a guarantee, and two readers may disagree about "
                f"which value this document contains")
        seen.add(k)
    if len(pairs) > MAX_MEMBERS_PER_OBJECT:
        raise WireFormatError(f"object has {len(pairs)} members, limit is {MAX_MEMBERS_PER_OBJECT}")
    return dict(pairs)


def _has_lone_surrogate(text: str) -> bool:
    """An unpaired surrogate has no UTF-8 encoding at all.

    Python refused these already -- but by ACCIDENT, via the UnicodeEncodeError that
    escaped from the length check below, which means the refusal moved whenever that
    check did and carried no explanation. Both JS parsers loaded them. A rule this
    load-bearing is stated, not inherited from an exception.
    """
    prev_high = False
    for ch in text:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDBFF:
            if prev_high:
                return True
            prev_high = True
        elif 0xDC00 <= cp <= 0xDFFF:
            if not prev_high:
                return True
            prev_high = False
        else:
            if prev_high:
                return True
            prev_high = False
    return prev_high


def _check_shape(obj, depth=0):
    """Walk the parsed document and enforce the structural limits.

    `depth` counts CONTAINERS ENTERED, which is npm's and Rust's rule. This used to
    start the top-level object at 0 and bound the deepest VALUE, so a document
    whose innermost container was empty carried 33 containers here and 32 there --
    one document, two answers about whether it loads. Which number is a spec
    choice; that the three disagreed was the defect.
    """
    if isinstance(obj, (dict, list)):
        depth += 1
    if depth > MAX_DEPTH:
        raise WireFormatError(f"nesting deeper than {MAX_DEPTH}")
    if isinstance(obj, str) and _has_lone_surrogate(obj):
        raise WireFormatError(
            "string contains an unpaired surrogate: it has no UTF-8 encoding, so "
            "implementations disagree about whether this document exists at all")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _has_lone_surrogate(k):
                raise WireFormatError("object key contains an unpaired surrogate")
            if len(k.encode("utf-8")) > MAX_STRING_BYTES:
                raise WireFormatError(f"object key longer than {MAX_STRING_BYTES} bytes")
            _check_shape(v, depth)
    elif isinstance(obj, list):
        if len(obj) > MAX_ARRAY_LENGTH:
            raise WireFormatError(f"array of {len(obj)} exceeds {MAX_ARRAY_LENGTH}")
        for v in obj:
            _check_shape(v, depth)
    elif isinstance(obj, str):
        if len(obj.encode("utf-8")) > MAX_STRING_BYTES:
            raise WireFormatError(f"string longer than {MAX_STRING_BYTES} bytes")
    elif isinstance(obj, int) and not isinstance(obj, bool):
        if len(str(abs(obj))) > MAX_INT_DIGITS:
            raise WireFormatError(f"integer with more than {MAX_INT_DIGITS} digits")


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

    # Size first: everything below walks the document, so the cheapest refusal
    # comes before any parsing work is done on an unbounded input.
    if len(text.encode("utf-8")) > MAX_RECEIPT_BYTES:
        raise WireFormatError(f"receipt larger than {MAX_RECEIPT_BYTES} bytes")
    try:
        obj = json.loads(text, parse_constant=_no_constants, parse_float=_finite_float,
                         object_pairs_hook=_no_duplicate_members)
    except RecursionError as e:
        # Depth is bounded explicitly below, but CPython can hit its own recursion
        # limit inside the parser first. A RecursionError escaping a loader reads as
        # a crash rather than a refusal, and a verifier that crashes on hostile input
        # has failed open in the eyes of whoever handed it the file.
        raise WireFormatError("receipt nesting is too deep to parse") from e
    if not isinstance(obj, dict):
        raise ValueError("a receipt must be a JSON object")
    _check_shape(obj)
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
