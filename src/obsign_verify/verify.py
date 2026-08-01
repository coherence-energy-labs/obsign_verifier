"""The four-step trust ladder.

    1. integrity      `receipt_sha256` recomputes from the claim
    2. reproduced     re-running the kernel reproduces `output.sha256`
    3. signature      the signature verifies, and covers what it claims to cover
    4. issuer trust   OUT OF SCOPE -- a key being valid says nothing about whose it is

Step 4 is deliberately not implemented. Deciding that a public key belongs to an
organisation you should trust is an identity question, and a verifier that answered
it by consulting a bundled list would be asserting a social fact as a cryptographic
one. `verified` therefore means steps 1-3, and `attributed_signer` is only ever
populated when the signature actually covered the name.

VERIFIED IS NOT THE SAME AS SIGNED, AND THE ORDER MATTERS

An unsigned receipt can still be `verified` here: integrity holds and the number
re-derives on your machine. That is the whole point of the replay rung -- you did
not have to trust anyone, you recomputed it. A signature adds *who*, not *whether*.
"""

from __future__ import annotations

from . import signature as sigmod
from .canonical import integrity
from .kernel import SUPPORTED_KERNELS, array_sha256, build_fixed_inputs, evolve


def verify(receipt: dict) -> dict:
    """Run the ladder. Never raises on a hostile receipt.

    A verifier that crashes on malformed input has failed open in the eyes of
    whoever handed it the file: an exception is not a refusal.
    """
    notes: list[str] = []
    result = {
        "integrity": False,
        "reproduced": False,
        "signature": None,
        "verified": False,
        "notes": notes,
    }

    try:
        ok, detail = integrity(receipt)
        result["integrity"] = ok
        if not ok:
            notes.append(detail)

        kernel = receipt.get("kernel")
        if kernel not in SUPPORTED_KERNELS:
            notes.append(f"kernel {kernel!r} cannot be re-executed by this verifier "
                         f"(supported: {', '.join(SUPPORTED_KERNELS)}) - "
                         f"NOT verified by re-derivation")
            result["signature"] = sigmod.check(receipt)
            return result

        params = receipt.get("params")
        if not isinstance(params, dict):
            notes.append("receipt carries no params; nothing to re-execute")
            result["signature"] = sigmod.check(receipt)
            return result

        inp = build_fixed_inputs(params)

        stated_input = (receipt.get("input") or {}).get("sha256")
        if stated_input is None:
            # A params-derived input carries no fingerprint by design: `params` is
            # inside the claim, so it is already hash-covered, and altering it breaks
            # BOTH integrity and reproduction. There is nothing to compare against.
            input_ok = True
        else:
            input_ok = array_sha256(inp["S"]) == stated_input
            if not input_ok:
                notes.append("input does not rebuild to the stated fingerprint")

        out = evolve(inp)
        got = array_sha256(out)
        want = (receipt.get("output") or {}).get("sha256")
        result["reproduced"] = (got == want)
        if not result["reproduced"]:
            notes.append(f"output mismatch: claim {str(want)[:16]}.., "
                         f"recomputed {got[:16]}..")

        # Shape and dtype ride OUTSIDE the byte hash, so they are compared against
        # the re-executed result explicitly. Otherwise that metadata could be
        # rewritten while the byte hash still agreed.
        declared = receipt.get("output") or {}
        shape_ok = list(declared.get("shape") or []) == list(out.shape)
        dtype_ok = declared.get("dtype") == str(out.dtype)
        if not (shape_ok and dtype_ok):
            notes.append("output shape/dtype does not match the re-executed result")

        sig = sigmod.check(receipt)
        result["signature"] = sig
        # A signature that is PRESENT but does not verify is a refusal. A signature
        # that is ABSENT is not: the replay rung stands on its own.
        sig_ok = (not sig["present"]) or sig["valid"]
        if sig["present"] and not sig["valid"]:
            notes.append(sig["detail"])

        result["verified"] = bool(result["integrity"] and result["reproduced"]
                                  and input_ok and shape_ok and dtype_ok and sig_ok)
        return result
    except Exception as exc:
        notes.append(f"verification error, treated as NOT verified: "
                     f"{type(exc).__name__}: {exc}")
        return result
