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
from . import replay as replaymod
from .kernel import SUPPORTED_KERNELS, array_sha256, build_fixed_inputs, evolve


def _signature_gate(receipt: dict, result: dict, notes: list) -> bool:
    """Run step 3 and return whether it permits a `verified` verdict.

    ONE place, because the fixed-kernel path and the replay path each had their own
    copy of this three-line rule -- and a rule with two copies is a rule that gets
    fixed in one of them.

    A signature that is PRESENT but does not verify is a refusal. A signature that is
    ABSENT is not: the replay rung stands on its own, which is the whole argument for
    a verifier a stranger can run.
    """
    sig = sigmod.check(receipt)
    result["signature"] = sig
    if sig["present"] and not sig["valid"]:
        notes.append(sig["detail"])
    # An unattested `case` on an otherwise valid signature is not a refusal, but it
    # must reach the reader: it is the block a court report prints first.
    for key in sig.get("unbound_metadata") or []:
        notes.append(f"{key!r} is present but NOT covered by the signature - "
                     f"unattested annotation, not an attested fact")
    return (not sig["present"]) or sig["valid"]


#: Perturbations tried per input when probing liveness. Small, mixed sign and
#: magnitude, so an input that only matters above some threshold is still caught.
_LIVENESS_DELTAS = (1, -1, 7, -7, 1000, -1000, 1_000_000)

_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1


def _input_liveness(prog: dict, inputs: list, base_out, base_steps: int):
    """Does the output actually depend on the declared inputs?

    A receipt proves "re-run this program on these inputs and you get this hash".
    That is empty if the program ignores the inputs: a two-instruction program that
    loads a constant and halts re-derives PERFECTLY and is signed and integral, yet
    establishes nothing about the inputs it names. `--expect-program` does not help
    -- the constant program has a perfectly good, pinnable digest. The only thing
    that separates it from a real computation is that perturbing an input moves the
    answer, and that is checkable here, on the VM already in hand, with no toolchain.

    This is an EXISTENCE PROOF, not a static approximation: find one input whose
    change moves the output (or changes whether the program traps at all) and the
    program demonstrably uses its inputs. Returns one of:

        "live"          -- at least one input demonstrably affects the outcome
        "dead"          -- EVERY input was fully probed and NONE affected it
        "indeterminate" -- the probe budget ran out before proving either

    The verdict only ever REFUSES on "dead", and "dead" is only returned after every
    input has been exercised within budget. An honest program is found live on its
    first live input, so it costs about one extra run; only the attack -- a program
    that genuinely ignores its inputs -- pays the full sweep, and such a program is
    cheap by construction (it does no work). "indeterminate" never refuses: a
    verifier must not reject an honest receipt merely because it was too expensive
    to fully probe. Fail towards NOT accusing.

    The probe is bounded so it can never be turned into a denial-of-service
    amplifier: total perturbation work is capped at a small multiple of the base
    run, plus a floor generous enough to fully sweep any cheap constant program.
    """
    n = len(inputs)
    if n == 0:
        return "n/a"  # a program with no declared inputs makes no claim about any

    # Cap ONE perturbation run, and cap the TOTAL. A single probe never runs longer
    # than the base did (plus a small floor for near-instant programs), so a program
    # that spins near its budget cannot make each probe expensive; and the total is a
    # small multiple of the base, so the whole liveness pass adds at most a few times
    # the verification cost it already paid. Both are what stop this being a DoS
    # amplifier -- a hostile program is handed a bounded probe, not an open one.
    per_run_cap = min(replaymod.MAX_STEPS, max(base_steps, 100_000))
    total_budget = max(base_steps * 8, 4_000_000)
    spent = 0

    for i in range(n):
        original = inputs[i]
        for d in _LIVENESS_DELTAS:
            probed = original + d
            if probed < _I64_MIN or probed > _I64_MAX:
                continue  # keep the perturbation a valid int64; an ingest rejection
                          # is not evidence about the program's use of the value
            if spent >= total_budget:
                return "indeterminate"  # never refuse for want of budget
            trial = list(inputs)
            trial[i] = probed
            try:
                out, used = replaymod.run_counted(prog, trial, step_cap=per_run_cap)
                spent += used
                if out != base_out:
                    return "live"  # the value moved the answer
            except replaymod.Trap:
                spent += per_run_cap  # unknown actual cost; charge the cap
                # The inputs are all valid int64, so a Trap here came from the
                # program's own guards or arithmetic (a domain guard, a row-count
                # pin, a divide-by-zero): the value controls whether an output
                # exists at all, which is dependence. Even a probe that only hit the
                # per-run cap proves the perturbed run BEHAVES DIFFERENTLY from the
                # base, which took fewer steps -- still dependence.
                return "live"

    return "dead"  # every input exercised within budget, none moved the outcome


def _verify_replay(receipt: dict, result: dict, notes: list) -> dict:
    """Re-derive a receipt whose computation travels inside it.

    Two things are checked that the fixed-kernel path does not need, and both exist
    because the program here is attacker-supplied:

    1. The program's own digest must match `params.program_sha256` when the receipt
       states one. `params` is already inside the claim, so this is redundant against
       a tamperer -- but it gives a stranger a short string to compare with a
       published one, and it catches an honest producer shipping a stale digest.

    2. A `Trap` is a REFUSAL with a reason, never an escape. A malformed or hostile
       program -- an out-of-bounds address, a division by zero, an infinite loop --
       reports `not verified` and says why. It must not hang the verifier and it must
       not raise past this function, because a receipt you were invited to check must
       not be able to take your process down.
    """
    params = receipt.get("params")
    if not isinstance(params, dict):
        notes.append("replay receipt carries no params; nothing to re-execute")
        _signature_gate(receipt, result, notes)
        return result

    prog = params.get("program")
    inputs = params.get("inputs")
    if not isinstance(prog, dict) or not isinstance(inputs, list):
        notes.append("replay params must carry {program: object, inputs: [int]}")
        _signature_gate(receipt, result, notes)
        return result

    stated_digest = params.get("program_sha256")
    actual_digest = replaymod.program_sha256(prog)
    digest_ok = stated_digest is None or stated_digest == actual_digest
    if not digest_ok:
        notes.append(f"program digest mismatch: states {str(stated_digest)[:16]}.., "
                     f"computes {actual_digest[:16]}..")

    try:
        out, base_steps = replaymod.run_counted(prog, inputs)
    except replaymod.Trap as trap:
        notes.append(f"program refused: {trap}")
        _signature_gate(receipt, result, notes)
        return result

    got = replaymod.output_sha256(out)
    want = (receipt.get("output") or {}).get("sha256")
    result["reproduced"] = (got == want)
    if not result["reproduced"]:
        notes.append(f"output mismatch: claim {str(want)[:16]}.., "
                     f"recomputed {got[:16]}..")

    # Length rides outside the byte hash, exactly as shape/dtype do for the array
    # kernel, so it is compared explicitly rather than trusted.
    declared = receipt.get("output") or {}
    len_ok = declared.get("length") in (None, len(out))
    if not len_ok:
        notes.append("output length does not match the re-executed result")

    # A re-derivation that does not depend on the inputs proves nothing about them.
    # Only "dead" -- every declared input exercised and none moved the outcome --
    # refuses; "indeterminate" (probe budget spent) never does.
    liveness = _input_liveness(prog, inputs, out, base_steps)
    result["input_liveness"] = liveness
    live_ok = liveness != "dead"
    if liveness == "dead":
        notes.append(
            "the output does not depend on ANY declared input: every input was "
            "perturbed and the result never changed. This program ignores its "
            "inputs, so re-deriving it proves nothing about them -- a constant "
            "dressed as a computation. REFUSED.")
    elif liveness == "indeterminate":
        notes.append(
            "input-liveness probe hit its budget before proving dependence either "
            "way; not treated as a failure (a verifier must not refuse an honest "
            "receipt for being expensive to probe)")

    sig_ok = _signature_gate(receipt, result, notes)

    result["verified"] = bool(result["integrity"] and result["reproduced"]
                              and digest_ok and len_ok and live_ok and sig_ok)
    return result


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

        # A REPLAY PROGRAM carries its own computation. Everything needed to
        # re-derive the number is inside the receipt, so this branch needs no
        # producer toolchain, no compiler checkout and no network -- which is the
        # whole difference between a receipt a stranger can check and one they
        # cannot. See replay.py for why nondeterminism is not expressible there.
        if kernel == replaymod.SPEC:
            return _verify_replay(receipt, result, notes)

        if kernel not in SUPPORTED_KERNELS:
            notes.append(f"kernel {kernel!r} cannot be re-executed by this verifier "
                         f"(supported: {', '.join(SUPPORTED_KERNELS)}) - "
                         f"NOT verified by re-derivation")
            _signature_gate(receipt, result, notes)
            return result

        params = receipt.get("params")
        if not isinstance(params, dict):
            notes.append("receipt carries no params; nothing to re-execute")
            _signature_gate(receipt, result, notes)
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

        sig_ok = _signature_gate(receipt, result, notes)

        result["verified"] = bool(result["integrity"] and result["reproduced"]
                                  and input_ok and shape_ok and dtype_ok and sig_ok)
        return result
    except Exception as exc:
        notes.append(f"verification error, treated as NOT verified: "
                     f"{type(exc).__name__}: {exc}")
        return result
