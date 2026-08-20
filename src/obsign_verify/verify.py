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
    # Unattested out-of-claim data on an otherwise valid signature is not a refusal,
    # but it must reach the reader. This iterated `unbound_metadata`, which is the
    # hardcoded `("case",)` list -- so `env` and every `_`-prefixed key produced no
    # note at all, and the producer stores its printed VERDICT in a `_`-prefixed key
    # (`_combined_verdict`) exactly because it is outside the claim. The computed set
    # is the one a reader needs.
    for key in sig.get("unattested_metadata") or sig.get("unbound_metadata") or []:
        notes.append(f"{key!r} is present but NOT covered by the signature - "
                     f"unattested annotation, not an attested fact")
    return (not sig["present"]) or sig["valid"]


#: Small absolute perturbations, mixed sign, tried first: an honest program usually
#: moves on the very first one, so the cheap probes come before the expensive ones.
_LIVENESS_DELTAS = (1, -1, 7, -7, 1000, -1000, 1_000_000, -1_000_000)

#: Perturbations SCALED TO THE INPUT ITSELF. A fixed ladder can only exercise a
#: program at the resolution of its largest step, so a computation coarser than that
#: never moved and was reported "dead" -- an honest receipt refused, and accused of
#: being "a constant dressed as a computation". Money held in cents and reported in
#: hundreds of millions, a byte count reported in gigabytes, any bucketed or rounded
#: figure: all of them ignore a delta of 1,000,000 and all of them are honest.
_LIVENESS_FRACTIONS = (2, 8, 64, 1024)

#: ...and perturbations scaled to the MACHINE, for the mirror-image case: an input
#: whose own magnitude is small but which is multiplied up before it reaches the
#: output, where a relative step is no bigger than the absolute one.
_LIVENESS_SHIFTS = (20, 32, 48, 62)

#: Replacements rather than deltas: the values a program is likeliest to treat
#: specially, and the edges of the type.
_LIVENESS_EDGES = (0, 1, -1)

_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1


def _probe_values(x: int) -> list[int]:
    """The values an input is re-run with, cheapest and likeliest first.

    Absolute deltas alone cannot move a program whose output is coarser than the
    largest of them; relative deltas alone cannot move a program whose input is zero.
    Both families are here, plus the type's edges -- deduplicated, and clipped to
    int64 because an ingest rejection says nothing about the program's use of the
    value, so an out-of-range perturbation is dropped rather than counted.
    """
    seen = {x}
    values: list[int] = []

    def add(v: int) -> None:
        if _I64_MIN <= v <= _I64_MAX and v not in seen:
            seen.add(v)
            values.append(v)

    for d in _LIVENESS_DELTAS:
        add(x + d)
    magnitude = abs(x)
    for f in _LIVENESS_FRACTIONS:
        step = magnitude // f
        if step:
            add(x + step)
            add(x - step)
    for k in _LIVENESS_SHIFTS:
        add(x + (1 << k))
        add(x - (1 << k))
    for v in _LIVENESS_EDGES:
        add(v)
    add(_I64_MAX)
    add(_I64_MIN)
    return values


# What one unit of each kind of per-run work costs, in units of "zeroing one memory
# cell" -- the cheapest thing a run does, and therefore the natural denominator.
# These are ORDERS OF MAGNITUDE measured on the reference implementation, not
# calibrated constants: re-validating an instruction (type checks, table lookup,
# range checks per operand) is around 150x a cell store, executing one is around 60x,
# and loading an input (bool check, isinstance, range check, store) around 16x. They
# are rounded UP to powers of two, because under-charging is what turns a budget into
# an amplifier and over-charging only costs a hostile receipt some probes.
_COST_CELL = 1        # one zeroed memory cell
_COST_INPUT = 16      # one input copied, type-checked and stored
_COST_CONST = 8       # one constant re-validated
_COST_CODE = 128      # one instruction re-validated
_COST_STEP = 64       # one instruction executed

#: The floor, in the same units: the budget a program gets however cheap it is, so a
#: small constant program with many declared inputs is still swept exhaustively rather
#: than reported "indeterminate" (which does not refuse). ~30 million cell-equivalents
#: is well under a second of real work on the reference implementation -- and because
#: the units track real cost, that stays true whichever dimension a hostile receipt
#: inflates.
_LIVENESS_FLOOR = 32_000_000


def _probe_cost(prog: dict, n_inputs: int, steps: int) -> int:
    """What ONE run of PROG costs the verifier -- all of it, not just what it retires.

    The probe budget was denominated in VM steps, and steps are the one thing a probe
    run need not spend. Before a program executes its first instruction,
    `run_counted` allocates `mem` cells, re-runs `validate` over every instruction and
    every constant, and copies and range-checks every declared input. A program that
    HALTs immediately pays all of that and retires ONE step, so a 4,000,000-STEP
    budget bought four million full machine instantiations: at the wire limit (2^20
    declared inputs over a 2^20-cell machine -- a 2.1 MB receipt `load_receipt`
    accepts) that is over a hundred hours of CPU from one file. It was spent before
    integrity was ever trusted, so the receipt did not even have to be valid; a
    1.7 KB one measured 8.0 s in Python and 14.0 s in Node against a 3.2 ms base run.

    Charging the fixed cost is what makes the documented bound real: every probe run
    costs at least what the base run cost, so "a small multiple of the base run"
    becomes arithmetic rather than aspiration, in every dimension a receipt can
    inflate -- memory, code length, constant pool, input count, steps.
    """
    return (steps * _COST_STEP
            + prog["mem"] * _COST_CELL
            + n_inputs * _COST_INPUT
            + len(prog["code"]) * _COST_CODE
            + len(prog["consts"]) * _COST_CONST)


def _input_liveness(prog: dict, inputs: list, base_out, base_steps: int):
    """What evidence is there that the output depends on the declared inputs?

    A receipt proves "re-run this program on these inputs and you get this hash".
    That is empty if the program ignores the inputs: a two-instruction program that
    loads a constant and halts re-derives PERFECTLY and is signed and integral, yet
    establishes nothing about the inputs it names.

    WHAT THIS CAN AND CANNOT ESTABLISH -- read before trusting a "live".

    Perturbing an input and watching the output move is EVIDENCE OF DEPENDENCE. It
    is not, and cannot be, proof that the program computes the formula its name
    claims. An adversary can always write

        if inputs == this_quarter_exact_inputs:  return the number I want
        else:                                    run the real formula

    which behaves correctly under every perturbation anyone thinks to try. No
    finite black-box probe closes that. The semantic boundary is an APPROVED
    PROGRAM IDENTITY -- `--expect-program`, a digest a validator recorded after
    READING the program -- and this probe is diagnostic evidence beneath it.

    A TRAP IS NOT EVIDENCE OF DEPENDENCE. This once counted a trap on a perturbed
    input as "live", reasoning that the value controls whether an output exists at
    all. The attacker controls when the program traps, so that handed the
    hardcoded-constant attack a way straight back through the check:

        input a, b;  let ok = 0;
        if a == 5 { if b == 7 { ok = 1; } }
        let guard = 1 / ok;        // traps unless the inputs are the receipted ones
        output 424242;             // ... and the output is a CONSTANT

    Every probe perturbs, hits the guard, traps -- and the old probe called that
    proof the constant depended on its inputs. A trap now says only that the
    program REFUSED TO RUN, which is not information about the output, so it is
    recorded as "guarded" and never as evidence.

    A PERTURBATION MUST REACH THE SCALE OF THE THING IT PERTURBS. The ladder was
    seven fixed absolute deltas, the largest 1,000,000, so any computation coarser
    than that in its inputs' own units -- cents reported in hundreds of millions,
    bytes reported in gigabytes, anything bucketed or rounded -- never moved, and was
    REFUSED as a hardcoded constant. `_probe_values` therefore mixes deltas scaled to
    the input, deltas scaled to the machine word, and the edges of the type.

    "THE OUTPUT" IS NOT ONE NUMBER. The verdict above is about the output WINDOW, and
    a window is a vector -- so a program whose reported figure is a hardcoded constant
    passes it by appending one decoy cell that echoes an input:

        input a, b;  output 424242, a + b;      // cell 0 is the "answer"

    Every input is live (the vector moved), the receipt verifies, and a
    docs/GRAPHS.md link that consumes `src_offset 0, length 1` carries the CONSTANT
    down the chain while `obsign-verify --chain` prints "CHAIN VERIFIED - every node
    re-derived, every link binds". So the sweep also records which output CELLS ever
    moved, and graph.py refuses a link whose whole source slice is dead. The per-cell
    answer only exists when the sweep was EXHAUSTIVE -- the per-input pass stops at
    the first perturbation that moves anything, which proves that input live but says
    nothing about a cell it did not happen to disturb, so a second pass finishes the
    ladder (within the same budget) before any cell may be called dead.

    Returns (verdict, per_input, per_cell). per_input[i] is one of:

        "live"          -- some perturbation of input i MOVED the output
        "guarded"       -- every perturbation of input i trapped; the program
                           declined to run, so nothing was learned about the output
        "dead"          -- input i was fully exercised and never moved the output
        "indeterminate" -- the probe budget ran out on input i

    and the overall verdict is "live" if any input is live, else "indeterminate" if
    any is indeterminate, else "guarded" if any is guarded, else "dead".
    per_cell[c] is "live", "dead" or "indeterminate" for output cell c.

    Only "dead" and "guarded" refuse, and both are sound NEGATIVES: in each case
    the run produced no evidence that any declared input reaches the output.
    "indeterminate" never refuses -- a verifier must not reject an honest receipt
    merely because it was expensive to probe. Fail towards not accusing.

    The probe is bounded so it can never be turned into a denial-of-service
    amplifier: total perturbation work is capped at a small multiple of the base
    run, plus a floor generous enough to fully sweep any cheap constant program.
    Work is measured by `_probe_cost`, which counts what a run ACTUALLY costs --
    counting only retired steps let a one-instruction program buy four million
    machine instantiations for a budget of four million steps.
    """
    n = len(inputs)
    if n == 0:
        # A program with no declared inputs makes no claim about any -- and with
        # nothing to perturb, nothing is known about its cells either.
        return "n/a", [], ["indeterminate"] * len(base_out)

    # Cap ONE perturbation run, and cap the TOTAL. A single probe never runs longer
    # than the base did (plus a small floor for near-instant programs), so a program
    # that spins near its budget cannot make each probe expensive; and the total is a
    # small multiple of the base COST -- not of the base step count, which a hostile
    # program sets to one and leaves there. Both are what stop this being a DoS
    # amplifier: a hostile program is handed a bounded probe, not an open one.
    per_run_cap = min(replaymod.MAX_STEPS, max(base_steps, 100_000))
    base_cost = _probe_cost(prog, n, base_steps)
    total_budget = max(base_cost * 8, _LIVENESS_FLOOR)

    cell_moved = [False] * len(base_out)   # which output cells any probe ever moved
    state = {"spent": 0, "ran": False}     # budget spent; did ANY probe complete

    def probe(i: int, value: int):
        """Run with input i replaced. Returns "moved" | "same" | "trap" | None (budget
        exhausted, nothing run). Records which cells moved whatever the answer is."""
        if state["spent"] >= total_budget:
            return None
        trial = list(inputs)
        trial[i] = value
        try:
            out, used = replaymod.run_counted(prog, trial, step_cap=per_run_cap)
        except replaymod.Trap as trap:
            # A refused run still cost the fixed per-run work, plus however many
            # instructions it retired before refusing -- which the Trap carries.
            # Charging the CAP instead over-bills an early trap enormously, and an
            # over-billed budget runs out and reports "indeterminate", which does not
            # refuse, in place of the "guarded" that does.
            state["spent"] += _probe_cost(prog, n, getattr(trap, "steps", 0))
            return "trap"
        state["spent"] += _probe_cost(prog, n, used)
        state["ran"] = True
        if out == base_out:
            return "same"
        for c in range(min(len(out), len(cell_moved))):
            if out[c] != base_out[c]:
                cell_moved[c] = True
        return "moved"

    # ---- pass 1: the per-input verdict. Stops at the first perturbation that moves
    # the output, because that is all it takes to establish dependence.
    #
    # The ladder for input i is built ONLY when there is budget left to spend on it.
    # Building all of them up front is n * ~30 integers before a single probe runs, and
    # `inputs` is attacker-controlled up to 2^20 -- the same "work nobody charged for"
    # that `_probe_cost` exists to close, reintroduced in the bookkeeping.
    tried = [0] * n
    per_input: list[str] = []
    for i in range(n):
        if state["spent"] >= total_budget:
            per_input.append("indeterminate")
            continue
        verdict_i = "dead"      # until a perturbation says otherwise
        trapped = False
        exhausted = False
        for probed in _probe_values(inputs[i]):
            outcome = probe(i, probed)
            if outcome is None:
                exhausted = True
                break
            tried[i] += 1
            if outcome == "trap":
                trapped = True  # the program declined to run: NOT evidence
            elif outcome == "moved":
                verdict_i = "live"   # the value moved the answer: real evidence
                break
        if verdict_i != "live":
            # An exhausted budget is the weakest thing we can say, so it wins over
            # "guarded"; both are weaker than a definite "dead", which requires
            # every perturbation to have actually RUN and left the output alone.
            verdict_i = ("indeterminate" if exhausted
                         else ("guarded" if trapped else "dead"))
        per_input.append(verdict_i)

    # ---- pass 2: finish the ladder, for the CELL answer only. Pass 1's early stop is
    # right for "does this input matter" and useless for "does this cell move": the
    # perturbation that proved the input live may have moved a different cell entirely.
    # A cell may only be called dead once every perturbation has actually been run.
    swept = True
    for i in range(n):
        if state["spent"] >= total_budget:
            swept = False
            break
        for probed in _probe_values(inputs[i])[tried[i]:]:
            if probe(i, probed) is None:
                swept = False
                break
        if not swept:
            break

    if state["ran"] and swept:
        per_cell = ["live" if moved else "dead" for moved in cell_moved]
    else:
        # Nothing completed, or the ladder was cut short: no cell may be called dead.
        per_cell = ["live" if moved else "indeterminate" for moved in cell_moved]

    if "live" in per_input:
        verdict = "live"
    elif "indeterminate" in per_input:
        verdict = "indeterminate"
    elif "guarded" in per_input:
        verdict = "guarded"
    else:
        verdict = "dead"
    return verdict, per_input, per_cell


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
    # kernel, so it is compared explicitly rather than trusted -- and it must BE a
    # JSON integer. This read `declared.get("length") in (None, len(out))`, and `in`
    # is `==`: Python says `True == 1` and `1.0 == 1`, so `"length": true` and
    # `"length": 1.0` passed HERE over a one-element output while js/src/verify.js
    # (`typeof declaredLen === 'bigint'`) and rust/src/verify.rs (`v.as_i64()`) both
    # refused the same bytes. That is the split replay.py's `_struct_int` closed for
    # the program's structural scalars -- "a forger hands the receipt to whichever
    # implementation loads it" -- with the reference on the lenient side. A count is
    # an integer; a boolean is not a count.
    declared = receipt.get("output") or {}
    declared_len = declared.get("length")
    len_ok = declared_len is None or (
        type(declared_len) is int and declared_len == len(out))
    if not len_ok:
        notes.append("output length does not match the re-executed result")

    # A re-derivation that does not depend on the inputs proves nothing about them.
    # "dead" and "guarded" both refuse: in each case NOTHING was observed reaching
    # the output from any declared input. "indeterminate" (probe budget spent) never
    # refuses. A "live" is EVIDENCE, not a semantic guarantee -- see _input_liveness.
    liveness, per_input, per_cell = _input_liveness(prog, inputs, out, base_steps)
    result["input_liveness"] = liveness
    result["input_liveness_by_input"] = per_input
    # Which output CELLS a perturbation ever moved. A whole-window verdict cannot see
    # a constant hiding beside a decoy that echoes an input, and graph.py refuses a
    # link whose source slice is entirely dead. See _input_liveness.
    result["output_liveness_by_cell"] = per_cell
    live_ok = liveness not in ("dead", "guarded")
    if liveness == "dead":
        notes.append(
            "the output does not depend on ANY declared input: every input was "
            "perturbed and the result never changed. This program ignores its "
            "inputs, so re-deriving it proves nothing about them -- a constant "
            "dressed as a computation. REFUSED.")
    elif liveness == "guarded":
        notes.append(
            "no declared input was shown to reach the output, and the program "
            "TRAPPED on every perturbation that did not. A program that refuses to "
            "run on anything but its own receipted inputs yields no evidence that "
            "those inputs produced this answer -- the shape of a hardcoded result "
            "behind an equality guard. REFUSED.")
    elif liveness == "indeterminate":
        notes.append(
            "input-liveness probe hit its budget before proving dependence either "
            "way; not treated as a failure (a verifier must not refuse an honest "
            "receipt for being expensive to probe)")
    if liveness == "live":
        dark = [i for i, st in enumerate(per_input) if st != "live"]
        dead_cells = [c for c, st in enumerate(per_cell) if st == "dead"]
        notes.append(
            "input-liveness is EVIDENCE, not proof: perturbing an input moved the "
            "output, which shows dependence but cannot show the program computes "
            "the formula its name claims. Pin an approved program digest "
            "(--expect-program) for that."
            + (f" Inputs {dark} were not shown to reach the output." if dark else "")
            + (f" Output cells {dead_cells} never moved under ANY perturbation - a "
               f"constant beside a live one still proves nothing about the constant."
               if dead_cells else ""))

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
