"""`for` bounds: the compiler and the oracle must agree on WHEN they are read.

docs/RL.md: "`for` bounds are evaluated **once**, before the first iteration." The
reference interpreter implements exactly that -- `lo = eval(s.lo); hi = eval(s.hi)`
and only then `vars[s.var] = lo` (replayc/interp.py). Code generation did it in the
other order: it evaluated `lo` DIRECTLY INTO the loop variable's cell and then
evaluated `hi`, which therefore read the loop variable already clobbered.

    input a; let i = 5; for i in 0..i { } output i + a * 0;

        oracle : [5]     hi is the 5 that `i` held when the loop was reached
        VM     : [0]     hi is the 0 that `lo` had just written into `i`

    2  MOV  2 5     ; i = 5
    3  MOV  2 6     ; i = 0     <- lo written into the loop variable
    4  MOV  3 2     ; hi = i    <- ...and hi then reads the clobbered cell

THIS IS THE ONE FAILURE MODE A COMPILER INSIDE A RECEIPT VERIFIER MUST NOT HAVE.
replayc/__init__.py: "A wrong compiler is worse than none: it would mint receipts
that faithfully reproduce the WRONG number." The receipt verifies -- the VM really
does re-derive the hash -- and `obsign-replayc attest` certifies that the shipped
bytecode is what this source compiles to, so the source an auditor reads and the
number the receipt attests are different computations, with the toolchain vouching
for the pair.

The same clobber silences a bounds check when the upper bound indexes an array at
the loop variable: the range gadget is emitted against the pre-loop value and the
LOAD then uses the post-`lo` one.
"""
from __future__ import annotations

import pytest

from obsign_verify import mint
from obsign_verify.replayc import compile_source, interpret_source, run_source
from obsign_verify.verify import verify


def _both(src: str, inputs: list[int]):
    """(vm, oracle), each either a value list or a 'trap' marker."""
    def attempt(f):
        try:
            return f()
        except Exception as exc:               # Trap / InterpError alike
            return ("trap", type(exc).__name__)
    return attempt(lambda: run_source(src, inputs)), \
        attempt(lambda: interpret_source(src, inputs))


CASES = [
    ("plain read of the loop variable in the upper bound",
     "input a; let i = 5; for i in 0..i { } output i + a * 0;", [7]),
    ("the upper bound computes from the loop variable",
     "input a; let i = 3; for i in 0..(i + 1) { } output i + a * 0;", [7]),
    ("the upper bound indexes an array at the loop variable",
     "input v[4]; let i = 3; for i in 0..v[i] { } output i;", [1, 1, 1, 2]),
    ("a coalesced bounds check is proved against the pre-loop value",
     "input v[8]; let i = 6; for i in v[0]..v[i + 1] { } output i;",
     [0, 0, 0, 0, 0, 0, 0, 3]),
]


@pytest.mark.parametrize("name,src,inputs", CASES,
                         ids=[c[0].replace(" ", "-") for c in CASES])
def test_the_compiler_and_the_oracle_agree(name, src, inputs):
    vm, oracle = _both(src, inputs)
    assert vm == oracle, (
        f"{name}: the compiled program computes {vm} where the reference "
        f"interpreter computes {oracle} for the SAME source. A receipt minted "
        f"from this source re-derives {vm} and `attest` confirms the bytecode "
        f"came from it.")


def test_the_lower_bound_still_reads_the_variable_it_is_about_to_overwrite():
    """`for i in i..4` is the case the old order got right, and it must stay right:
    `lo` reads `i` BEFORE the loop assigns it."""
    vm, oracle = _both("input a; let i = 2; for i in i..4 { } output i + a * 0;", [7])
    assert vm == oracle == [4], (vm, oracle)


def test_a_receipt_minted_from_the_divergent_source_would_attest_the_wrong_number():
    """The consequence, spelled out as a receipt: it verifies, and the number in it
    is not the number the source computes."""
    # `a` is genuinely used, so the liveness rung cannot be what refuses this.
    src = "input a; let i = 5; for i in 0..i { } output i * 1000 + a;"
    receipt = mint.replay_receipt(compile_source(src), [7])
    assert verify(receipt)["verified"] is True, "precondition: the receipt verifies"
    assert receipt["output"]["length"] == 1
    from obsign_verify import replay
    reproduced = replay.run(receipt["params"]["program"], receipt["params"]["inputs"])
    assert reproduced == interpret_source(src, [7]), (
        "the receipt attests a number the source does not compute")


def test_bounds_are_still_evaluated_exactly_once():
    """Fixing the order must not turn a once-evaluated bound into a per-iteration
    one: a bound that TRAPS must trap once, and a loop must not re-read it."""
    vm, oracle = _both("input v[3]; let n = 0; for i in 0..v[n] { n = n + 1; } output n;",
                       [3, 0, 0])
    assert vm == oracle == [3], (vm, oracle)
