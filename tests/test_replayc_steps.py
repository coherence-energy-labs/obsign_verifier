"""Static step-bound inference: the budget is computed, exact, and honest.

`steps` in a replay program is a security parameter -- it is what stops a hostile
receipt hanging a verifier -- and until now authors guessed it. For any program whose
loops are statically bounded, the compiler now KNOWS the worst-case executed
instruction count and writes it as the budget. These tests hold that claim to the
strongest standard available: on a worst-case input the program must RUN at exactly
the inferred budget and TRAP at the inferred budget minus one. Not "roughly right" --
off by one, in either direction, fails.
"""
from __future__ import annotations

import pytest

from obsign_verify.replay import MAX_STEPS, Trap, run_counted
from obsign_verify.replayc import compile_source

#: (source, worst-case input) -- the input must drive the longest path, because the
#: inferred budget is the WORST case and exactness is only observable on it
_EXACT = [
    # straight line
    ("input a, b; let x = a * b + 3; output x, x - a, abs(x);", [7, 9]),
    # if/else: the THEN branch is longer (extra work + its trailing JMP); take it
    ("input c; let r = 0; if c { r = c * 2 + 1; r = r - c; } else { r = 1; } output r;", [5]),
    # for with constant bounds, straight body
    ("input z; let s = 0; for i in 0..10 { s = s + i * 2; } output s + z;", [1]),
    # nested for, both constant
    ("input z; let s = 0; for i in 0..4 { for j in 0..3 { s = s + i * j; } } output s;", [0]),
    # empty-range for: init + one failing check
    ("input z; let s = 5; for i in 3..3 { s = 0; } output s + z;", [2]),
    # constant-index array traffic (static cells, no gadgets)
    ("input a; arr m[3]; m[0] = a; m[1] = m[0] * 2; m[2] = m[1] + m[0]; output m[2];", [4]),
    # dynamic index (bounds gadget) still straight-line and countable
    ("input i; arr m[4]; m[0]=1; m[1]=2; m[2]=3; m[3]=4; output m[i] + 1;", [2]),
    # functions inline to straight line, so they infer too
    ("fn f(x, y) { return x * y + 1; } input a; output f(a, a) + f(a, 3);", [6]),
]


@pytest.mark.parametrize("src,worst", _EXACT)
def test_inferred_budget_is_exact_runs_at_it_traps_below_it(src, worst):
    prog = compile_source(src)
    assert prog["steps"] < MAX_STEPS, "no inference happened; budget fell to the ceiling"

    out, used = run_counted(prog, worst)
    assert used == prog["steps"], (
        f"inferred {prog['steps']} but the worst-case input executed {used} -- the "
        f"inference is not exact")

    starved = dict(prog, steps=prog["steps"] - 1)
    with pytest.raises(Trap):
        run_counted(starved, worst)


def test_shorter_paths_run_under_the_inferred_budget():
    # the else-branch is shorter than then; budget is the max, so else runs with room
    src = "input c; let r = 0; if c { r = c * 2 + 1; r = r - c; } else { r = 1; } output r;"
    prog = compile_source(src)
    _, used = run_counted(prog, [0])          # takes the SHORT branch
    assert used < prog["steps"]


def test_break_and_continue_stay_within_the_inferred_budget():
    # break/continue shorten iterations; the bound is the full-body worst case
    src = """input z; let s = 0;
    for i in 0..10 { if i == 4 { continue; } if i == 8 { break; } s = s + i; }
    output s + z;"""
    prog = compile_source(src)
    assert prog["steps"] < MAX_STEPS
    _, used = run_counted(prog, [0])
    assert used <= prog["steps"]


def test_uninferable_shapes_fall_back_honestly():
    # a while: trip count is data-dependent
    p1 = compile_source("input n; let i = 0; while i < n { i = i + 1; } output i;")
    assert p1["steps"] == MAX_STEPS
    # a for with a data-dependent bound
    p2 = compile_source("input n; let s = 0; for i in 0..n { s = s + 1; } output s;")
    assert p2["steps"] == MAX_STEPS
    # a for whose body writes its own loop variable
    p3 = compile_source("input z; let s = 0; for i in 0..5 { i = i - 1; s = z; } output s;")
    assert p3["steps"] == MAX_STEPS


def test_declared_steps_always_beat_inference():
    prog = compile_source("#steps 12345\ninput a; output a + 1;")
    assert prog["steps"] == 12345


def test_a_huge_constant_loop_clamps_to_the_ceiling():
    # worst case beyond MAX_STEPS clamps to MAX_STEPS instead of refusing: a run that
    # long traps at the ceiling regardless, and a break may finish far earlier
    src = "input z; let s = 0; for i in 0..200000000 { s = s + 1; } output s + z;"
    prog = compile_source(src)
    assert prog["steps"] == MAX_STEPS
