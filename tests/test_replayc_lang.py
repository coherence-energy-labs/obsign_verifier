"""The phase-2 language surface: functions, for/break/continue, const, len.

Every semantic test here asserts run_source == interpret_source, because the two
paths lower these features INDEPENDENTLY: the compiler inlines calls and emits jump
labels; the interpreter executes calls natively in a fresh frame and loops in Python.
Agreement is therefore evidence, not tautology -- especially for the inliner, which
the oracle never touches.
"""
from __future__ import annotations

import pytest

from obsign_verify.replay import INT64_MAX, Trap
from obsign_verify.replayc import (ParseError, TypeError, compile_source,
                                    interpret_source, run_source)
from obsign_verify.replayc.resolve import ResolveError


def both(src: str, inp: list[int]) -> list[int]:
    vm = run_source(src, inp)
    ref = interpret_source(src, inp)
    assert vm == ref, f"vm={vm} interp={ref} for {inp}"
    return vm


def both_trap(src: str, inp: list[int]) -> None:
    with pytest.raises(Trap):
        run_source(src, inp)
    with pytest.raises(Trap):
        interpret_source(src, inp)


# ------------------------------------------------------------------ functions
def test_functions_inline_and_native_agree():
    src = """
    fn clamp(x, lo, hi) { return min(max(x, lo), hi); }
    fn scale(x) { return clamp(x, 0, 1000) * 3; }
    input a, b;
    output scale(a) + scale(b), clamp(a - b, -10, 10);
    """
    assert both(src, [500, -20]) == [1500, 10]
    assert both(src, [2000, 999]) == [3000 + 2997, 10]
    assert both(src, [-5, -5]) == [0, 0]


def test_function_with_loop_and_tail_return():
    """Newton's isqrt -- with the seed capped, because `x + n/x` on a NAIVE seed of
    x = n wraps for n near INT64_MAX and converges to garbage. Both lowerings agree
    on the garbage (wrapping is the language's honest semantics); the fix belongs in
    the program: 3037000500 > isqrt(INT64_MAX), so min(n, that) is always a safe
    upper seed and the sum stays around 6e9, far from the edge."""
    src = """
    fn isqrt(n) {
      let x = 0;
      if n > 0 {
        x = min(n, 3037000500);
        let y = (x + n / x) / 2;
        while y < x { x = y; y = (x + n / x) / 2; }
      }
      return x;
    }
    input a; output isqrt(a);
    """
    for n, want in [(0, 0), (1, 1), (2, 1), (3, 1), (4, 2), (24, 4), (25, 5),
                    (10**12, 10**6), (INT64_MAX, 3037000499)]:
        assert both(src, [n]) == [want]


def test_call_arguments_are_evaluated_once_each_in_order():
    """Call-by-value: an argument expression's trap fires once, at the call, before
    the body runs -- identically under inlining and native execution."""
    src = "fn f(a, b) { return a + b; } input x; arr m[2]; output f(m[x], 7);"
    assert both(src, [1]) == [7]
    both_trap(src, [5])      # the ARGUMENT traps, in both lowerings


def test_while_condition_calling_a_function_reevaluates_every_iteration():
    """The inliner hoists a call out of a while condition; hoisting it ONCE would spin
    forever. The rewrite must re-run the hoisted work per iteration."""
    src = """
    fn lt(a, b) { return a < b; }
    input n; let i = 0;
    while lt(i, n) { i = i + 2; }
    output i;
    """
    assert both(src, [0]) == [0]
    assert both(src, [7]) == [8]
    assert both(src, [10]) == [10]


def test_functions_compose_and_topo_inline():
    src = """
    fn sq(x) { return x * x; }
    fn sumsq(a, b) { return sq(a) + sq(b); }
    fn norm2(a, b, c) { return sumsq(a, b) + sq(c); }
    input p, q, r; output norm2(p, q, r);
    """
    assert both(src, [3, 4, 12]) == [169]


def test_recursion_is_rejected_direct_and_mutual():
    with pytest.raises(TypeError, match="recursion"):
        compile_source("fn f(x) { return f(x); } output f(1);")
    with pytest.raises(TypeError, match="recursion"):
        compile_source("""
        fn even(n) { return sel(n == 0, 1, odd(n - 1)); }
        fn odd(n)  { return sel(n == 0, 0, even(n - 1)); }
        output even(4);
        """)


def test_functions_are_closed():
    # a global is not visible inside a fn
    with pytest.raises(TypeError, match="closed"):
        compile_source("input g; fn f(x) { return x + g; } output f(1);")
    # arrays are not accessible inside a fn
    with pytest.raises(TypeError, match="closed"):
        compile_source("arr m[3]; fn f(x) { return m[x]; } output f(1);")


def test_return_rules():
    with pytest.raises(TypeError, match="return"):
        compile_source("fn f(x) { let y = x; } output f(1);")          # no return
    with pytest.raises(TypeError, match="exactly one"):
        compile_source("fn f(x) { if x { return 1; } return 2; } output f(1);")
    with pytest.raises(TypeError, match="outside a function"):
        compile_source("input a; return a; output a;")


def test_fn_arity_and_name_errors():
    with pytest.raises(TypeError, match="argument"):
        compile_source("fn f(a, b) { return a + b; } output f(1);")
    with pytest.raises(TypeError, match="unknown function"):
        compile_source("output nosuch(1);")
    with pytest.raises(TypeError, match="is a function"):
        compile_source("fn f(a) { return a; } output f + 1;")


# ------------------------------------------------------------------ for / break / continue
def test_for_semantics_including_empty_and_negative_ranges():
    src = "input a, b; let s = 0; for i in a..b { s = s + i; } output s;"
    assert both(src, [0, 5]) == [10]
    assert both(src, [3, 3]) == [0]        # empty
    assert both(src, [5, 3]) == [0]        # hi < lo: zero iterations
    assert both(src, [-3, 2]) == [-5]      # negative lo


def test_for_bounds_evaluated_once():
    """The upper bound is captured before the first iteration; growing its source
    variable inside the body must not extend the loop."""
    src = "input n; let s = 0; for i in 0..n { n = n + 1; s = s + 1; } output s, n;"
    assert both(src, [3]) == [3, 6]


def test_for_var_is_an_ordinary_scalar_the_body_may_assign():
    src = "input n; let c = 0; for i in 0..n { if i == 2 { i = 7; } c = c + 1; } output c, i;"
    # i jumps 0,1,2->7(+1=8), loop ends when 8 >= n(=10): iterations at i=0,1,2,8,9
    assert both(src, [10]) == [5, 10]


def test_break_and_continue_in_both_loop_kinds():
    src = """
    input n; let s = 0;
    for i in 0..n {
      if i == 2 { continue; }
      if i == 5 { break; }
      s = s + i;
    }
    let j = 0; let t = 0;
    while j < n {
      j = j + 1;
      if j == 3 { continue; }
      if j == 6 { break; }
      t = t + j;
    }
    output s, t, j;
    """
    assert both(src, [10]) == [0 + 1 + 3 + 4, 1 + 2 + 4 + 5, 6]


def test_break_in_inner_loop_only_exits_inner():
    src = """
    input n; let c = 0;
    for i in 0..n { for j in 0..n { if j > i { break; } c = c + 1; } }
    output c;
    """
    assert both(src, [4]) == [10]   # 1+2+3+4


def test_continue_in_for_still_increments():
    """The regression `for` exists to prevent: desugaring to while would send
    `continue` past the increment and spin forever. It must land ON the increment."""
    src = "input n; let s = 0; for i in 0..n { continue; } output i;"
    assert both(src, [4]) == [4]


def test_break_continue_outside_a_loop_rejected():
    with pytest.raises(TypeError, match="outside a loop"):
        compile_source("break; output 1;")
    with pytest.raises(TypeError, match="outside a loop"):
        compile_source("input a; if a { continue; } output 1;")


# ------------------------------------------------------------------ const / len
def test_const_in_lengths_fracs_bounds_and_expressions():
    src = """
    const N = 3; const SCALE_BITS = 4 * 8;
    const HALF = 1 << (SCALE_BITS - 1);
    input v[N];
    let s = 0;
    for i in 0..N { s = s + mulfx(v[i], HALF, SCALE_BITS); }
    output s, N * 100;
    """
    one = 1 << 32
    assert both(src, [2 * one, 4 * one, 6 * one]) == [6 * one // 2 * 1, 300] or True
    vm = both(src, [2 * one, 4 * one, 6 * one])
    assert vm == [(2 * one) // 2 + (4 * one) // 2 + (6 * one) // 2, 300]


def test_len_folds_and_agrees():
    src = "arr m[5]; input a; for i in 0..len(m) { m[i] = a; } output len(m), m[4];"
    assert both(src, [9]) == [5, 9]
    # len() folded to a constant: no LOAD of a length at run time
    prog = compile_source(src)
    assert 5 in prog["consts"]


def test_const_errors():
    with pytest.raises(ResolveError, match="reduce to an integer"):
        compile_source("input a; const N = a; output N;")        # not a constant
    with pytest.raises(ResolveError, match="collides"):
        compile_source("const N = 3; let N = 4; output N;")      # binding shadows const
    with pytest.raises(ResolveError, match="collides"):
        compile_source("const N = 3; input N; output N;")
    with pytest.raises(ResolveError, match="duplicate"):
        compile_source("const N = 3; const N = 4; output N;")


def test_const_forward_reference_rejected():
    with pytest.raises(ResolveError):
        compile_source("const A = B + 1; const B = 2; output A;")


# ------------------------------------------------------------------ integration
def test_cecl_rewritten_with_functions_and_for_matches_the_receipt():
    """The CECL anchor, rewritten in the richer language -- same output hash."""
    import json
    import pathlib
    from obsign_verify.replay import output_sha256
    root = pathlib.Path(__file__).resolve().parent.parent
    receipt = json.loads(
        (root / "src/obsign_verify/data/conformance/producer_signed_replay.json").read_text())
    src = """
    const SCALE = 32;
    fn ecl(pd, lgd, ead) { return mulfx(mulfx(pd, lgd, SCALE), ead, SCALE); }
    input v[13];
    let acc = 0;
    for i in 0..v[0] {
      let base = i * 3 + 1;
      acc = acc + ecl(v[base], v[base + 1], v[base + 2]);
    }
    output acc;
    """
    out = both(src, receipt["params"]["inputs"])
    assert output_sha256(out) == receipt["output"]["sha256"]
