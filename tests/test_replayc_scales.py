"""Fixed-point scale checking: the wrong-unit bug becomes a compile error.

Re-execution guarantees a receipt's number is REPRODUCIBLE; it cannot know the number
is what the author MEANT. Mixing an fx32 with an fx16, or renormalizing by the wrong
F, produces bit-exact, faithfully-attested garbage. These tests pin that the checker
refuses exactly that class -- and, just as important, that it costs nothing: programs
without annotations are untouched, and every legitimate fixed-point idiom (scaling by
a count, ratios of like units, renormalizing with mulfx) still compiles and still
agrees with the oracle.
"""
from __future__ import annotations

import pytest

from obsign_verify.replayc import ScaleError, compile_source, interpret_source, run_source


def both(src, inp):
    vm = run_source(src, inp)
    ref = interpret_source(src, inp)
    assert vm == ref
    return vm


# ------------------------------------------------------------------ refusals
@pytest.mark.parametrize("src,fragment", [
    # the classic: two different units added / subtracted / compared
    ("input p: fx32, r: fx16; output p + r;", "fx32 vs fx16"),
    ("input p: fx32, r: fx16; output p - r;", "fx32 vs fx16"),
    ("input p: fx32, r: fx16; output p < r;", "fx32 vs fx16"),
    ("input p: fx32, r: fx16; output min(p, r);", "fx32 vs fx16"),
    # fx * fx without renormalization
    ("input a: fx32, b: fx32; output a * b;", "renormalize with"),
    # mixed-unit division
    ("input a: fx32, b: fx16; output a / b;", "different fixed-point units"),
    # mulfx F wrong for the operands (result scale out of range)
    ("input a: fx32, b: fx16; output mulfx(a, b, 60);", "outside fx0..fx63"),
    ("input a: fx8, b: fx8; output mulfx(a, b, 40);", "outside fx0..fx63"),
    # bit operations reinterpret an fx
    ("input a: fx32; output a << 3;", "silently changes"),
    ("input a: fx32, b; output a & b;", "silently changes"),
    ("input a: fx32; output ~a;", "reinterprets an fx"),
    # an fx as a condition
    ("input a: fx32; let r = 0; if a { r = 1; } output r;", "plain integer"),
    # annotation contradicted by the initializer
    ("input a: fx16; let x: fx32 = a; output x;", "fx32"),
    # a store mixing units through an annotated array
    ("input a: fx16; arr m[2]: fx32; m[0] = a; output m[0];", "fx32 vs fx16"),
    # function argument at the wrong scale
    ("fn f(x: fx32) { return x; } input a: fx16; output f(a);", "fx32 vs fx16"),
    # a poly variable refined to fx32, then misused against fx16
    ("input p: fx32, r: fx16; let acc = 0; acc = acc + p; acc = acc + r; output acc;",
     "fx32 vs fx16"),
])
def test_scale_bugs_are_compile_errors(src, fragment):
    with pytest.raises(ScaleError) as exc:
        compile_source(src)
    assert fragment in str(exc.value), f"error message {exc.value} lacks {fragment!r}"


# ------------------------------------------------------------------ legitimate idioms
def test_correct_fixed_point_code_compiles_and_agrees():
    one32 = 1 << 32
    # renormalized product, scale by a count, ratio of like units
    src = """
    input price: fx32, qty, other: fx32;
    let notional: fx32 = price * qty;
    let product: fx32 = mulfx(price, other, 32);
    let ratio = price / other;
    output notional, product, ratio;
    """
    assert both(src, [3 * one32, 7, 2 * one32]) == [21 * one32, 6 * one32, 1]


def test_fn_signatures_propagate_scales():
    one32 = 1 << 32
    src = """
    fn ecl(pd: fx32, lgd: fx32, ead) { return mulfx(mulfx(pd, lgd, 32), ead, 32); }
    input pd: fx32, lgd: fx32, ead;
    let e: fx0 = ecl(pd, lgd, ead);
    output e;
    """
    # pd*lgd -> fx32; *ead(poly) -> poly? no: ead is unannotated param -> poly, so the
    # fn returns poly, assignable to fx0. The point is the ANNOTATED path checks.
    assert both(src, [one32 // 2, one32 // 2, 1000]) == [250]


def test_zero_literals_are_polymorphic():
    src = """
    input p: fx32;
    let acc: fx32 = 0;
    acc = acc + p;
    output max(acc, 0);
    """
    assert both(src, [42]) == [42]


def test_unannotated_programs_are_untouched():
    # everything the scale checker would refuse is fine without annotations --
    # the pass is strictly opt-in
    src = "input a, b; output a + b, a * b, a << 3, a & b;"
    assert both(src, [5, 3]) == [8, 15, 40, 1]


def test_fx0_is_a_concrete_integer_annotation():
    with pytest.raises(ScaleError):
        compile_source("input a: fx0, b: fx32; output a + b;")
    assert both("input a: fx0, b; output a + b;", [1, 2]) == [3]


def test_the_cecl_kernel_fully_annotated():
    """The anchor computation with its units spelled out -- still byte-identical."""
    import json
    import pathlib
    from obsign_verify.replay import output_sha256
    root = pathlib.Path(__file__).resolve().parent.parent
    receipt = json.loads(
        (root / "src/obsign_verify/data/conformance/producer_signed_replay.json").read_text())
    # pd and lgd are fx32 fractions; ead and the result are plain cents. The input
    # window is heterogeneous, so it stays unannotated and the UNITS are pinned at the
    # function boundary instead -- exactly where a reviewer wants them stated.
    src = """
    const S = 32;
    fn ecl(pd: fx32, lgd: fx32, ead: fx0) { return mulfx(mulfx(pd, lgd, S), ead, S); }
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
