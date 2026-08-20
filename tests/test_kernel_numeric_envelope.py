"""tau_field_fixed's numeric envelope: which receipts are ADMISSIBLE, not just how
much work they may demand.

test_kernel_hardening.py bounds the WORK -- grid, steps, grid*grid*steps, and the
grid<2 NaN. It says nothing about the VALUES, and that leaves the hole this file
closes: source tuples and coefficients were unconstrained, so a receipt could ask
this verifier to re-execute arithmetic that has no single right answer.

int64 overflow is not an error in any substrate this kernel claims to be identical
on. numpy wraps silently -- measured 9 of 64 cells wrong at D=1e5 against an
exact-integer oracle, with no exception and no warning. `rustc -O`, which is how the
producer builds libcoherence, wraps silently too. A debug-profile Rust build has
overflow-checks ON and PANICS on the same line. C++ signed overflow is undefined
behaviour the optimiser may assume away. Three of those four are a wrong answer with
no diagnostic and the fourth is a crash: an overflowing receipt has no correct output
to be identical about, so re-executing it is not verification, it is guessing along
with whoever sent the file.

The float half is worse because it is quieter. A NaN or an inf reaching
np.round(...).astype(np.int64) is a PLATFORM-DEPENDENT cast: INT64_MIN on x86-64, 0
on aarch64. This kernel already refuses grid<2 for exactly that reason; `width == 0`
with a source centre on a grid node reaches the same NaN through a different door,
and so do negative widths, non-finite coefficients, and a strength large enough to
overflow the scaled cast.

Every case below was confirmed against the unfixed kernel before the bound existed.
The headline: at frac_bits=60 the producer's three substrates returned three
different things for one receipt -- numpy 1152921504606846976, torch a RuntimeError,
the Rust FFI -6917529027641081856 -- and this verifier admitted it.
"""
from __future__ import annotations

import math
import sys

import numpy as np
import pytest

from obsign_verify import kernel as K
from obsign_verify.verify import verify

INT64_MAX = (1 << 63) - 1
SMALLEST_SUBNORMAL = 5e-324


def _p(**over):
    p = {"grid": 8, "steps": 3, "D": 0.14, "gamma": 0.02, "dt": 0.15,
         "frac_bits": 24, "sources": [[0.3, 0.3, 0.11, 0.01]]}
    p.update(over)
    return p


# The hostile corpus, shared verbatim with the producer's
# tests/test_fixedpoint_numeric_envelope.py. The two must agree case for case: a
# verifier that admits what the producer would never mint, or refuses what it would,
# has already diverged from it.
HOSTILE = [
    ({"sources": [[0.0, 0.0, 1.0, 0.0]]}, "width",
     "width 0 at a centre on a grid node is 0/0 = NaN -> platform-dependent cast"),
    ({"sources": [[0.3, 0.3, 0.11, 0.0]]}, "width",
     "width 0 is a divide-by-zero even when no node coincides"),
    ({"sources": [[0.3, 0.3, 0.11, -0.01]]}, "width",
     "negative width flips the exponent sign -> exp overflows to +inf"),
    ({"sources": [[0.3, 0.3, 0.11, SMALLEST_SUBNORMAL]]}, "width",
     "a subnormal divisor is flushed to zero under FTZ -> 0/0 = NaN there only"),
    ({"sources": [[0.3, 0.3, 0.11, float("nan")]]}, "width",
     "NaN width propagates to the int64 cast"),
    ({"sources": [[0.3, 0.3, 0.11, float("inf")]]}, "width",
     "non-finite width"),
    ({"sources": [[float("nan"), 0.3, 0.11, 0.01]]}, "cx",
     "non-finite source coordinate"),
    ({"sources": [[0.3, float("inf"), 0.11, 0.01]]}, "cy",
     "non-finite source coordinate"),
    ({"sources": [[0.3, 0.3, float("inf"), 0.01]]}, "strength",
     "inf strength reaches the int64 cast"),
    ({"sources": [[0.3, 0.3, float("nan"), 0.01]]}, "strength",
     "NaN strength reaches the int64 cast"),
    ({"sources": [[1e200, 0.3, 0.11, 0.01]]}, "cx",
     "(cx - x)**2 overflows f64 to inf"),
    ({"sources": [[0.0, 0.0, 1e12, 0.01]]}, "strength",
     "strength*2**frac_bits leaves int64 -> invalid cast, observed INT64_MIN"),
    ({"D": float("nan")}, "D", "non-finite coefficient"),
    ({"D": float("inf")}, "D", "non-finite coefficient"),
    ({"gamma": float("nan")}, "gamma", "non-finite coefficient"),
    ({"dt": float("inf")}, "dt", "non-finite coefficient"),
    ({"frac_bits": 58}, "frac_bits",
     "4*hi = 1.15e19 leaves int64: the laplacian's own temporaries overflow"),
    ({"frac_bits": 60}, "frac_bits",
     "observed three-way substrate divergence: numpy / torch crash / Rust wrap"),
    ({"D": 1e5}, "D",
     "silent int64 wrap: 9 of 64 cells disagreed with an exact-integer oracle"),
    ({"D": 1e9}, "D", "D*lap leaves int64"),
    ({"gamma": 1e9}, "gamma", "gamma*t leaves int64"),
    ({"dt": 1e9}, "dt", "dt*inner leaves int64"),
    ({"sources": [[0.3, 0.3, 1e6, 0.01]]}, "dt",
     "strength fits int64 alone but dt*inner does not"),
    ({"frac_bits": 57, "sources": [[0.0, 0.0, 20.0, 10.0]]}, "D",
     "observed wrap: all three substrates disagreed with exact arithmetic"),
    ({"frac_bits": 31}, "D",
     "the joint bound: D*lap grows as scale**2, so frac_bits and D trade off"),
    ({"sources": [[0.3, 0.3, 0.11]]}, "source",
     "a 3-tuple source unpacks differently or not at all"),
]


@pytest.mark.parametrize("over, param, why", HOSTILE,
                         ids=[f"{list(o)[0]}-{w[:34]}" for o, _, w in HOSTILE])
def test_a_value_outside_the_envelope_is_refused_by_name(over, param, why):
    """Fail CLOSED, and say which parameter and which bound. A refusal that does not
    name the offending value is a refusal nobody can act on."""
    with pytest.raises(ValueError) as e:
        K.build_fixed_inputs(_p(**over))
    assert param in str(e.value), (
        f"refused, but the message does not name `{param}`: {e.value}\n  ({why})")


def test_the_refusal_reaches_the_verdict_as_a_refusal_not_a_crash():
    """A numeric refusal must arrive as 'not verified' with a note, exactly as the
    work-bound refusals do. An exception escaping verify() is a fail-OPEN to whoever
    called it -- the same defect test_kernel_hardening pins for grid."""
    receipt = {"spec": "obsign/receipt/v1", "kernel": "tau_field_fixed",
               "params": _p(sources=[[0.0, 0.0, 1.0, 0.0]]),
               "output": {"sha256": "0" * 64, "shape": [8, 8], "dtype": "int64"}}
    res = verify(receipt)
    assert res["verified"] is False
    assert any("width" in n for n in res["notes"]), res["notes"]


# --------------------------------------------------------------------------- #
# The counterweight: the envelope must not refuse anything legitimate.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("over", [
    {},
    {"frac_bits": 0},
    {"frac_bits": 26},                                    # a shipped conformance scale
    {"frac_bits": 30},                                    # the joint max for D = 0.14
    # MAX_FRAC_BITS bounds the CLAMP alone; with no coefficients to multiply it, the
    # top of the frac_bits range really is reachable.
    {"frac_bits": 57, "D": 0.0, "gamma": 0.0, "dt": 0.0, "sources": []},
    {"D": 9.5, "sources": [[0.5, 0.5, -8.0, 0.05]]},      # negative strength is legal
    {"sources": [[0.3, 0.3, 0.11, 0.01], [0.7, 0.7, 0.16, 0.008]]},
    {"steps": 0},
    {"grid": 2},
    {"sources": []},
])
def test_an_ordinary_field_is_still_admitted(over):
    inp = K.build_fixed_inputs(_p(**over))
    out = K.evolve(inp)
    assert out.dtype == np.int64
    assert out.shape == (int(_p(**over)["grid"]),) * 2


# --------------------------------------------------------------------------- #
# The coefficient bound, at the boundary and one step past it
# --------------------------------------------------------------------------- #
def _limits(frac_bits=24):
    scale = 1 << frac_bits
    lo, hi = int(round(0.01 * scale)), int(round(10.0 * scale))
    return scale, lo, hi, 4 * (hi - lo)


def test_the_largest_D_that_cannot_wrap_is_accepted_and_the_next_one_is_not():
    """Named boundary: |D_int| * 4*(hi-lo) must stay inside int64. At frac_bits 24
    that is D_int <= 13757652987, i.e. D <= 820.0200192332268."""
    scale, _, _, lap_max = _limits()
    d_int_max = INT64_MAX // lap_max
    assert d_int_max * lap_max <= INT64_MAX
    assert (d_int_max + 1) * lap_max > INT64_MAX

    K.build_fixed_inputs(_p(D=d_int_max / scale))
    with pytest.raises(ValueError, match="D"):
        K.build_fixed_inputs(_p(D=(d_int_max + 1) / scale))


def test_the_largest_gamma_that_cannot_wrap_is_accepted_and_the_next_one_is_not():
    """|G_int| * hi must stay inside int64 -- `G*t` with t at the top clamp."""
    scale, _, hi, _ = _limits()
    g_int_max = INT64_MAX // hi
    K.build_fixed_inputs(_p(gamma=g_int_max / scale))
    with pytest.raises(ValueError, match="gamma"):
        K.build_fixed_inputs(_p(gamma=(g_int_max + 1) / scale))


def test_frac_bits_57_is_the_last_scale_whose_clamp_survives_the_laplacian():
    """hi = round(10.0*2**frac_bits) and the laplacian forms `up+dn+lf+rt` and `4*t`
    as int64 temporaries, so 4*hi must fit. 57 does, 58 does not.

    Checked with the coefficients zeroed, because MAX_FRAC_BITS bounds the CLAMP on
    its own. With coefficients present the joint bound below binds first."""
    assert 4 * int(round(10.0 * (1 << 57))) <= INT64_MAX
    assert 4 * int(round(10.0 * (1 << 58))) > INT64_MAX
    assert K.MAX_FRAC_BITS == 57
    zero = {"D": 0.0, "gamma": 0.0, "dt": 0.0, "sources": []}
    K.build_fixed_inputs(_p(frac_bits=57, **zero))
    with pytest.raises(ValueError, match="frac_bits"):
        K.build_fixed_inputs(_p(frac_bits=58, **zero))


def test_frac_bits_and_D_trade_off_because_D_times_lap_grows_as_scale_squared():
    """The bound a per-parameter table could never express: D scales by
    2**frac_bits and so does the laplacian it multiplies, so the product grows as
    scale**2. At the shipped D = 0.14 the real ceiling is frac_bits 30."""
    for frac_bits, admissible in ((24, True), (30, True), (31, False), (57, False)):
        scale = 1 << frac_bits
        lap_max = 4 * (int(round(10.0 * scale)) - int(round(0.01 * scale)))
        fits = int(round(0.14 * scale)) * lap_max <= INT64_MAX
        assert fits is admissible, f"frac_bits {frac_bits}"
        if admissible:
            K.build_fixed_inputs(_p(frac_bits=frac_bits))
        else:
            with pytest.raises(ValueError, match="D"):
                K.build_fixed_inputs(_p(frac_bits=frac_bits))


# --------------------------------------------------------------------------- #
# The bound is not decoration: without it these produce a WRONG answer, silently
# --------------------------------------------------------------------------- #
def _exact(inp):
    """The same recurrence in Python bignums -- no int64, so no wrap. This is the
    oracle every substrate must match, and the one they stopped matching."""
    n, steps, scale = inp["n"], inp["steps"], inp["SCALE"]
    D, G, DT, lo, hi = inp["D"], inp["G"], inp["DT"], inp["lo"], inp["hi"]
    S = inp["S"].tolist()
    t = [[scale] * n for _ in range(n)]

    def td(a):
        return -((-a) // scale) if a < 0 else a // scale

    for _ in range(steps):
        nt = [[0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                up = t[i - 1][j] if i > 0 else t[i][j]
                dn = t[i + 1][j] if i < n - 1 else t[i][j]
                lf = t[i][j - 1] if j > 0 else t[i][j]
                rt = t[i][j + 1] if j < n - 1 else t[i][j]
                lap = up + dn + lf + rt - 4 * t[i][j]
                inner = td(D * lap) - td(G * t[i][j]) + S[i][j]
                nt[i][j] = min(max(t[i][j] + td(DT * inner), lo), hi)
        t = nt
    return t


def test_inside_the_envelope_int64_matches_exact_integer_arithmetic():
    """The point of the envelope: within it, int64 and unbounded integers agree, so
    every substrate has one right answer to produce."""
    inp = K.build_fixed_inputs(_p(grid=8, steps=3, D=9.5,
                                  sources=[[0.5, 0.5, -8.0, 0.05]]))
    assert [list(map(int, r)) for r in K.evolve(inp)] == _exact(inp)


def test_the_refused_coefficient_really_did_wrap():
    """Pin the defect the D bound prevents, by building the inputs BEHIND the
    validator and showing int64 disagrees with exact arithmetic. If someone widens
    the bound to admit D=1e5 again, this is the damage they are admitting."""
    inp = K.build_fixed_inputs(_p(grid=8, steps=3))
    inp["D"] = int(round(1e5 * inp["SCALE"]))          # what the bound now refuses
    got, want = K.evolve(inp), _exact(inp)
    wrong = sum(1 for a, b in zip(np.asarray(got).ravel().tolist(),
                                  [v for r in want for v in r]) if a != b)
    assert wrong > 0, "expected a silent int64 wrap; the oracle agreed instead"
    assert inp["D"] * 4 * (inp["hi"] - inp["lo"]) > INT64_MAX


def test_the_envelope_constants_are_pinned():
    """A cross-implementation contract with the producer (obsign.fixedpoint), pinned
    as literals so changing one is a deliberate act with a red test attached rather
    than an incidental edit. The producer pins the identical values and additionally
    asserts, at test time, that the two modules' constants are equal."""
    assert K.MIN_GRID == 2
    assert K.MAX_GRID == 4096
    assert K.MAX_TAU_STEPS == 1_000_000
    assert K.MAX_SOURCES == 1 << 16
    assert K.MAX_CELL_STEPS == 1 << 30
    assert K.MAX_FRAC_BITS == 57
    assert K.MIN_SOURCE_WIDTH == sys.float_info.min == 2.2250738585072014e-308
    assert K.MAX_SOURCE_COORD == 1e150
    assert math.isfinite(K.MAX_SOURCE_COORD ** 2)


def test_validation_precedes_allocation_for_numeric_refusals_too():
    """A numeric refusal must land before the n*n float field is built, for the same
    reason a grid refusal does: the receipt is a file an adversary handed you."""
    import time
    t = time.perf_counter()
    with pytest.raises(ValueError):
        K.build_fixed_inputs(_p(grid=4096, steps=64, D=1e9))
    assert time.perf_counter() - t < 1.0, "refused only after doing the work"
