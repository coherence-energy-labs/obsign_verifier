"""tau_field_fixed hardening: a hostile param block must not hang the verifier or
divide differently per CPU.

Three defects, all in a kernel sold on "int64 is identical on every machine":

  * DoS -- `grid` and `steps` were unbounded, so a receipt could ask the verifier
    to allocate 149 GiB (grid 100000) or loop for ~28 hours (steps 1e9). A file an
    adversary hands you must not be able to consume your host.
  * per-CPU NaN -- at grid 1 the coordinate grid is 0/(n-1) = 0/0 = NaN, and
    np.round(NaN).astype(int64) is a PLATFORM-DEPENDENT cast: INT64_MIN on x86-64,
    0 on aarch64. That receipt verified on one CPU and refused on another.
  * INT64_MIN sign flip -- `tdiv` was `np.sign(a) * (np.abs(a) // scale)`, and
    np.abs(INT64_MIN) overflows to INT64_MIN, so tdiv(INT64_MIN) came out POSITIVE.
    A correct native port (`/` truncates toward zero without overflowing there)
    disagreed -- numpy was the substrate breaking the promise, not keeping it.
"""
from __future__ import annotations

import time

import numpy as np
import pytest

from obsign_verify import kernel as K
from obsign_verify.verify import verify


def _params(**over):
    p = {"grid": 8, "steps": 2, "D": 0.14, "gamma": 0.02, "dt": 0.15,
         "frac_bits": 24, "sources": [[0.3, 0.3, 0.11, 0.01]]}
    p.update(over)
    return p


# --------------------------------------------------------------------------- #
# DoS + NaN: refused BEFORE any allocation or loop
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("over, why", [
    ({"grid": 100000}, "a 149 GiB allocation"),
    ({"grid": 1}, "the per-CPU NaN cast"),
    ({"steps": 10 ** 9}, "a ~28-hour loop"),
    ({"grid": 4096, "steps": 1000}, "16.7M cells x 1000 steps = a total-work DoS"),
    ({"frac_bits": 200}, "an absurd scale"),
])
def test_a_hostile_param_block_is_refused_before_it_can_run(over, why):
    t = time.perf_counter()
    with pytest.raises(ValueError):
        K.build_fixed_inputs(_params(**over))
    assert time.perf_counter() - t < 1.0, (
        f"refusing {why} took real time -- it was not rejected BEFORE allocating")


def test_the_refusal_reaches_the_verdict_as_a_refusal_not_a_crash():
    """verify() must turn a param-bound ValueError into 'not verified' with a note,
    never let it escape as an exception (a crash is a fail-open to the caller)."""
    receipt = {"spec": "obsign/receipt/v1", "kernel": "tau_field_fixed",
               "params": _params(grid=100000),
               "output": {"sha256": "0" * 64, "shape": [1, 1], "dtype": "int64"}}
    res = verify(receipt)
    assert res["verified"] is False
    assert any("grid" in n and "refused" in n.lower() for n in res["notes"])


def test_a_grid_at_the_limit_is_allowed():
    """The counterweight: the bound must not refuse a legitimate small field."""
    inp = K.build_fixed_inputs(_params(grid=64, steps=10))
    out = K.evolve(inp)
    assert out.shape == (64, 64)


# --------------------------------------------------------------------------- #
# INT64_MIN: truncate toward zero, WITHOUT np.abs
# --------------------------------------------------------------------------- #
def _reference_trunc(a: int, scale: int) -> int:
    """Python-bignum truncation toward zero -- the definition, no overflow."""
    q = abs(a) // scale
    return -q if a < 0 else q


@pytest.mark.parametrize("frac_bits", [0, 1, 12, 24, 40, 60])
def test_the_kernels_truncation_is_correct_at_every_int64_edge(frac_bits):
    """Reproduce the exact numpy expression the kernel uses and check it against the
    bignum reference over INT64_MIN and its neighbours. INT64_MIN is the value the
    old np.abs form got wrong; it must now match."""
    scale = 1 << frac_bits
    I64MIN, I64MAX = -(1 << 63), (1 << 63) - 1
    edges = [0, 1, -1, scale, -scale, scale - 1, -(scale - 1),
             I64MIN, I64MIN + 1, I64MAX, I64MAX - 1, -(scale + 7), scale + 7]
    a = np.array(edges, dtype=np.int64)
    # the published kernel formula (see kernel.evolve.tdiv):
    bias = (a >> np.int64(63)) & np.int64(scale - 1)
    got = (a + bias) >> np.int64(frac_bits)
    for v, g in zip(edges, got):
        assert int(g) == _reference_trunc(v, scale), (
            f"tdiv({v}, 2^{frac_bits}) = {int(g)}, reference {_reference_trunc(v, scale)}")


def test_the_old_np_abs_form_was_wrong_at_exactly_int64_min():
    """Pin the defect so a well-meaning 'simplification' back to np.abs is caught."""
    scale = 1 << 24
    a = np.array([-(1 << 63)], dtype=np.int64)
    old = int((np.sign(a) * (np.abs(a) // scale))[0])
    assert old == 549_755_813_888, "the old form's sign bug"
    assert _reference_trunc(-(1 << 63), scale) == -549_755_813_888, "the truth"
    assert old != _reference_trunc(-(1 << 63), scale)


def test_evolve_is_deterministic_and_reproduces_its_own_output():
    inp = K.build_fixed_inputs(_params(grid=24, steps=30))
    a = K.evolve(K.build_fixed_inputs(_params(grid=24, steps=30)))
    b = K.evolve(inp)
    assert np.array_equal(a, b)
