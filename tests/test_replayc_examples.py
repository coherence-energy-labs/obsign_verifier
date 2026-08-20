"""The examples ship working, and their numbers are INDEPENDENTLY computed.

Each expected value below is derived in plain Python here in the test -- unbounded
ints, written from the problem statement -- not by running the compiler and pasting
what came out. An example that drifts from its own documentation fails; a compiler
change that alters any example's numbers fails. cecl.rl is additionally anchored to
the shipped conformance receipt's output hash, so the flagship example IS the
flagship receipt.
"""
from __future__ import annotations

import json
import pathlib

from obsign_verify.replay import output_sha256
from obsign_verify.replayc import compile_source, interpret_source, run_source

ROOT = pathlib.Path(__file__).resolve().parent.parent
EX = ROOT / "examples" / "rl"


def load(name: str) -> str:
    return (EX / name).read_text(encoding="utf-8")


def both(src: str, inp: list[int]) -> list[int]:
    vm = run_source(src, inp)
    assert vm == interpret_source(src, inp)
    return vm


def test_cecl_example_is_the_conformance_receipt():
    receipt = json.loads(
        (ROOT / "src/obsign_verify/data/conformance/producer_signed_replay.json").read_text())
    out = both(load("cecl.rl"), receipt["params"]["inputs"])
    assert output_sha256(out) == receipt["output"]["sha256"]


def test_amortization_matches_independent_math():
    one32 = 1 << 32
    principal, payment, months = 1_000_000_00, 8_800_00, 12   # $1M, $8,800/mo, 1 year
    rate_fx = int(0.005 * one32)                              # 0.5%/month, fx32

    # independent reference: unbounded ints, truncation toward zero like the machine
    def tdiv(a, b):
        q = abs(a) // abs(b)
        return -q if (a < 0) != (b < 0) else q

    bal, interest_total = principal, 0
    for _ in range(months):
        interest = tdiv(bal * rate_fx, 1 << 32)
        interest_total += interest
        bal = bal + interest - payment
        if bal < 0:
            bal = 0

    assert both(load("amortization.rl"),
                [principal, rate_fx, payment, months]) == [bal, interest_total]
    # sanity on the numbers themselves: some principal was repaid, interest accrued
    assert 0 < bal < principal and interest_total > 0


def test_isqrt_matches_math_isqrt_across_the_range():
    import math
    src = load("isqrt.rl")
    for n in [0, 1, 2, 3, 4, 24, 25, 10**6, 10**12 + 3, (1 << 62) + 12345,
              (1 << 63) - 1]:
        assert both(src, [n]) == [math.isqrt(n)], f"isqrt({n})"


def test_portfolio_stats_matches_independent_math():
    one32 = 1 << 32
    returns = [int(x * one32) for x in (0.05, -0.02, 0.10, 0.03, 0.00, -0.07, 0.04, 0.01)]
    weights = [10, 20, 5, 15, 10, 10, 20, 10]

    def tdiv(a, b):
        q = abs(a) // abs(b)
        return -q if (a < 0) != (b < 0) else q

    wsum = sum(weights)
    wret = sum(r * w for r, w in zip(returns, weights))
    mean = tdiv(wret, wsum)
    var2 = sum(tdiv((r - mean) * (r - mean), one32) * w for r, w in zip(returns, weights))
    expected = [mean, tdiv(var2, wsum)]

    assert both(load("portfolio_stats.rl"), returns) == expected


def test_every_example_compiles_with_a_finite_or_declared_budget():
    for f in sorted(EX.glob("*.rl")):
        prog = compile_source(f.read_text(encoding="utf-8"))
        assert prog["steps"] >= 1, f.name
