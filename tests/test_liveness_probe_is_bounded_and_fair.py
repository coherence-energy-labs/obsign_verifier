"""The input-liveness probe must be BOUNDED and it must not accuse honest receipts.

`_input_liveness` sits inside the `verified` conjunction: a "dead" or "guarded"
verdict REFUSES the receipt and prints "a constant dressed as a computation". A
check with that much authority owes two things, and it was delivering neither.

1. IT MUST COST WHAT IT SAYS IT COSTS. The docstring promises "total perturbation
   work is capped at a small multiple of the base run ... Both are what stop this
   being a DoS amplifier". The budget is denominated in VM STEPS -- and steps are
   the one thing a probe run need not spend. Every probe re-allocates `prog["mem"]`
   cells, re-validates all `len(prog["code"])` instructions and re-loads
   `len(inputs)` values before executing its first instruction, and none of that is
   charged. A program that HALTs immediately retires one step per probe, so the
   4,000,000-step budget buys 4,000,000 full machine instantiations.

   Measured on this machine before the fix: a 1,754-byte receipt (mem 2^20, 400
   declared inputs, `code: [["HALT"]]`) took 8.0 s in Python and 14.0 s in Node
   against a 3.2 ms base run -- and it takes that long even though its
   `receipt_sha256` is garbage, because the probe runs before anything is trusted.
   At the wire limit of 2^20 declared inputs (a 2.1 MB receipt, which
   `load_receipt` accepts) one probe costs 125 ms and the budget permits four
   million of them: 139 hours of CPU from one file.

2. IT MUST NOT CALL AN HONEST PROGRAM A CONSTANT. The perturbation ladder was seven
   fixed ABSOLUTE deltas, the largest 1,000,000. Any computation whose output is
   coarser than that in its inputs' own units never moves under any of them --
   money in cents reported in millions, a byte count reported in gigabytes, a
   bucketed or rounded figure -- and is refused as a hardcoded constant. That is
   the verifier's central promise failing in the direction that discredits an
   honest producer.

Both halves are pinned here, and the existing refusals (bare constant, guarded
constant) are re-pinned so a fix for one cannot quietly buy the other.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

from obsign_verify import mint, replay
from obsign_verify.canonical import canonical_bytes
from obsign_verify.replayc import compile_source
from obsign_verify.verify import verify

#: `obsign_verify.verify` is rebound to the FUNCTION by the package's __init__, so the
#: module itself has to come out of sys.modules.
verifymod = sys.modules["obsign_verify.verify"]

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_needs_node = pytest.mark.skipif(
    not _HAS_NODE and "node" not in _REQUIRED,
    reason="node not available (set OBSIGN_REQUIRE=node to make this leg mandatory)")


# --------------------------------------------------------------------- 1. the cost

#: What ONE run of PROG really costs the verifier: the instructions it retires PLUS
#: the fixed work every run pays before retiring any -- the memory it allocates, the
#: inputs it copies and loads, the code it re-validates. Nothing here is exotic; it
#: is simply everything `run_counted` touches that the step counter does not see.
#: Written out here rather than imported, so the test measures the property and not
#: the implementation's own opinion of it.
_CELL, _INPUT, _CONST, _CODE, _STEP = 1, 16, 8, 128, 64


def _real_cost(prog: dict, n_inputs: int, steps: int) -> int:
    return (steps * _STEP + prog["mem"] * _CELL + n_inputs * _INPUT
            + len(prog["code"]) * _CODE + len(prog["consts"]) * _CONST)


#: The rule the probe promises: total perturbation work is at most a small multiple
#: of the base run, or a fixed floor for programs too cheap for a multiple to mean
#: anything -- plus at most one run of overshoot, because the budget is checked
#: BEFORE a probe rather than after it.
def _permitted(base: int) -> int:
    return max(8 * base, 32_000_000) + base


def _instrumented(monkeypatch):
    """Record the real cost of every `run_counted` the verifier performs."""
    calls: list[int] = []
    real = replay.run_counted

    def counting(prog, inputs, step_cap=None):
        try:
            out, used = real(prog, inputs, step_cap)
        except replay.Trap as trap:
            calls.append(_real_cost(prog, len(inputs), getattr(trap, "steps", 0)))
            raise
        calls.append(_real_cost(prog, len(inputs), used))
        return out, used

    monkeypatch.setattr(verifymod.replaymod, "run_counted", counting)
    return calls


def _halt_only_receipt(n_inputs: int, mem: int = 1 << 20) -> dict:
    """The cheapest possible machine wrapped around the most expensive possible
    instantiation: one HALT, a megacell of memory and N declared inputs."""
    prog = {"spec": replay.SPEC, "mem": mem, "steps": 1, "consts": [],
            "input": {"offset": 0, "length": n_inputs},
            "output": {"offset": 0, "length": 1},
            "code": [["HALT"]]}
    return mint.replay_receipt(prog, [7] * n_inputs)


def test_the_probe_never_spends_more_than_a_small_multiple_of_the_base_run(monkeypatch):
    """THE EXPLOIT. The receipt below is under 300 bytes of program and its claim
    hash is deliberately WRONG, so nothing about it is trusted -- and the probe
    still instantiates the machine hundreds of times, charging itself one step
    each. Scaled to the wire limit this is hours of CPU per file."""
    receipt = _halt_only_receipt(40)
    tampered = dict(receipt, receipt_sha256="0" * 64)
    assert len(canonical_bytes(tampered)) < 2048, "precondition: a tiny document"

    calls = _instrumented(monkeypatch)
    res = verify(tampered)
    assert res["integrity"] is False, "precondition: this receipt is not even integral"
    assert calls, "precondition: the verifier ran the program"

    base, probes = calls[0], sum(calls[1:])
    assert probes <= _permitted(base), (
        f"the liveness probe spent {probes / base:.0f}x the base run's work on a "
        f"receipt that fails integrity ({len(calls) - 1} machine instantiations of "
        f"{base:,} cost units each). The budget counts VM steps, and this program "
        f"retires one step per probe, so the cap never engages: it is a denial of "
        f"service delivered through the file you were invited to check.")


def test_the_probe_charges_for_the_code_it_re_validates(monkeypatch):
    """The same hole through a second door: `validate()` walks every instruction on
    EVERY probe run, so a program that HALTs on instruction 0 and carries 65,535
    dead instructions behind it pays a full validation per probe and is charged one
    step. Measured before the fix: 34.5 ms per probe on a 787 KB receipt."""
    n = 12
    code = [["HALT"]] + [["MOV", 0, 0]] * (replay.MAX_CODE - 1)
    prog = {"spec": replay.SPEC, "mem": n + 1, "steps": 1, "consts": [],
            "input": {"offset": 0, "length": n},
            "output": {"offset": n, "length": 1},
            "code": code}
    receipt = mint.replay_receipt(prog, [7] * n)

    calls = _instrumented(monkeypatch)
    verify(receipt)
    base, probes = calls[0], sum(calls[1:])
    assert probes <= _permitted(base), (
        f"the probe re-validated {len(calls) - 1} x {len(code)} instructions "
        f"({probes / base:.0f}x the base run) while charging itself "
        f"{len(calls) - 1} steps")


# ------------------------------------------------------- 2. honest receipts stand

#: Cents. An honest total reported in whole hundreds of millions -- the granularity
#: of a figure a bank actually publishes. 15,600,000 cents clear of a rounding
#: boundary, so no perturbation smaller than that can move the answer.
_CENTS = 743_215_600_000

_COARSE = "input cents; output cents / 100000000;"

#: An honest program with an honest sanity check: liabilities cannot be negative.
#: The check TRAPS on a perturbation, which the probe reads as "guarded" -- the
#: shape it was taught to call a hardcoded result behind an equality guard.
_COARSE_GUARDED = """
input assets_cents, liabilities_cents;
if liabilities_cents < 0 { let bad = 1 / 0; }
output (assets_cents - liabilities_cents) / 100000000;
"""


def _verdict(src: str, inputs: list[int]) -> dict:
    return verify(mint.replay_receipt(compile_source(src), inputs))


def test_a_figure_reported_in_millions_is_not_a_hardcoded_constant():
    """THE FALSE ACCUSATION. `cents / 100000000` uses its input on every run. Every
    perturbation the probe knows is at most 1,000,000 cents, which cannot move a
    figure denominated in hundreds of millions -- so the verifier reports that the
    program ignores its inputs and REFUSES a receipt that is entirely honest."""
    v = _verdict(_COARSE, [_CENTS])
    assert v["reproduced"] is True and v["integrity"] is True, v
    assert v["input_liveness"] != "dead", (
        "an honest computation was reported as ignoring its input because the "
        "probe only ever perturbs by at most 1,000,000")
    assert v["verified"] is True, v["notes"]


def test_an_honest_sanity_check_is_not_read_as_an_equality_guard():
    """The same coarseness, reached through the "guarded" verdict: the program's
    own range check traps on one perturbation and the rest are too small to move a
    figure in hundreds of millions, so nothing is ever observed reaching the
    output."""
    v = _verdict(_COARSE_GUARDED, [_CENTS + 400, 400])
    assert v["reproduced"] is True, v
    assert v["input_liveness"] != "guarded", (
        "a program whose only guard is `liabilities >= 0` was reported as refusing "
        "to run on anything but its own receipted inputs")
    assert v["verified"] is True, v["notes"]


def test_the_perturbation_ladder_reaches_the_scale_of_its_input():
    """Directly: SOME probe value for a large input must be large. A ladder of
    fixed small deltas can only ever exercise a program at the resolution of those
    deltas, whatever the input's magnitude."""
    values = verifymod._probe_values(_CENTS)
    assert max(abs(v - _CENTS) for v in values) > _CENTS // 4, (
        "no perturbation comes within a quarter of the input's own magnitude, so "
        "any computation coarser than the fixed ladder reads as dead")


# ---------------------------------------------------- 3. the refusals still refuse

def test_the_bare_constant_is_still_refused():
    v = _verdict("input a, b; output 424242;", [5, 7])
    assert v["input_liveness"] == "dead", v
    assert v["verified"] is False


def test_the_guarded_constant_is_still_not_live():
    src = ("input a, b; let ok = 0; if a == 5 { if b == 7 { ok = 1; } } "
           "let guard = 1 / ok; output 424242;")
    v = _verdict(src, [5, 7])
    assert v["input_liveness"] != "live", v
    assert v["verified"] is False


def test_an_honest_program_is_still_found_live():
    v = _verdict("input a, b; output a * 3 + b;", [5, 7])
    assert v["input_liveness"] == "live", v
    assert v["verified"] is True


# ------------------------------------------------------------------ 4. JS parity

@_needs_node
def test_javascript_reaches_the_same_liveness_verdict(tmp_path):
    """The two implementations must not disagree about which receipts exist. A
    coarse-grained honest receipt refused by one and accepted by the other is the
    split this format cannot absorb."""
    import json

    for name, src, inputs in (
        ("coarse", _COARSE, [_CENTS]),
        ("coarse-guarded", _COARSE_GUARDED, [_CENTS + 400, 400]),
        ("bare-constant", "input a, b; output 424242;", [5, 7]),
        ("honest", "input a, b; output a * 3 + b;", [5, 7]),
    ):
        receipt = mint.replay_receipt(compile_source(src), inputs)
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        proc = subprocess.run(
            ["node", "js/bin/obsign-verify.js", "--json", str(path)],
            capture_output=True, text=True, timeout=600, check=False)
        js = json.loads(proc.stdout)[0]
        py = verify(receipt)
        assert (py["verified"], py["input_liveness"]) == (js["verified"], js["input_liveness"]), (
            f"{name}: python={py['verified']}/{py['input_liveness']} "
            f"javascript={js['verified']}/{js['input_liveness']}")
