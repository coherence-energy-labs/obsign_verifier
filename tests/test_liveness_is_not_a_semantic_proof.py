"""The liveness probe can be gamed, so it must not speak like a proof.

`_input_liveness` exists to refuse the hardcoded-constant attack: a program that
ignores its inputs, re-derives perfectly, and therefore establishes nothing about
the inputs it names. Perturb an input, watch the output move, conclude the inputs
are used. That much is sound.

The hole is what the probe does with a TRAP. It counted a trap as evidence of
dependence -- the value "controls whether an output exists at all" -- which is true
and useless, because the attacker chooses when to trap. Guard the constant:

    if inputs == the exact receipted inputs:  return THE NUMBER I WANT
    else:                                     trap

The genuine run returns the number, hashes correctly and re-derives. Every probe
perturbs an input, hits the guard, traps -- and the old probe read that as "live".
The hardcoded-constant attack simply grew a guard and walked back through.

There is a deeper limit that no amount of probing removes: an adversary can always
write `if inputs == this_quarter: return desired else: run_the_real_formula`, which
behaves correctly under every perturbation anyone tries. No finite black-box probe
can establish that a program computes the formula you believe it computes. So
liveness is DIAGNOSTIC EVIDENCE, never a semantic guarantee, and the semantic
boundary is an approved program identity (`--expect-program`) checked by someone who
read the program.

These tests pin both halves: the guard attack must not be called live, and an
honest program must still be found live.
"""
from __future__ import annotations

import pytest

from obsign_verify import mint
from obsign_verify.verify import verify
from obsign_verify.replayc import compile_source

# The attack. `ok` is 1 only for the exact receipted inputs; `1/ok` traps otherwise,
# and the output never depends on a or b at all -- it is a constant.
_GUARDED_CONSTANT = """
input a, b;
let ok = 0;
if a == 5 { if b == 7 { ok = 1; } }
let guard = 1 / ok;
output 424242;
"""

_HONEST = "input a, b; output a * 3 + b;"

# A constant with no guard: the attack the probe was built for, still refused.
_BARE_CONSTANT = "input a, b; output 424242;"


def _verdict(src: str, inputs: list[int]) -> dict:
    receipt = mint.replay_receipt(compile_source(src), inputs)
    return verify(receipt)


def test_the_guarded_constant_is_not_reported_live():
    """THE EXPLOIT. A trap on a perturbed input is the attacker's choice, not
    evidence that the receipted output depended on anything."""
    v = _verdict(_GUARDED_CONSTANT, [5, 7])
    assert v["reproduced"] is True, "precondition: the attack re-derives perfectly"
    assert v["integrity"] is True, "precondition: the attack hashes correctly"
    assert v["input_liveness"] != "live", (
        "a program whose output is a CONSTANT was reported as using its inputs, "
        "because it traps on every perturbation -- the hardcoded-constant attack "
        "with a guard bolted on")


def test_the_guarded_constant_does_not_reach_a_clean_verified():
    """It may be refused or flagged, but it must never read as a clean pass."""
    v = _verdict(_GUARDED_CONSTANT, [5, 7])
    assert not (v["verified"] and v["input_liveness"] == "live"), v


def test_the_bare_constant_is_still_refused():
    """The original attack must not regress while fixing its guarded sibling."""
    v = _verdict(_BARE_CONSTANT, [5, 7])
    assert v["input_liveness"] == "dead", v
    assert v["verified"] is False, "a program that ignores its inputs must not verify"


def test_an_honest_program_is_still_found_live():
    """The fix must not cost honest receipts their liveness evidence."""
    v = _verdict(_HONEST, [5, 7])
    assert v["input_liveness"] == "live", v
    assert v["verified"] is True, v


def test_liveness_reports_per_input_evidence_not_one_global_boolean():
    """A 500-input receipt that ignores 499 of them used to clear the check on the
    strength of one live input. The verdict must say WHICH inputs moved the answer."""
    v = _verdict("input a, b, c; output a + 0 * b + 0 * c;", [1, 2, 3])
    per = v.get("input_liveness_by_input")
    assert per is not None, "the verdict carries no per-input liveness vector"
    assert len(per) == 3, per
    assert per[0] == "live", per
    assert per[1] != "live" and per[2] != "live", (
        "inputs the output provably ignores were reported as used", per)
