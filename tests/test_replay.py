"""What a stranger is trusting when the computation travels inside the receipt.

The fixed kernel is ours; a replay program is ATTACKER-SUPPLIED. Every test here
exists because the property it pins can fail while the verifier still prints
something confident.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from obsign_verify import verify
from obsign_verify.canonical import canonical_sha256, claim_of
from obsign_verify.replay import (
    INT64_MAX, INT64_MIN, SPEC, Trap, output_sha256, program_sha256, run, validate,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "ecl_receipt.json"


def prog(code, consts=(0,), mem=16, steps=1000, in_len=1, out_len=1):
    return {
        "spec": SPEC, "mem": mem, "steps": steps, "consts": list(consts),
        "input": {"offset": mem - in_len, "length": in_len},
        "output": {"offset": 0, "length": out_len},
        "code": code,
    }


# ----------------------------------------------------------------- arithmetic

def test_wrapping_is_int64_not_python_bignum():
    """Python ints are unbounded. If the machine forgets its width, it silently
    computes a different function from any port with a native i64."""
    p = prog([["LOADC", 0, 0], ["LOADC", 1, 1], ["ADD", 0, 0, 1], ["HALT"]],
             consts=[INT64_MAX, 1])
    assert run(p, [0]) == [INT64_MIN]


def test_int64_min_divided_by_minus_one_wraps_rather_than_raising():
    """The one case that overflows division. On x86 the hardware instruction traps;
    here it must wrap to INT64_MIN, and a port that lets it raise disagrees."""
    p = prog([["LOADC", 0, 0], ["LOADC", 1, 1], ["DIV", 0, 0, 1], ["HALT"]],
             consts=[INT64_MIN, -1])
    assert run(p, [0]) == [INT64_MIN]


@pytest.mark.parametrize("a,b,want", [(-7, 2, -3), (7, -2, -3), (-7, -2, 3), (7, 2, 3)])
def test_division_truncates_toward_zero_not_floor(a, b, want):
    """Python's // floors. C truncates. They differ on negatives, and the estate's
    other kernels truncate -- so this must too or receipts disagree across ports."""
    p = prog([["LOADC", 0, 0], ["LOADC", 1, 1], ["DIV", 0, 0, 1], ["HALT"]],
             consts=[a, b])
    assert run(p, [0]) == [want]


def test_mulfx_multiplies_exactly_before_truncating():
    """The fixed-point porting bug in one test: multiply in int64 and shift after,
    and you lose exactly the high bits the shift exists to discard."""
    p = prog([["LOADC", 0, 0], ["LOADC", 1, 1], ["MULFX", 0, 0, 1, 32], ["HALT"]],
             consts=[3 << 32, 5 << 32])
    assert run(p, [0]) == [15 << 32]


# ---------------------------------------------------------------------- traps

@pytest.mark.parametrize("name,code,consts", [
    ("div zero", [["LOADC", 0, 0], ["LOADC", 1, 1], ["DIV", 2, 0, 1], ["HALT"]], [1, 0]),
    ("mod zero", [["LOADC", 0, 0], ["LOADC", 1, 1], ["MOD", 2, 0, 1], ["HALT"]], [1, 0]),
    ("bad shift", [["LOADC", 0, 0], ["LOADC", 1, 1], ["SHL", 2, 0, 1], ["HALT"]], [1, 99]),
    ("oob load", [["LOADC", 1, 0], ["LOAD", 0, 1], ["HALT"]], [999999]),
    ("oob store", [["LOADC", 1, 0], ["STORE", 1, 1], ["HALT"]], [999999]),
])
def test_every_partial_operation_traps_rather_than_raising(name, code, consts):
    with pytest.raises(Trap):
        run(prog(code, consts=consts), [0])


def test_an_infinite_loop_cannot_hang_the_verifier():
    """A receipt you were invited to check must not be able to take your process
    down. Unrestricted jumps are fine BECAUSE the budget is enforced."""
    with pytest.raises(Trap, match="step budget"):
        run(prog([["LOADC", 0, 0], ["JMP", 0]], steps=500), [0])


def test_floats_are_not_representable_anywhere():
    """Not discouraged -- rejected. This is what makes determinism structural: with
    no float in the constant pool there is no libm, and no libm divergence."""
    with pytest.raises(Trap, match="not an integer"):
        validate(prog([["LOADC", 0, 0], ["HALT"]], consts=[0.5]))


def test_booleans_are_not_integers_here():
    """`True` is an int subclass in Python. A port reading the same JSON sees a
    boolean and would disagree, so the reference refuses it outright."""
    with pytest.raises(Trap, match="not an integer"):
        validate(prog([["LOADC", 0, 0], ["HALT"]], consts=[True]))


@pytest.mark.parametrize("mutate,match", [
    (lambda p: p.update(spec="nope"), "unknown program spec"),
    (lambda p: p.update(code=[["NOPE", 0]]), "unknown opcode"),
    (lambda p: p.update(code=[["ADD", 0, 1]]), "takes 3 operand"),
    (lambda p: p.update(code=[["JMP", 999]]), "outside the program"),
    (lambda p: p.update(code=[["LOADC", 99, 0], ["HALT"]]), "out of range"),
    (lambda p: p.update(output={"offset": 0, "length": 0}), "output length"),
    (lambda p: p.update(mem=0), "mem must be"),
    (lambda p: p.update(steps=0), "steps must be"),
])
def test_the_validator_refuses_before_executing_anything(mutate, match):
    p = prog([["LOADC", 0, 0], ["HALT"]])
    mutate(p)
    with pytest.raises(Trap, match=match):
        validate(p)


# ------------------------------------------------------- the worked example

class TestEclReceipt:
    """NO skipif. A skip reads like a pass in every summary line, and these are the
    tests that back the product claim -- so a missing example is a hard failure that
    says what to run, not seven quietly absent assertions."""

    @staticmethod
    def load():
        assert EXAMPLE.is_file(), (
            f"{EXAMPLE.name} is missing -- run `python examples/ecl_portfolio.py`. "
            f"These tests must never be skipped: they are the evidence.")
        return json.loads(EXAMPLE.read_text(encoding="utf-8"))

    def test_a_regulated_number_re_derives_with_no_producer_toolchain(self):
        """The whole point: no compiler checkout, no network, no engine."""
        assert verify(self.load())["verified"]

    def test_a_resealed_forgery_passes_integrity_and_fails_re_derivation(self):
        """Edit an exposure, edit the answer, re-hash so the file is internally
        perfect. A signature cannot catch this. Re-execution can."""
        r = self.load()
        r["params"]["inputs"][3] = 1_000_000_00
        r["output"]["sha256"] = output_sha256([20_000_000])
        r.pop("receipt_sha256")
        r["receipt_sha256"] = canonical_sha256(claim_of(r))
        res = verify(r)
        assert res["integrity"] is True, "the forgery should look internally consistent"
        assert res["reproduced"] is False
        assert res["verified"] is False

    def test_a_hostile_program_is_refused_not_crashed(self):
        r = self.load()
        r["params"]["program"] = prog([["LOADC", 0, 0], ["JMP", 0]], steps=100,
                                      in_len=len(r["params"]["inputs"]), mem=64)
        r["params"]["program_sha256"] = program_sha256(r["params"]["program"])
        res = verify(r)
        assert res["verified"] is False
        assert any("refused" in n for n in res["notes"])

    def test_a_hardcoded_answer_VERIFIES_and_that_is_the_honest_boundary(self):
        """THE LIMIT OF THE REPLAY RUNG, pinned so nobody rediscovers it in a meeting.

        Replay proves the output follows FROM THE PROGRAM. It does not prove the
        program computes what its name claims. A two-instruction constant re-derives
        perfectly and this verifier says VERIFIED -- correctly, because it did.

        The answer is not to weaken the verdict, it is to pin the program: see the
        next test. If this ever starts failing, the boundary moved and the README
        and COMPLIANCE.md both need re-reading.
        """
        r = self.load()
        true_answer = 38_922_496
        r["params"]["program"] = {
            "spec": SPEC, "mem": 64, "steps": 100, "consts": [true_answer],
            "input": {"offset": 16, "length": len(r["params"]["inputs"])},
            "output": {"offset": 0, "length": 1},
            "code": [["LOADC", 0, 0], ["HALT"]],
        }
        r["params"]["program_sha256"] = program_sha256(r["params"]["program"])
        r.pop("receipt_sha256")
        r["receipt_sha256"] = canonical_sha256(claim_of(r))
        assert verify(r)["verified"] is True

    def test_program_pinning_catches_what_re_derivation_cannot(self):
        """A validator approves 27 readable instructions ONCE and records the digest.
        The question becomes 'did this re-derive from the program I approved?'."""
        from obsign_verify.cli import main
        approved = self.load()["params"]["program_sha256"]
        assert main([str(EXAMPLE), "--expect-program", approved, "--quiet"]) == 0
        assert main([str(EXAMPLE), "--expect-program", "0" * 64, "--quiet"]) == 1

    def test_the_program_digest_is_inside_the_claim(self):
        """`params` carries the program, and `params` is hash-covered -- so swapping
        the program breaks integrity, not just the digest field."""
        r = self.load()
        r["params"]["program"]["steps"] += 1
        assert verify(r)["integrity"] is False
