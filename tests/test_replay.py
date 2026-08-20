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


#: The same program with ONE structural scalar written as a JSON boolean. Each stays
#: a program that would validate if that field were the integer `bool` collapses to,
#: so nothing but the type rule decides the outcome.
_STRUCTURAL_BOOL = [
    ("mem", {"mem": True, "input": {"offset": 0, "length": 1},
             "output": {"offset": 0, "length": 1}}),
    ("steps", {"steps": True}),
    ("input.offset", {"input": {"offset": True, "length": 1}}),
    ("input.length", {"input": {"offset": 2, "length": True}}),
    ("output.offset", {"output": {"offset": True, "length": 1}}),
    ("output.length", {"output": {"offset": 0, "length": True}}),
]


@pytest.mark.parametrize("field, over", _STRUCTURAL_BOOL,
                         ids=[f for f, _ in _STRUCTURAL_BOOL])
def test_booleans_are_not_integers_in_the_structural_fields_either(field, over):
    """The constant pool was guarded against `bool`; the machine's SHAPE was not.

    `mem`, `steps` and the two window bounds were checked with a bare
    `isinstance(x, int)`, which is True for `True`, so `{"mem": true}` loaded here as
    `mem = 1`. js/src/replay.js sees a JSON boolean and refuses, so these programs
    existed in one implementation and not the other -- and a receipt only half the
    verifiers will load is a receipt whose verdict depends on who you hand it to.
    """
    p = {"spec": SPEC, "mem": 4, "steps": 8, "consts": [0],
         "input": {"offset": 2, "length": 1}, "output": {"offset": 0, "length": 1},
         "code": [["LOADC", 0, 0], ["HALT"]]}
    p.update(over)
    with pytest.raises(Trap):
        validate(p)


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

    def test_a_hardcoded_answer_is_REFUSED_because_it_ignores_its_inputs(self):
        """THE REPLAY-RUNG BOUNDARY, and where it now sits.

        This test used to assert the OPPOSITE -- that a two-instruction constant
        re-derives perfectly and is therefore VERIFIED, "the honest boundary", with
        a standing note: "if this ever starts failing, the boundary moved and the
        README and COMPLIANCE.md both need re-reading." It moved. It was moved on
        purpose, and the docs were re-read.

        Re-derivation proves the output follows from the program AND ITS INPUTS. A
        constant follows from neither -- perturb every input and the answer never
        changes -- so it proves nothing about the inputs it names, and the verifier
        now refuses it on input-liveness. `--expect-program` was the old mitigation;
        it never helped here, because a constant has a perfectly pinnable digest.
        Making the output actually depend on the inputs is the one thing a pin
        cannot fake, and it is now checked.
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
        res = verify(r)
        assert res["verified"] is False
        assert res["input_liveness"] == "dead"
        assert any("does not depend on ANY declared input" in n for n in res["notes"])

    def test_a_genuine_computation_reads_live_and_still_verifies(self):
        """The counterweight, so liveness can never be 'fixed' by refusing everything:
        the shipped ECL program depends on all thirteen of its inputs, reads `live`,
        and verifies unchanged."""
        res = verify(self.load())
        assert res["verified"] is True
        assert res["input_liveness"] == "live"

    def test_liveness_probing_cannot_be_turned_into_a_denial_of_service(self):
        """A program that IGNORES its inputs but spins is still refused fast: the
        probe caps each perturbation run and the total, so a hostile expensive
        constant cannot make liveness cost more than a small multiple of the base."""
        import time
        r = self.load()
        # a program that does real looping work, then returns a constant
        r["params"]["program"] = {
            "spec": SPEC, "mem": 64, "steps": 50_000_000, "consts": [38_922_496, 1, 0],
            "input": {"offset": 16, "length": len(r["params"]["inputs"])},
            "output": {"offset": 0, "length": 1},
            "code": [["LOADC", 0, 1], ["LOADC", 1, 2], ["MUL", 0, 0, 0],
                     ["LOADC", 2, 0], ["MOV", 3, 0], ["HALT"]],
        }
        r["params"]["program_sha256"] = program_sha256(r["params"]["program"])
        r.pop("receipt_sha256")
        r["receipt_sha256"] = canonical_sha256(claim_of(r))
        t = time.perf_counter()
        res = verify(r)
        assert time.perf_counter() - t < 5.0, "liveness probe was not bounded"
        assert res["verified"] is False
        assert res["input_liveness"] == "dead"

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
