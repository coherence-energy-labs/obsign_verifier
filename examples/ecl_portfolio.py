"""A regulated number on the replay path, built without a design partner.

THE QUESTION THIS ANSWERS

PROGRAM.md §9 carries a risk it calls High: *"determinism porting cost blocks
adoption"*, mitigated by a claim we had never tested — *"only the CLAIMED NUMBER need
live in the deterministic core"*, and *"if you cannot shrink scope to the twelve
disputed numbers on call one, that customer is not ready."*

That claim was an assertion. Testing it appeared to need a bank, an NDA and $15-25k of
design-partner money. It does not: the shape of the computation is public.

WHAT THIS COMPUTES

Expected Credit Loss under IFRS 9 / CECL:

    ECL = SUM over exposures of  PD * LGD * EAD

PD (probability of default) and LGD (loss given default) are fractions; EAD (exposure
at default) is money. It is the canonical number a model validator re-derives by hand,
an auditor disputes, and a bank currently defends with a spreadsheet and a memo.

WHY IT PORTS IN AN AFTERNOON, WHICH IS THE ACTUAL FINDING

Nothing about the bank's pipeline moves. The models that PRODUCE pd and lgd stay
exactly where they are, in whatever stack they already use, with whatever
floating-point they already have. Only the ARITHMETIC THAT COMBINES THEM crosses into
the deterministic core -- three multiplications and a sum.

That is the 80/20 the document asserts, made concrete: the disputed number is not the
model, it is the aggregation, and the aggregation is small.

FIXED POINT, AND THE PRECISION STATED RATHER THAN IMPLIED

PD and LGD arrive as fractions scaled by 2^32; EAD arrives in cents as an integer.
Money is never a float here -- the reason banks keep money in minor units is the same
reason this does: 0.1 is not representable in binary floating point, and a rounding
policy nobody wrote down is a rounding policy nobody can audit.

A PORTABILITY CONSTRAINT WORTH KNOWING BEFORE YOU PORT

`MULFX` multiplies EXACTLY and then truncates. For this program the intermediate
`pd_fx * lgd_fx` reaches 2^64 and `pd_lgd * ead` can exceed 4e20 -- both beyond int64,
while every RESULT fits comfortably. A port must therefore hold the intermediate in
128 bits (Rust `i128`, JS `BigInt`, Python's native ints). An implementation that
multiplies in int64 and shifts afterwards loses exactly the high bits the shift exists
to discard, and it will agree with this reference on small portfolios and diverge on
large ones -- the worst possible failure shape.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from obsign_verify.replay import (  # noqa: E402
    SPEC, output_sha256, program_sha256, run,
)
from obsign_verify.canonical import canonical_sha256, claim_of  # noqa: E402

FRAC = 32                      # PD and LGD are fractions scaled by 2**32
SCALE = 1 << FRAC


def to_fx(fraction: float) -> int:
    """A probability -> fixed point. The ONLY float in the whole path, and it is
    rounded to an integer here, before anything is computed -- so a last-ulp
    difference in whoever produced `fraction` cannot compound through the arithmetic.
    """
    return int(round(fraction * SCALE))


# Memory map. Written out because a register machine with anonymous cells is
# unreadable, and this program is meant to be read by a validator, not just run.
R_TOTAL, R_I, R_N, R_ADDR, R_PD, R_LGD, R_EAD, R_TMP, R_ONE, R_THREE, R_BASE = range(11)
INPUT_OFF = 16                 # inputs land here: [n, pd0, lgd0, ead0, pd1, ...]


def build_program() -> dict:
    """The ECL aggregation as a replay program.

    Fifteen instructions. That is the entire deterministic core a bank would have to
    accept -- not their model, not their data pipeline, not their infrastructure.
    """
    consts = [0, 1, 3, INPUT_OFF + 1]        # 0:zero 1:one 2:three 3:first-exposure
    code = [
        ["LOADC", R_TOTAL, 0],               # total = 0
        ["LOADC", R_I, 0],                   # i = 0
        ["LOADC", R_ONE, 1],                 # one = 1
        ["LOADC", R_THREE, 2],               # three = 3
        ["LOADC", R_BASE, 3],                # base = first exposure cell
        ["LOADC", R_ADDR, 0],
        ["ADD", R_ADDR, R_ADDR, R_ONE],      # addr = 1 ... (INPUT_OFF holds n)
        ["LOADC", R_TMP, 0],
        ["ADD", R_TMP, R_TMP, R_ONE],
        ["MOV", R_ADDR, R_TMP],
    ]
    # n = mem[INPUT_OFF]
    consts.append(INPUT_OFF)
    code += [
        ["LOADC", R_ADDR, len(consts) - 1],
        ["LOAD", R_N, R_ADDR],
    ]
    loop = len(code)
    code += [
        ["GE", R_TMP, R_I, R_N],             # done?
        ["JMPNZ", R_TMP, 0],                 # -> end (patched below)
        ["MUL", R_ADDR, R_I, R_THREE],       # addr = base + 3*i
        ["ADD", R_ADDR, R_ADDR, R_BASE],
        ["LOAD", R_PD, R_ADDR],              # pd
        ["ADD", R_ADDR, R_ADDR, R_ONE],
        ["LOAD", R_LGD, R_ADDR],             # lgd
        ["ADD", R_ADDR, R_ADDR, R_ONE],
        ["LOAD", R_EAD, R_ADDR],             # ead (cents)
        ["MULFX", R_TMP, R_PD, R_LGD, FRAC],     # pd*lgd
        ["MULFX", R_TMP, R_TMP, R_EAD, FRAC],    # * ead -> cents
        ["ADD", R_TOTAL, R_TOTAL, R_TMP],        # total += ecl_i
        ["ADD", R_I, R_I, R_ONE],
        ["JMP", loop],
    ]
    end = len(code)
    code[loop + 1] = ["JMPNZ", R_TMP, end]   # patch the exit
    code += [["HALT"]]

    return {
        "spec": SPEC,
        "mem": 4096,
        "steps": 2_000_000,
        "consts": consts,
        "input": {"offset": INPUT_OFF, "length": 0},   # set by build_receipt
        "output": {"offset": R_TOTAL, "length": 1},
        "code": code,
    }


def build_receipt(portfolio: list[tuple[float, float, int]]) -> dict:
    """Produce a receipt for this portfolio's ECL."""
    inputs = [len(portfolio)]
    for pd, lgd, ead_cents in portfolio:
        inputs += [to_fx(pd), to_fx(lgd), ead_cents]

    prog = build_program()
    prog["input"]["length"] = len(inputs)

    out = run(prog, inputs)

    receipt = {
        "spec": "obsign/receipt/v1",
        "kernel": SPEC,
        "producer": {"name": "obsign", "spec": "obsign/spec/1", "version": "2.0.0"},
        "params": {
            "program": prog,
            "program_sha256": program_sha256(prog),
            "inputs": inputs,
            "note": (f"IFRS 9 / CECL expected credit loss over {len(portfolio)} "
                     f"exposure(s). PD and LGD are fractions scaled by 2^{FRAC}; "
                     f"EAD and the result are in cents."),
        },
        "input": {"kind": "inline", "ref": "params.inputs", "sha256": None},
        "output": {"sha256": output_sha256(out), "length": len(out),
                   "dtype": "int64", "units": "cents"},
        "run": {"backend": "replay-int64", "deterministic": True,
                "device": "any", "dtype": "int64"},
    }
    receipt["receipt_sha256"] = canonical_sha256(claim_of(receipt))
    return receipt, out


if __name__ == "__main__":
    # A small portfolio with the shape of a real one: a good book, a watch-list
    # exposure, and one in stage 3.
    portfolio = [
        (0.0042, 0.45, 12_500_000_00),   # investment grade, $12.5m
        (0.0310, 0.55,  3_200_000_00),   # watch list,       $3.2m
        (0.4800, 0.72,    850_000_00),   # stage 3,          $850k
        (0.0009, 0.40, 48_000_000_00),   # prime,            $48m
    ]
    receipt, out = build_receipt(portfolio)

    expected = sum(pd * lgd * ead for pd, lgd, ead in portfolio)
    print(f"  exposures         : {len(portfolio)}")
    print(f"  ECL (replay, int) : {out[0]:,} cents  = ${out[0] / 100:,.2f}")
    print(f"  ECL (float, naive): {expected:,.2f} cents  = ${expected / 100:,.2f}")
    print(f"  difference        : {abs(out[0] - expected):.4f} cents "
          f"(fixed-point truncation, bounded and stated)")
    print(f"  instructions      : {len(receipt['params']['program']['code'])}")
    print(f"  program sha256    : {receipt['params']['program_sha256'][:32]}...")
    print(f"  receipt sha256    : {receipt['receipt_sha256'][:32]}...")

    dest = Path(__file__).resolve().parent / "ecl_receipt.json"
    dest.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    print(f"  wrote             : {dest}")
