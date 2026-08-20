"""Replay Programs — a deterministic integer machine that travels inside the receipt.

WHY THIS EXISTS

Until now this verifier could re-execute exactly one computation: `tau_field_fixed`.
Every other receipt got `UNVERIFIED (kernel cannot be re-executed here)`. That is fine
for a demonstration and fatal for a product, because the thing anyone actually wants a
receipt for is *their* number, not ours.

The producer already had a bring-your-own-kernel path — a `.cl` source stored in the
receipt params, recompiled at verification time. It does not survive contact with a
stranger: recompiling needs `COHERENCE_LANG_ROOT`, a checkout of a **private**
compiler. A verification you can only perform with the producer's toolchain is the
producer agreeing with itself, which is the exact circularity this product exists to
break.

So the program travels *in the receipt*, in a form this file can execute with nothing
but the standard library.

DETERMINISM IS STRUCTURAL, NOT PROMISED

The usual way to ship "your deterministic computation" is a sandbox plus a rule that
says please do not call the clock. That is a promise, and promises are what receipts
replace. Here, nondeterminism is **not expressible**:

  - There are no floating-point values anywhere. Not in the ops, not in the operands,
    not in the constant pool. The residual libm risk the README admits for
    `tau_field_fixed` does not exist for a replay program, because there is no libm.
  - There is no clock, no randomness, no environment, no I/O, no allocation, no
    indirect call, no host escape. Not restricted — absent from the instruction set.
  - Every operation is TOTAL. Division by zero, an out-of-range shift, an
    out-of-bounds address and an exhausted step budget are all TRAPs, and a trap is a
    refusal with a reason, never an exception that escapes into the caller.

  Arithmetic is **wrapping int64**, stated rather than assumed: `INT64_MAX + 1` is
  `INT64_MIN`. This matches the estate's language semantics, and the one genuinely
  nasty case is pinned by a test: `INT64_MIN / -1` overflows the range and wraps to
  `INT64_MIN` rather than raising.

WHY A STEP BUDGET IS A SECURITY PROPERTY

Jumps are unrestricted, so a program can loop forever. Rather than restricting control
flow into something awkward, execution carries a hard step budget declared in the
program and re-checked here. A receipt handed to you by an adversary must not be able
to hang your verifier: that would be a denial of service delivered through the file
you were invited to check.

WHAT THIS IS NOT

It is not a general language, and that is the point. It is a target — small enough to
re-implement from this docstring in an afternoon, in any language with 64-bit
integers. That is the same bar the rest of this package is held to.
"""

from __future__ import annotations

import hashlib
import json
import struct
from typing import Any

SPEC = "obsign/replay/1"

MASK = (1 << 64) - 1
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


class Trap(Exception):
    """A refusal with a reason. Never allowed to escape `run`."""


def _wrap(v: int) -> int:
    """Wrap an arbitrary Python int into int64. Python ints are unbounded, so this is
    where the machine's actual width is enforced -- forget it and a port to a language
    with native i64 disagrees with this reference on the first overflow."""
    v &= MASK
    return v - (1 << 64) if v >= (1 << 63) else v


def _trunc_div(a: int, b: int) -> int:
    """Truncate toward ZERO, like C and like the estate's other kernels.

    Python's `//` floors, which differs for negative operands: -7 // 2 == -4 while
    truncation gives -3. A port that reaches for the native `/` or for an arithmetic
    shift silently picks a different rounding and drifts from this reference by one
    bit, then by everything.
    """
    if b == 0:
        raise Trap("division by zero")
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


# --------------------------------------------------------------------------- ops
#
# name -> (arity, kind). `kind` decides how the operands are read, which keeps the
# validator and the interpreter reading the same table rather than two lists that
# drift apart.
_ALU2 = "alu2"      # dst, a, b     (registers)
_ALU1 = "alu1"      # dst, a
_JUMP = "jump"      # target
_JCC = "jcc"        # cond, target

OPS: dict[str, tuple[int, str]] = {
    "LOADC": (2, "loadc"),   # dst, const-index
    "MOV":   (2, _ALU1),
    "ADD":   (3, _ALU2), "SUB": (3, _ALU2), "MUL": (3, _ALU2),
    "DIV":   (3, _ALU2), "MOD": (3, _ALU2),
    "MIN":   (3, _ALU2), "MAX": (3, _ALU2),
    "AND":   (3, _ALU2), "OR":  (3, _ALU2), "XOR": (3, _ALU2),
    "SHL":   (3, _ALU2), "SHR": (3, _ALU2),
    "EQ":    (3, _ALU2), "NE":  (3, _ALU2),
    "LT":    (3, _ALU2), "LE":  (3, _ALU2),
    "GT":    (3, _ALU2), "GE":  (3, _ALU2),
    "MULFX": (4, "mulfx"),   # dst, a, b, frac  -- (a*b) >> frac, exact then wrapped
    "SEL":   (4, "sel"),     # dst, cond, a, b
    "NEG":   (2, _ALU1), "ABS": (2, _ALU1), "NOT": (2, _ALU1),
    "LOAD":  (2, _ALU1),     # dst, addr-register
    "STORE": (2, "store"),   # addr-register, src-register
    "JMP":   (1, _JUMP),
    "JMPZ":  (2, _JCC), "JMPNZ": (2, _JCC),
    "HALT":  (0, "halt"),
}

MAX_MEM = 1 << 20          # 1M cells. A receipt is a document, not a workload.
MAX_STEPS = 50_000_000     # hard ceiling; a program may declare less, never more.
MAX_CODE = 1 << 16


def _struct_int(x: Any) -> bool:
    """A STRUCTURAL integer: a memory size, a step budget, a window bound.

    `bool` is excluded first because it SUBCLASSES `int` in Python, so a bare
    `isinstance(x, int)` reads a JSON `true` as 1. js/src/replay.js sees a boolean and
    refuses, so `{"mem": true}` was a program that loaded in the reference and nowhere
    else -- the two verifiers disagreeing about which receipts exist, which is the one
    disagreement this format cannot absorb: a forger hands the receipt to whichever
    implementation loads it. The value-carrying fields (`consts`, operands, inputs)
    have always guarded this; the shape fields did not.
    """
    return not isinstance(x, bool) and isinstance(x, int)


def validate(prog: Any) -> dict:
    """Reject anything malformed BEFORE executing a single instruction.

    Static rejection is what lets `run` be small and total: by the time it starts,
    every opcode is known, every register index is in range, every jump target is a
    real instruction, and every constant is an int64. A validator that ran alongside
    execution would have to be re-checked on every path.
    """
    if not isinstance(prog, dict):
        raise Trap("program must be a JSON object")
    if prog.get("spec") != SPEC:
        raise Trap(f"unknown program spec {prog.get('spec')!r}, expected {SPEC!r}")

    for field in ("mem", "steps", "code", "consts", "input", "output"):
        if field not in prog:
            raise Trap(f"program is missing {field!r}")

    mem = prog["mem"]
    if not _struct_int(mem) or not (1 <= mem <= MAX_MEM):
        raise Trap(f"mem must be an int in 1..{MAX_MEM}")

    steps = prog["steps"]
    if not _struct_int(steps) or not (1 <= steps <= MAX_STEPS):
        raise Trap(f"steps must be an int in 1..{MAX_STEPS}")

    consts = prog["consts"]
    if not isinstance(consts, list) or len(consts) > MAX_MEM:
        raise Trap("consts must be a list")
    for i, c in enumerate(consts):
        # bool is a subclass of int in Python; a JSON `true` must not become a 1 here,
        # because a port reading the same JSON would see a boolean and disagree.
        if isinstance(c, bool) or not isinstance(c, int):
            raise Trap(f"consts[{i}] is not an integer (floats are not representable)")
        if not (INT64_MIN <= c <= INT64_MAX):
            raise Trap(f"consts[{i}] does not fit in int64")

    for name, spec in (("input", prog["input"]), ("output", prog["output"])):
        if (not isinstance(spec, dict) or not _struct_int(spec.get("offset"))
                or not _struct_int(spec.get("length"))):
            raise Trap(f"{name} must be {{offset:int, length:int}}")
        off, ln = spec["offset"], spec["length"]
        if off < 0 or ln < 0 or off + ln > mem:
            raise Trap(f"{name} window {off}..{off + ln} is outside mem ({mem})")
    if prog["output"]["length"] == 0:
        # A program that outputs nothing hashes the empty string, and every such
        # program would share one output digest. That is a collision by construction.
        raise Trap("output length must be > 0")

    code = prog["code"]
    if not isinstance(code, list) or not code or len(code) > MAX_CODE:
        raise Trap(f"code must be a non-empty list of at most {MAX_CODE} instructions")

    for pc, ins in enumerate(code):
        if not isinstance(ins, list) or not ins or not isinstance(ins[0], str):
            raise Trap(f"code[{pc}] is not an instruction")
        op = ins[0]
        if op not in OPS:
            raise Trap(f"code[{pc}] unknown opcode {op!r}")
        arity, kind = OPS[op]
        args = ins[1:]
        if len(args) != arity:
            raise Trap(f"code[{pc}] {op} takes {arity} operand(s), got {len(args)}")
        for a in args:
            if isinstance(a, bool) or not isinstance(a, int):
                raise Trap(f"code[{pc}] {op} has a non-integer operand")

        if kind == "loadc":
            if not (0 <= args[0] < mem):
                raise Trap(f"code[{pc}] {op} dst {args[0]} out of range")
            if not (0 <= args[1] < len(consts)):
                raise Trap(f"code[{pc}] {op} const index {args[1]} out of range")
        elif kind in (_JUMP, _JCC):
            target = args[-1]
            if not (0 <= target < len(code)):
                raise Trap(f"code[{pc}] {op} jumps to {target}, outside the program")
            for a in args[:-1]:
                if not (0 <= a < mem):
                    raise Trap(f"code[{pc}] {op} register {a} out of range")
        elif kind == "mulfx":
            for a in args[:3]:
                if not (0 <= a < mem):
                    raise Trap(f"code[{pc}] {op} register {a} out of range")
            if not (0 <= args[3] <= 63):
                raise Trap(f"code[{pc}] MULFX frac {args[3]} must be 0..63")
        elif kind != "halt":
            for a in args:
                if not (0 <= a < mem):
                    raise Trap(f"code[{pc}] {op} register {a} out of range")

    return prog


def program_sha256(prog: Any) -> str:
    """Hash of the program in canonical JSON.

    The receipt names this digest, and `params` (which carries the program) is inside
    the claim, so the program cannot be swapped after the fact without breaking
    `receipt_sha256`. Belt and braces on purpose: the digest also gives a stranger a
    short string to compare against a published one.
    """
    return hashlib.sha256(
        json.dumps(prog, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False).encode("utf-8")
    ).hexdigest()


def run(prog: dict, inputs: list[int]) -> list[int]:
    """Execute a validated program. Returns the output window.

    Raises `Trap` and nothing else. Any other exception escaping this function is a
    bug in the interpreter, not a property of the receipt -- and the caller treats a
    crash as a verifier defect rather than as a verdict.
    """
    out, _steps = run_counted(prog, inputs)
    return out


def run_counted(prog: dict, inputs: list[int], step_cap: int | None = None):
    """`run`, plus the number of instructions actually executed.

    The count is verifier-internal -- not part of the cross-implementation contract,
    which is (program, inputs) -> output bytes. It exists so a caller can BOUND its
    own work when it re-runs a program many times (input-liveness probing), because
    the declared `steps` budget is only an upper bound: a program may spin close to
    it. `step_cap`, when given, lowers the budget for THIS call only, so a probe can
    refuse to spend more than it planned on any single perturbation; hitting the cap
    raises the ordinary step-budget Trap.

    The value returned by an uncapped call is identical to `run`'s, byte for byte.
    """
    validate(prog)

    mem = [0] * prog["mem"]
    code = prog["code"]
    budget = prog["steps"] if step_cap is None else min(prog["steps"], step_cap)

    in_off, in_len = prog["input"]["offset"], prog["input"]["length"]
    if len(inputs) != in_len:
        raise Trap(f"program expects {in_len} input(s), got {len(inputs)}")
    for i, v in enumerate(inputs):
        if isinstance(v, bool) or not isinstance(v, int):
            raise Trap(f"input[{i}] is not an integer")
        if not (INT64_MIN <= v <= INT64_MAX):
            raise Trap(f"input[{i}] does not fit in int64")
        mem[in_off + i] = v

    pc = 0
    steps = 0
    while True:
        if steps >= budget:
            raise Trap(f"step budget exhausted after {budget} steps")
        steps += 1
        if not (0 <= pc < len(code)):
            raise Trap(f"pc {pc} left the program")

        ins = code[pc]
        op = ins[0]
        pc += 1

        if op == "HALT":
            break
        elif op == "LOADC":
            mem[ins[1]] = prog["consts"][ins[2]]
        elif op == "MOV":
            mem[ins[1]] = mem[ins[2]]
        elif op == "NEG":
            mem[ins[1]] = _wrap(-mem[ins[2]])
        elif op == "ABS":
            mem[ins[1]] = _wrap(abs(mem[ins[2]]))
        elif op == "NOT":
            mem[ins[1]] = _wrap(~mem[ins[2]])
        elif op == "LOAD":
            addr = mem[ins[2]]
            if not (0 <= addr < len(mem)):
                raise Trap(f"LOAD address {addr} out of bounds")
            mem[ins[1]] = mem[addr]
        elif op == "STORE":
            addr = mem[ins[1]]
            if not (0 <= addr < len(mem)):
                raise Trap(f"STORE address {addr} out of bounds")
            mem[addr] = mem[ins[2]]
        elif op == "JMP":
            pc = ins[1]
        elif op == "JMPZ":
            if mem[ins[1]] == 0:
                pc = ins[2]
        elif op == "JMPNZ":
            if mem[ins[1]] != 0:
                pc = ins[2]
        elif op == "SEL":
            mem[ins[1]] = mem[ins[3]] if mem[ins[2]] != 0 else mem[ins[4]]
        elif op == "MULFX":
            # Exact product first, THEN truncate, THEN wrap. Multiplying in int64 and
            # shifting afterwards would lose the high bits that the shift is there to
            # discard -- the classic fixed-point porting bug.
            mem[ins[1]] = _wrap(_trunc_div(mem[ins[2]] * mem[ins[3]], 1 << ins[4]))
        else:
            a, b = mem[ins[2]], mem[ins[3]]
            if op == "ADD":
                v = _wrap(a + b)
            elif op == "SUB":
                v = _wrap(a - b)
            elif op == "MUL":
                v = _wrap(a * b)
            elif op == "DIV":
                v = _wrap(_trunc_div(a, b))
            elif op == "MOD":
                if b == 0:
                    raise Trap("modulo by zero")
                v = _wrap(a - _trunc_div(a, b) * b)
            elif op == "MIN":
                v = a if a < b else b
            elif op == "MAX":
                v = a if a > b else b
            elif op == "AND":
                v = _wrap(a & b)
            elif op == "OR":
                v = _wrap(a | b)
            elif op == "XOR":
                v = _wrap(a ^ b)
            elif op in ("SHL", "SHR"):
                if not (0 <= b <= 63):
                    raise Trap(f"{op} shift amount {b} must be 0..63")
                v = _wrap(a << b) if op == "SHL" else _wrap(a >> b)
            elif op == "EQ":
                v = int(a == b)
            elif op == "NE":
                v = int(a != b)
            elif op == "LT":
                v = int(a < b)
            elif op == "LE":
                v = int(a <= b)
            elif op == "GT":
                v = int(a > b)
            else:  # GE -- the table above is exhaustive, so no other value reaches here
                v = int(a >= b)
            mem[ins[1]] = v

    out_off, out_len = prog["output"]["offset"], prog["output"]["length"]
    return mem[out_off:out_off + out_len], steps


def output_sha256(values: list[int]) -> str:
    """SHA-256 over the output as little-endian int64, matching `array_sha256`.

    Same byte convention as the rest of the spec so one hashing rule covers every
    kernel. Length and dtype ride outside this hash, exactly as they do there.
    """
    return hashlib.sha256(
        b"".join(struct.pack("<q", _wrap(v)) for v in values)
    ).hexdigest()
