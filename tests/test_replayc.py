"""The compiler is trusted only as far as this file proves it.

A compiler that mints receipts is a soundness component: a wrong lowering produces a
receipt that faithfully reproduces the WRONG number, and every downstream check passes.
So correctness here is not asserted, it is triangulated between three things that share
as little as possible:

  * the reference interpreter -- a tree-walk that allocates no cells and sequences no
    instructions, so a codegen bug cannot hide in it;
  * the actual replay VM -- runs the emitted bytecode;
  * a from-scratch arithmetic spec in THIS file -- wrap and truncation written with
    different formulas than the VM uses, so a bug in the machine's own `_wrap` would
    surface as a disagreement rather than be copied into the oracle.

Plus the external anchor no amount of self-consistency can fake: a real, independently
hand-authored receipt's program is regenerated from source and must reproduce its
output hash to the byte.
"""
from __future__ import annotations

import itertools
import json

import pytest

from obsign_verify.replay import INT64_MAX, INT64_MIN, Trap, output_sha256, validate
from obsign_verify.replayc import (CodegenError, ParseError, TypeError, compile_source,
                                    disassemble, interpret_source, ir_sha256, run_source)

# ------------------------------------------------------------------ independent spec
_2_64 = 1 << 64


def spec_wrap(v: int) -> int:
    """int64 wrap, written DIFFERENTLY from the VM's `_wrap` on purpose."""
    v %= _2_64
    return v - _2_64 if v >= (1 << 63) else v


def spec_tdiv(a: int, b: int) -> int:
    # truncate toward zero, via float-free integer identity distinct from the VM's
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def spec_binop(op: str, a: int, b: int) -> int:
    if op == "ADD":
        return spec_wrap(a + b)
    if op == "SUB":
        return spec_wrap(a - b)
    if op == "MUL":
        return spec_wrap(a * b)
    if op == "DIV":
        return spec_wrap(spec_tdiv(a, b))
    if op == "MOD":
        return spec_wrap(a - spec_tdiv(a, b) * b)
    if op == "AND":
        return spec_wrap(a & b)
    if op == "OR":
        return spec_wrap(a | b)
    if op == "XOR":
        return spec_wrap(a ^ b)
    if op == "SHL":
        return spec_wrap(a << b)
    if op == "SHR":
        return spec_wrap(a >> b)
    return {"EQ": a == b, "NE": a != b, "LT": a < b, "LE": a <= b,
            "GT": a > b, "GE": a >= b}[op] and 1 or 0


#: adversarial int64 values: the edges where a wrong wrap or rounding shows up
EDGE = [0, 1, -1, 2, -2, 3, -3, 7, -7, 255, 256,
        INT64_MAX, INT64_MIN, INT64_MAX - 1, INT64_MIN + 1,
        (1 << 62), -(1 << 62), (1 << 32), -(1 << 32),
        6148914691236517205, -6148914691236517205]   # 0x5555... both signs

_ARITH = ["ADD", "SUB", "MUL", "DIV", "MOD", "AND", "OR", "XOR"]
_CMP = ["EQ", "NE", "LT", "LE", "GT", "GE"]
_SRC_OP = {"ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%",
           "AND": "&", "OR": "|", "XOR": "^", "SHL": "<<", "SHR": ">>",
           "EQ": "==", "NE": "!=", "LT": "<", "LE": "<=", "GT": ">", "GE": ">="}


# ------------------------------------------------------------------ gadget proofs
@pytest.mark.parametrize("op", _ARITH + _CMP)
def test_binary_gadget_matches_over_every_edge_pair(op):
    """Compile `x OP y` ONCE, then run it over every adversarial (a,b) pair and require
    VM == interpreter == independent spec. DIV/MOD by zero is skipped here (trap parity
    is its own test)."""
    src = f"input x, y; output x {_SRC_OP[op]} y;"
    prog = compile_source(src)
    validate(prog)   # the compiler's output must satisfy the receipt validator
    for a, b in itertools.product(EDGE, EDGE):
        if op in ("DIV", "MOD") and b == 0:
            continue
        vm = run_source(src, [a, b])[0]
        ref = interpret_source(src, [a, b])[0]
        want = spec_binop(op, a, b)
        assert vm == ref == want, f"{op}({a},{b}): vm={vm} interp={ref} spec={want}"


@pytest.mark.parametrize("op,sym", [("SHL", "<<"), ("SHR", ">>")])
def test_shift_gadget_over_edges_and_valid_amounts(op, sym):
    src = f"input x, y; output x {sym} y;"
    for a in EDGE:
        for b in range(0, 64):   # 0..63 are the machine-legal shift amounts
            vm = run_source(src, [a, b])[0]
            ref = interpret_source(src, [a, b])[0]
            want = spec_binop(op, a, b)
            assert vm == ref == want, f"{op}({a},{b}): vm={vm} interp={ref} spec={want}"


def test_unary_and_builtin_gadgets_over_edges():
    for a in EDGE:
        assert run_source("input x; output 0 - x;", [a])[0] == interpret_source("input x; output 0 - x;", [a])[0] == spec_wrap(-a)
        assert run_source("input x; output ~x;", [a])[0] == spec_wrap(~a)
        assert run_source("input x; output abs(x);", [a])[0] == spec_wrap(abs(a))
        for b in EDGE:
            assert run_source("input x,y; output min(x,y);", [a, b])[0] == (a if a < b else b)
            assert run_source("input x,y; output max(x,y);", [a, b])[0] == (a if a > b else b)
            assert run_source("input c,x,y; output sel(c,x,y);", [a, 10, 20])[0] == (10 if a != 0 else 20)


@pytest.mark.parametrize("frac", [0, 1, 16, 31, 32, 40, 63])
def test_mulfx_gadget_over_edges(frac):
    src = f"input x, y; output mulfx(x, y, {frac});"
    for a, b in itertools.product(EDGE, EDGE):
        vm = run_source(src, [a, b])[0]
        want = spec_wrap(spec_tdiv(a * b, 1 << frac))
        assert vm == want, f"mulfx({a},{b},{frac}): vm={vm} spec={want}"


# ------------------------------------------------------------------ trap parity
@pytest.mark.parametrize("src,inp", [
    ("input a,b; output a / b;", [10, 0]),
    ("input a,b; output a % b;", [10, 0]),
    ("input x; arr a[3]; a[0]=1; output a[x];", [3]),        # index == len
    ("input x; arr a[3]; a[0]=1; output a[x];", [-1]),       # negative index
    ("input x; arr a[3]; a[x]=9; output a[0];", [5]),        # OOB store
    ("input x,y; output x << y;", [1, 64]),                  # shift out of range
])
def test_trap_parity_interp_and_vm_both_refuse(src, inp):
    with pytest.raises(Trap):
        run_source(src, inp)
    with pytest.raises(Trap):
        interpret_source(src, inp)


def test_step_budget_trap_is_reachable():
    # a loop that runs longer than a tiny declared budget must trap on the VM
    src = "#steps 5\ninput n; let i=0; while i < n { i = i + 1; } output i;"
    with pytest.raises(Trap):
        run_source(src, [1000])


# ------------------------------------------------------------------ control flow / arrays
def test_curated_programs_interp_equals_vm():
    cases = [
        ("input a,b; let s=a+b; output s, a*b, a-b;", [[3, 4], [-9, 2], [INT64_MAX, 1]]),
        ("input x; let r=0; if x < 0 { r = 0-x; } else { r = x; } output r;", [[-5], [5], [0]]),
        ("#steps 100000\ninput n; let acc=0; let i=1; while i<=n { acc=acc+i; i=i+1; } output acc;",
         [[0], [1], [10], [1000]]),
        ("#steps 100000\ninput xs[5]; let s=0; let i=0; while i<5 { s=s+xs[i]; i=i+1; } output s;",
         [[1, 2, 3, 4, 5], [-1, -1, -1, -1, -1]]),
        ("#steps 100000\ninput n; let f=1; let i=2; while i<=n { f=f*i; i=i+1; } output f;",
         [[1], [5], [20]]),
    ]
    for src, inputs in cases:
        for inp in inputs:
            assert run_source(src, inp) == interpret_source(src, inp), (src, inp)


# ------------------------------------------------------------------ the external anchor
CONF = "src/obsign_verify/data/conformance/producer_signed_replay.json"
CECL_SRC = """#steps 100000
input v[13];
let n = v[0]; let acc = 0; let i = 0;
while i < n {
  let base = i*3 + 1;
  let el = mulfx(v[base], v[base+1], 32);
  acc = acc + mulfx(el, v[base+2], 32);
  i = i + 1;
}
output acc;
"""


def test_cecl_receipt_regenerates_bit_identically():
    """The claim no self-consistency can fake: a real, hand-authored IFRS-9/CECL
    receipt's OUTPUT hash is reproduced from source through this compiler."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    receipt = json.loads((root / CONF).read_text())
    inputs = receipt["params"]["inputs"]
    out_vm = run_source(CECL_SRC, inputs)
    out_ref = interpret_source(CECL_SRC, inputs)
    assert out_vm == out_ref
    assert output_sha256(out_vm) == receipt["output"]["sha256"], \
        "compiled CECL output does not match the hand-authored receipt"


# ------------------------------------------------------------------ hygiene
def test_compile_is_deterministic():
    a = compile_source(CECL_SRC)
    b = compile_source(CECL_SRC)
    assert a == b and ir_sha256(a) == ir_sha256(b)


def test_disassemble_covers_every_instruction():
    prog = compile_source(CECL_SRC)
    text = disassemble(prog)
    assert text.count("\n") >= len(prog["code"])
    assert "MULFX" in text and "LOAD" in text


@pytest.mark.parametrize("bad", [
    "output 1;",                                   # ok? no -- needs to parse; this is fine actually
])
def test_smoke_minimal_program(bad):
    # a program with a constant output and no inputs is legal and reproducible
    assert run_source("output 42;", []) == [42]


@pytest.mark.parametrize("src", [
    "input a; output a",                            # missing ;
    "input a; output 1.5;",                         # float literal
    "let x = ;",                                    # empty expr
    "input a; output )(;",                          # garbage
])
def test_syntax_errors_are_parse_errors(src):
    with pytest.raises(ParseError):
        compile_source(src)


@pytest.mark.parametrize("src", [
    "output x;",                                    # undefined name
    "x = 1; output x;",                             # assign to undefined (no prior let)
    "input y; output mulfx(1, 2, y);",              # mulfx frac not a literal
    "output min(1);",                               # arity
    "arr a[0]; output 1;",                          # empty array
    "input a; output a[0];",                        # scalar indexed as array
])
def test_semantic_errors_are_type_errors(src):
    with pytest.raises((TypeError, ParseError)):
        compile_source(src)


def test_reassigning_an_input_is_allowed():
    # inputs are ordinary assignable scalars, like reassignable parameters
    assert run_source("input a; a = a + 1; output a;", [41]) == [42]


def test_no_program_without_output_is_accepted():
    with pytest.raises(ParseError):
        compile_source("input a; let x = a;")


def test_over_large_literal_is_rejected():
    with pytest.raises(TypeError):
        compile_source(f"output {1 << 63};")        # INT64_MAX+1
