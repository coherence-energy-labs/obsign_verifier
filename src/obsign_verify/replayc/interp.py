"""The reference interpreter for RL -- the oracle codegen is proved against.

This walks the AST directly: expressions are evaluated as a tree, control flow as
ordinary Python recursion/loops. It allocates no memory cells, sequences no
instructions and back-patches no jumps -- none of the machinery codegen.py uses. That
is the entire point. `run(compile(src)) == interpret(src)` can only fail if codegen's
lowering is wrong, because the two share nothing but the int64 number model (imported
from the VM, which is itself the tested spec of that model) and the meaning of each
operator name.

It carries the SAME totality as the machine: division by zero, a bad shift, an
out-of-bounds array access and an exceeded step budget are Traps here exactly as they
are there, so a program that traps under the VM also traps here -- the oracle agrees on
refusals, not only on numbers.
"""
from __future__ import annotations

from ..replay import INT64_MAX, INT64_MIN, Trap, _trunc_div, _wrap
from . import nodes


class InterpError(Trap):
    """A trap raised while interpreting. Subclasses Trap so callers that catch the
    machine's refusals catch the oracle's identically."""


def _as_bool(v: int) -> bool:
    return v != 0


class _Frame:
    """Variable and array state for one interpretation. Arrays live in a flat cell
    list addressed exactly as the compiled program addresses them, but that layout is
    an implementation detail the interpreter never exposes -- it is reproduced here
    only so an out-of-bounds `arr[i]` traps at the same boundary the machine would."""

    def __init__(self) -> None:
        self.vars: dict[str, int] = {}
        self.arrays: dict[str, list[int]] = {}


class Interpreter:
    def __init__(self, prog: nodes.Program, step_budget: int) -> None:
        self.prog = prog
        self.budget = step_budget
        self.steps = 0
        self.f = _Frame()

    # ---- driver ----
    def run(self, inputs: list[int]) -> list[int]:
        ia = self.prog.input_array
        expected = ia.length if ia is not None else len(self.prog.inputs)
        if len(inputs) != expected:
            raise InterpError(f"program expects {expected} input(s), got {len(inputs)}")
        for i, v in enumerate(inputs):
            if isinstance(v, bool) or not isinstance(v, int):
                raise InterpError(f"input[{i}] is not an integer")
            if not (INT64_MIN <= v <= INT64_MAX):
                raise InterpError(f"input[{i}] does not fit in int64")
        if ia is not None:
            self.f.arrays[ia.name] = list(inputs)
        else:
            for name, v in zip(self.prog.inputs, inputs):
                self.f.vars[name] = v
        for arr in self.prog.arrays:
            self.f.arrays[arr.name] = [0] * arr.length
        self._exec_block(self.prog.body)
        return [self._eval(e) for e in self.prog.outputs]

    # ---- a step counter that mirrors the machine's budget as a refusal, not a hang ----
    def _tick(self) -> None:
        # The interpreter is a tree-walk, so its "steps" are not the machine's
        # instruction count; this bound exists only so an infinite source `while`
        # refuses here too instead of hanging the oracle. It is intentionally
        # generous and is NOT part of any cross-checked contract.
        self.steps += 1
        if self.steps > self.budget:
            raise InterpError(f"interpreter step budget exhausted after {self.budget}")

    # ---- statements ----
    def _exec_block(self, stmts: tuple[nodes.Stmt, ...]) -> None:
        for s in stmts:
            self._exec(s)

    def _exec(self, s: nodes.Stmt) -> None:
        self._tick()
        if isinstance(s, nodes.Let):
            self.f.vars[s.name] = self._eval(s.expr)
        elif isinstance(s, nodes.Assign):
            self.f.vars[s.name] = self._eval(s.expr)
        elif isinstance(s, nodes.StoreElem):
            arr = self.f.arrays[s.array]
            idx = self._eval(s.index)
            if not (0 <= idx < len(arr)):
                raise InterpError(f"store to {s.array}[{idx}] out of bounds (len {len(arr)})")
            arr[idx] = self._eval(s.value)
        elif isinstance(s, nodes.If):
            if _as_bool(self._eval(s.cond)):
                self._exec_block(s.then)
            else:
                self._exec_block(s.els)
        elif isinstance(s, nodes.While):
            while _as_bool(self._eval(s.cond)):
                self._tick()
                self._exec_block(s.body)
        else:  # pragma: no cover - the parser produces no other statement
            raise InterpError(f"unknown statement {type(s).__name__}")

    # ---- expressions ----
    def _eval(self, e: nodes.Expr) -> int:
        if isinstance(e, nodes.IntLit):
            return e.value
        if isinstance(e, nodes.Name):
            # A scalar reads 0 until it is assigned on the executed path. This MODELS
            # THE MACHINE, whose memory starts zeroed and whose cell for this variable
            # is 0 until a MOV writes it -- so a variable `let` inside a branch that did
            # not run reads 0 here exactly as it does there. The typer has already
            # rejected any name that is never declared at all; this default is only for
            # a declared name not yet assigned on this path.
            return self.f.vars.get(e.ident, 0)
        if isinstance(e, nodes.Index):
            arr = self.f.arrays[e.array]
            idx = self._eval(e.index)
            if not (0 <= idx < len(arr)):
                raise InterpError(f"read of {e.array}[{idx}] out of bounds (len {len(arr)})")
            return arr[idx]
        if isinstance(e, nodes.Unary):
            x = self._eval(e.operand)
            if e.op == "neg":
                return _wrap(-x)
            if e.op == "not":
                return _wrap(~x)
            raise InterpError(f"unknown unary {e.op!r}")  # pragma: no cover
        if isinstance(e, nodes.Binary):
            return self._binary(e.op, self._eval(e.left), self._eval(e.right))
        if isinstance(e, nodes.Call):
            return self._call(e)
        raise InterpError(f"unknown expression {type(e).__name__}")  # pragma: no cover

    def _binary(self, op: str, a: int, b: int) -> int:
        # Each arm mirrors the machine op of the same name. The differential test is
        # meaningful precisely because these are written independently of run().
        if op == "ADD":
            return _wrap(a + b)
        if op == "SUB":
            return _wrap(a - b)
        if op == "MUL":
            return _wrap(a * b)
        if op == "DIV":
            return _wrap(_trunc_div(a, b))
        if op == "MOD":
            if b == 0:
                raise InterpError("modulo by zero")
            return _wrap(a - _trunc_div(a, b) * b)
        if op == "AND":
            return _wrap(a & b)
        if op == "OR":
            return _wrap(a | b)
        if op == "XOR":
            return _wrap(a ^ b)
        if op in ("SHL", "SHR"):
            if not (0 <= b <= 63):
                raise InterpError(f"{op} shift amount {b} must be 0..63")
            return _wrap(a << b) if op == "SHL" else _wrap(a >> b)
        if op == "EQ":
            return int(a == b)
        if op == "NE":
            return int(a != b)
        if op == "LT":
            return int(a < b)
        if op == "LE":
            return int(a <= b)
        if op == "GT":
            return int(a > b)
        if op == "GE":
            return int(a >= b)
        raise InterpError(f"unknown binary {op!r}")  # pragma: no cover

    def _call(self, e: nodes.Call) -> int:
        a = [self._eval(x) for x in e.args]
        if e.fn == "min":
            return a[0] if a[0] < a[1] else a[1]
        if e.fn == "max":
            return a[0] if a[0] > a[1] else a[1]
        if e.fn == "abs":
            return _wrap(abs(a[0]))
        if e.fn == "sel":
            return a[1] if a[0] != 0 else a[2]
        if e.fn == "mulfx":
            # mulfx(x, y, F): exact product, truncate toward zero by 2**F, then wrap --
            # byte-identical to the MULFX opcode. F is a compile-time constant, checked
            # by the typer to be 0..63; the interpreter trusts that check.
            frac = a[2]
            return _wrap(_trunc_div(a[0] * a[1], 1 << frac))
        raise InterpError(f"unknown builtin {e.fn!r}")  # pragma: no cover


def interpret(prog: nodes.Program, inputs: list[int], step_budget: int = 50_000_000) -> list[int]:
    return Interpreter(prog, step_budget).run(list(inputs))
