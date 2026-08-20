"""Lower a checked AST to an `obsign/replay/1` program.

The whole compiler earns trust from one property: for every input on which the
reference interpreter produces a number, the program emitted here runs -- on the
Python VM and the JS VM alike -- to the SAME number; and on every input where the
interpreter refuses (a trap), the program traps too. codegen.py is the only place that
can break that, so it is kept boring: a tree-walk that emits one gadget per node, a
bump allocator for memory, and a single back-patch pass for jumps.

MEMORY MAP (all disjoint, low to high)
  [0, n_in)                    input window   -- the VM writes inputs here
  [n_in, n_in + n_out)         output window  -- the VM reads the result here
  scalars                      one cell per named variable (inputs excepted)
  arrays                       a contiguous block per `arr`
  temps                        expression scratch, reset per top-level statement

THE ONE SEMANTIC TRAP CODEGEN MUST NOT DROP
  `arr[i]` for i outside [0, len) traps in the interpreter. The machine's LOAD/STORE
  only trap outside ALL of memory, so a raw `base + i` could land on a NEIGHBOURING
  cell and return a wrong number with no error -- exactly the silent-wrong-answer a
  receipt must never carry. So every indexed access first forces a trap when i is out
  of range (a division by zero, the machine's cheapest guaranteed refusal), and only
  then computes the address. The compiled program refuses precisely where the
  interpreter does.
"""
from __future__ import annotations

from ..replay import MAX_MEM, MAX_STEPS, SPEC, validate
from . import nodes


class CodegenError(Exception):
    pass


class _Label:
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name


class Codegen:
    def __init__(self, prog: nodes.Program):
        self.prog = prog
        self.code: list[list] = []
        self.consts: list[int] = []
        self._const_ix: dict[int, int] = {}
        self.scalar: dict[str, int] = {}
        self.array: dict[str, tuple[int, int]] = {}   # name -> (base, length)
        self._labels: dict[int, int] = {}             # id(label) -> code index
        self._n_in = prog.input_array.length if prog.input_array is not None else len(prog.inputs)
        self._n_out = len(prog.outputs)
        self._next = 0            # bump allocator high-water
        self._temp_ptr = 0        # reset to _temp_base per statement
        self._temp_base = 0
        self._temp_hi = 0

    # ---- memory allocation ----
    def _alloc(self, k: int = 1) -> int:
        c = self._next
        self._next += k
        if self._next > MAX_MEM:
            raise CodegenError(f"program needs {self._next} cells, over the {MAX_MEM} limit")
        return c

    def _temp(self) -> int:
        c = self._temp_ptr
        self._temp_ptr += 1
        self._temp_hi = max(self._temp_hi, self._temp_ptr)
        return c

    def _reset_temps(self) -> None:
        self._temp_ptr = self._temp_base

    # ---- constants ----
    def _const(self, value: int) -> int:
        if value not in self._const_ix:
            self._const_ix[value] = len(self.consts)
            self.consts.append(value)
        return self._const_ix[value]

    def _load_const(self, value: int) -> int:
        t = self._temp()
        self.code.append(["LOADC", t, self._const(value)])
        return t

    # ---- labels / emit ----
    def _label(self, name: str) -> _Label:
        return _Label(name)

    def _place(self, lbl: _Label) -> None:
        self._labels[id(lbl)] = len(self.code)

    def _emit(self, *ins) -> None:
        self.code.append(list(ins))

    # ---- driver ----
    def generate(self) -> dict:
        # 1. fixed windows
        self._alloc(self._n_in)                       # inputs at [0, n_in)
        out_off = self._alloc(self._n_out)            # outputs next
        # 2. scalars: every input name maps to its input cell; every other name a fresh cell
        if self.prog.input_array is not None:
            # the input window IS this array, based at 0 -- the VM fills it directly
            self.array[self.prog.input_array.name] = (0, self.prog.input_array.length)
        for i, name in enumerate(self.prog.inputs):
            self.scalar[name] = i
        for name in _scalar_names(self.prog):
            if name not in self.scalar:
                self.scalar[name] = self._alloc()
        # 3. arrays
        for arr in self.prog.arrays:
            self.array[arr.name] = (self._alloc(arr.length), arr.length)
        # 4. temps start after everything permanent
        self._temp_base = self._next
        self._temp_ptr = self._temp_base
        self._temp_hi = self._temp_base

        # 5. body
        for s in self.prog.body:
            self._reset_temps()
            self._stmt(s, _LabelCtx())
        # 6. outputs into the output window
        for i, e in enumerate(self.prog.outputs):
            self._reset_temps()
            c = self._expr(e)
            self._emit("MOV", out_off + i, c)
        self._emit("HALT")

        # 7. resolve labels -> instruction indices
        self._resolve_labels()

        mem = max(self._temp_hi, self._next, self._n_in + self._n_out, 1)
        if mem > MAX_MEM:
            raise CodegenError(f"program needs {mem} cells, over the {MAX_MEM} limit")

        steps = self.prog.steps if self.prog.steps is not None else MAX_STEPS
        if not (1 <= steps <= MAX_STEPS):
            raise CodegenError(f"#steps {steps} must be in 1..{MAX_STEPS}")

        program = {
            "spec": SPEC,
            "mem": mem,
            "steps": steps,
            "consts": list(self.consts),
            "input": {"offset": 0, "length": self._n_in},
            "output": {"offset": out_off, "length": self._n_out},
            "code": self.code,
        }
        # The compiler's output must satisfy the SAME validator a stranger's receipt
        # does. If codegen ever emits something validate() rejects, that is a compiler
        # bug and it surfaces here, at build time, not at verification time.
        validate(program)
        return program

    def _resolve_labels(self) -> None:
        for ins in self.code:
            op = ins[0]
            if op in ("JMP", "JMPZ", "JMPNZ"):
                tgt = ins[-1]
                if isinstance(tgt, _Label):
                    if id(tgt) not in self._labels:
                        raise CodegenError(f"unresolved label {tgt.name!r}")  # pragma: no cover
                    ins[-1] = self._labels[id(tgt)]

    # ---- statements ----
    def _stmt(self, s: nodes.Stmt, ctx: "_LabelCtx") -> None:
        if isinstance(s, nodes.Let):
            c = self._expr(s.expr)
            self._emit("MOV", self.scalar[s.name], c)
        elif isinstance(s, nodes.Assign):
            c = self._expr(s.expr)
            self._emit("MOV", self.scalar[s.name], c)
        elif isinstance(s, nodes.StoreElem):
            base, length = self.array[s.array]
            idx = self._expr(s.index)
            self._bounds_trap(idx, length)
            val = self._expr(s.value)
            addr = self._add_const(idx, base)
            self._emit("STORE", addr, val)
        elif isinstance(s, nodes.If):
            cond = self._expr(s.cond)
            else_l = self._label("else")
            end_l = self._label("end")
            self._emit("JMPZ", cond, else_l)
            for st in s.then:
                self._stmt(st, ctx)
            self._emit("JMP", end_l)
            self._place(else_l)
            for st in s.els:
                self._stmt(st, ctx)
            self._place(end_l)
        elif isinstance(s, nodes.While):
            top = self._label("while")
            end = self._label("endwhile")
            self._place(top)
            self._reset_temps()                 # cond scratch is fresh each iteration
            cond = self._expr(s.cond)
            self._emit("JMPZ", cond, end)
            for st in s.body:
                self._stmt(st, ctx)
            self._emit("JMP", top)
            self._place(end)
        else:  # pragma: no cover
            raise CodegenError(f"unknown statement {type(s).__name__}")

    # ---- expressions: each returns the cell holding the value ----
    def _expr(self, e: nodes.Expr) -> int:
        if isinstance(e, nodes.IntLit):
            return self._load_const(e.value)
        if isinstance(e, nodes.Name):
            return self.scalar[e.ident]             # read a variable in place; never written
        if isinstance(e, nodes.Index):
            base, length = self.array[e.array]
            idx = self._expr(e.index)
            self._bounds_trap(idx, length)
            addr = self._add_const(idx, base)
            dst = self._temp()
            self._emit("LOAD", dst, addr)
            return dst
        if isinstance(e, nodes.Unary):
            x = self._expr(e.operand)
            dst = self._temp()
            self._emit("NEG" if e.op == "neg" else "NOT", dst, x)
            return dst
        if isinstance(e, nodes.Binary):
            a = self._expr(e.left)
            b = self._expr(e.right)
            dst = self._temp()
            self._emit(e.op, dst, a, b)
            return dst
        if isinstance(e, nodes.Call):
            return self._call(e)
        raise CodegenError(f"unknown expression {type(e).__name__}")  # pragma: no cover

    def _call(self, e: nodes.Call) -> int:
        if e.fn in ("min", "max"):
            a = self._expr(e.args[0])
            b = self._expr(e.args[1])
            dst = self._temp()
            self._emit("MIN" if e.fn == "min" else "MAX", dst, a, b)
            return dst
        if e.fn == "abs":
            x = self._expr(e.args[0])
            dst = self._temp()
            self._emit("ABS", dst, x)
            return dst
        if e.fn == "sel":
            cond = self._expr(e.args[0])
            a = self._expr(e.args[1])
            b = self._expr(e.args[2])
            dst = self._temp()
            self._emit("SEL", dst, cond, a, b)
            return dst
        if e.fn == "mulfx":
            a = self._expr(e.args[0])
            b = self._expr(e.args[1])
            frac = e.args[2].value                   # typer guarantees a literal 0..63
            dst = self._temp()
            self._emit("MULFX", dst, a, b, frac)
            return dst
        raise CodegenError(f"unknown builtin {e.fn!r}")  # pragma: no cover

    # ---- helpers ----
    def _add_const(self, cell: int, k: int) -> int:
        """A cell holding mem[cell] + k, k a compile-time constant."""
        if k == 0:
            return cell
        kc = self._load_const(k)
        dst = self._temp()
        self._emit("ADD", dst, cell, kc)
        return dst

    def _bounds_trap(self, idx_cell: int, length: int) -> None:
        """Force a trap unless 0 <= mem[idx_cell] < length.

        Faithful to the interpreter, which traps on an out-of-range array index. The
        machine has no `assert`, so the refusal is spelled as its cheapest guaranteed
        trap: divide 1 by an in-range flag that is 0 exactly when the index is out of
        range. In range, the flag is 1 and the division is a harmless 1; out of range,
        it is a division by zero -- a Trap, on both VMs, with no memory touched."""
        zero = self._load_const(0)
        lenc = self._load_const(length)
        ge0 = self._temp()
        self._emit("GE", ge0, idx_cell, zero)        # idx >= 0
        lt = self._temp()
        self._emit("LT", lt, idx_cell, lenc)         # idx < length
        inb = self._temp()
        self._emit("AND", inb, ge0, lt)              # both -> 1, else 0
        one = self._load_const(1)
        scratch = self._temp()
        self._emit("DIV", scratch, one, inb)         # inb==0 -> division by zero -> Trap


class _LabelCtx:
    """Reserved for break/continue targets; unused in v1 but threaded so adding them
    later does not touch every _stmt signature."""


def _scalar_names(prog: nodes.Program) -> list[str]:
    """Every variable name introduced by a `let`, in first-seen order (so the memory
    map is deterministic -- the same source always compiles to the same bytes)."""
    seen: list[str] = []
    seen_set: set[str] = set()

    def visit_stmt(s: nodes.Stmt) -> None:
        if isinstance(s, nodes.Let):
            if s.name not in seen_set:
                seen_set.add(s.name)
                seen.append(s.name)
        elif isinstance(s, nodes.If):
            for st in s.then:
                visit_stmt(st)
            for st in s.els:
                visit_stmt(st)
        elif isinstance(s, nodes.While):
            for st in s.body:
                visit_stmt(st)

    for s in prog.body:
        visit_stmt(s)
    return seen


def generate(prog: nodes.Program) -> dict:
    return Codegen(prog).generate()
