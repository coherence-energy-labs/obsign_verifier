"""Lower a checked, folded AST to an `obsign/replay/1` program -- and make it tight.

The whole compiler earns trust from one property: for every input on which the
reference interpreter produces a number, the program emitted here runs -- on the
Python VM and the JS VM alike -- to the SAME number; and on every input where the
interpreter refuses (a trap), the program traps too. codegen is the only place that
can break that, so every optimization below is justified against that property, and
the differential fuzzer (which compares this output against the interpreter, which
never sees this code) is the enforcement.

WHAT THE OPTIMIZER DOES, and why each transformation is trap-faithful:

  CONSTANT POOL. Every distinct constant is loaded ONCE, in a preamble, into its own
    dedicated cell; uses reference the cell with no instruction at all. The naive
    lowering re-LOADC'd constants on every loop iteration -- the single largest waste
    in real programs. Pool cells are never written after the preamble, so a use reads
    the same value the LOADC would have produced. The constant 0 is cheaper still: a
    replay machine's memory STARTS zeroed, so 0 lives in a dedicated cell that is
    simply never written -- no instruction anywhere.

  DESTINATION-DIRECTED EMISSION. `let x = a + b` emits `ADD x, a, b`, not
    `ADD t, a, b; MOV x, t`. Safe because the machine reads both operands before
    writing the destination (pinned by the VM spec and both implementations), and
    because expressions cannot write scalars -- only statements can -- so nothing
    inside the right-hand side can observe the destination early.

  STATIC ARRAY INDEXING. `xs[2]` with a constant in-range index is a KNOWN CELL: a
    read is just that cell used as an operand (zero instructions), a write is one MOV.
    A constant index that is statically OUT of range keeps the interpreter's trap: an
    unconditional trap gadget is emitted at the same evaluation point, because a
    program that traps when that line runs must still trap -- deleting the access
    would change behaviour on exactly the runs that reach it.

  DYNAMIC BOUNDS GADGET, SLIMMED. For a computed index the bounds check must run at
    run time. With pooled constants it is four instructions -- GE, LT, AND, and a
    DIV whose divisor is the in-range flag: 1 in range (a harmless division), 0 out of
    range (division by zero, the machine's cheapest guaranteed trap). The temps reuse
    one cell; operands are read before the write, so in-place reuse is exact. When the
    array sits at offset 0 (the input window), the index cell IS the address -- the
    base-add disappears too.

MEMORY MAP (all disjoint, low to high)
  [0, n_in)            input window -- the VM writes inputs here
  [n_in, n_in+n_out)   output window -- the VM reads the result here
  scalars              one cell per named variable (inputs alias their input cells)
  arrays               a contiguous block per `arr`
  temps                expression scratch, reset per statement
  pool                 one cell per distinct constant, + the never-written zero cell
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


class _Const:
    """Placeholder operand for a pooled constant; resolved to a cell index after
    emission, when the pool's position in memory is known."""
    __slots__ = ("value",)

    def __init__(self, value: int):
        self.value = value


class Codegen:
    def __init__(self, prog: nodes.Program):
        self.prog = prog
        self.pre: list[list] = []          # constant-pool preamble
        self.code: list[list] = []         # body
        self.consts: list[int] = []        # the program's const table (for LOADC)
        self._const_ix: dict[int, int] = {}
        self._pool: dict[int, _Const] = {}  # value -> shared placeholder
        self.scalar: dict[str, int] = {}
        self.array: dict[str, tuple[int, int]] = {}   # name -> (base, length)
        self._labels: dict[int, int] = {}             # id(label) -> body index
        self._n_in = prog.input_array.length if prog.input_array is not None else len(prog.inputs)
        self._n_out = len(prog.outputs)
        self._next = 0
        self._temp_ptr = 0
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
    def _const_index(self, value: int) -> int:
        if value not in self._const_ix:
            self._const_ix[value] = len(self.consts)
            self.consts.append(value)
        return self._const_ix[value]

    def _cellc(self, value: int) -> _Const:
        """The pool cell holding VALUE. First use of a nonzero value adds one LOADC to
        the preamble; every use after that is free. Zero is free from the first use:
        its cell is simply never written (memory starts zeroed)."""
        if value not in self._pool:
            self._pool[value] = _Const(value)
            if value != 0:
                self.pre.append(["LOADC", self._pool[value], self._const_index(value)])
        return self._pool[value]

    # ---- labels / emit ----
    def _label(self, name: str) -> _Label:
        return _Label(name)

    def _place(self, lbl: _Label) -> None:
        self._labels[id(lbl)] = len(self.code)

    def _emit(self, *ins) -> None:
        self.code.append(list(ins))

    # ---- driver ----
    def generate(self) -> dict:
        self._alloc(self._n_in)
        out_off = self._alloc(self._n_out)
        if self.prog.input_array is not None:
            self.array[self.prog.input_array.name] = (0, self.prog.input_array.length)
        for i, name in enumerate(self.prog.inputs):
            self.scalar[name] = i
        for name in _scalar_names(self.prog):
            if name not in self.scalar:
                self.scalar[name] = self._alloc()
        for arr in self.prog.arrays:
            self.array[arr.name] = (self._alloc(arr.length), arr.length)
        self._temp_base = self._next
        self._temp_ptr = self._temp_base
        self._temp_hi = self._temp_base

        for s in self.prog.body:
            self._reset_temps()
            self._stmt(s)
        for i, e in enumerate(self.prog.outputs):
            self._reset_temps()
            c = self._expr(e, want=out_off + i)
            if c != out_off + i:
                self._emit("MOV", out_off + i, c)
        self._emit("HALT")

        # ---- place the pool after the temp high-water, resolve placeholders ----
        pool_base = max(self._temp_hi, self._next)
        cell_of: dict[int, int] = {}
        for i, value in enumerate(self._pool):        # dict order = first-use order
            cell_of[value] = pool_base + i
        mem = pool_base + len(self._pool)
        mem = max(mem, self._n_in + self._n_out, 1)
        if mem > MAX_MEM:
            raise CodegenError(f"program needs {mem} cells, over the {MAX_MEM} limit")

        offset = len(self.pre)
        final: list[list] = []
        for ins in self.pre + self.code:
            out = [ins[0]]
            for a in ins[1:]:
                if isinstance(a, _Const):
                    out.append(cell_of[a.value])
                elif isinstance(a, _Label):
                    if id(a) not in self._labels:
                        raise CodegenError(f"unresolved label {a.name!r}")  # pragma: no cover
                    out.append(self._labels[id(a)] + offset)
                else:
                    out.append(a)
            final.append(out)

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
            "code": final,
        }
        # The compiler's output must satisfy the SAME validator a stranger's receipt
        # does; a program validate() rejects is a compiler bug caught at build time.
        validate(program)
        return program

    # ---- statements ----
    def _stmt(self, s: nodes.Stmt) -> None:
        if isinstance(s, (nodes.Let, nodes.Assign)):
            dst = self.scalar[s.name]
            c = self._expr(s.expr, want=dst)
            if c != dst:
                self._emit("MOV", dst, c)
        elif isinstance(s, nodes.StoreElem):
            base, length = self.array[s.array]
            idx = s.index
            if isinstance(idx, nodes.IntLit):
                if 0 <= idx.value < length:
                    cell = base + idx.value
                    c = self._expr(s.value, want=cell)
                    if c != cell:
                        self._emit("MOV", cell, c)
                else:
                    # statically out of range: trap exactly where the interpreter
                    # does -- after the (constant) index, before the value
                    self._trap_now()
                    self._expr(s.value)   # unreachable at run time; keeps cell shapes
            else:
                idx_cell = self._expr(idx)
                self._bounds_trap(idx_cell, length)
                val = self._expr(s.value)
                addr = self._addr(idx_cell, base)
                self._emit("STORE", addr, val)
        elif isinstance(s, nodes.If):
            cond = self._expr(s.cond)
            else_l = self._label("else")
            end_l = self._label("end")
            self._emit("JMPZ", cond, else_l)
            for st in s.then:
                self._stmt(st)
            self._emit("JMP", end_l)
            self._place(else_l)
            for st in s.els:
                self._stmt(st)
            self._place(end_l)
        elif isinstance(s, nodes.While):
            top = self._label("while")
            end = self._label("endwhile")
            self._place(top)
            self._reset_temps()
            cond = self._expr(s.cond)
            self._emit("JMPZ", cond, end)
            for st in s.body:
                self._stmt(st)
            self._emit("JMP", top)
            self._place(end)
        else:  # pragma: no cover
            raise CodegenError(f"unknown statement {type(s).__name__}")

    # ---- expressions ----
    def _expr(self, e: nodes.Expr, want: int | None = None):
        """Emit E; return the cell (int or _Const placeholder) holding its value.
        WANT is a destination the caller will accept -- when the expression must emit
        an instruction anyway, it lands there; when the value already lives somewhere
        (a constant, a scalar, a statically-indexed array cell), that cell is returned
        with no emission and the caller decides whether a MOV is needed."""
        if isinstance(e, nodes.IntLit):
            return self._cellc(e.value)
        if isinstance(e, nodes.Name):
            return self.scalar[e.ident]
        if isinstance(e, nodes.Index):
            base, length = self.array[e.array]
            if isinstance(e.index, nodes.IntLit):
                if 0 <= e.index.value < length:
                    return base + e.index.value          # a known cell: zero instructions
                self._trap_now()                         # statically OOB: still traps here
                return self._cellc(0)                    # unreachable; a valid operand
            idx_cell = self._expr(e.index)
            self._bounds_trap(idx_cell, length)
            addr = self._addr(idx_cell, base)
            dst = want if want is not None else self._temp()
            self._emit("LOAD", dst, addr)
            return dst
        if isinstance(e, nodes.Unary):
            x = self._expr(e.operand)
            dst = want if want is not None else self._temp()
            self._emit("NEG" if e.op == "neg" else "NOT", dst, x)
            return dst
        if isinstance(e, nodes.Binary):
            a = self._expr(e.left)
            b = self._expr(e.right)
            dst = want if want is not None else self._temp()
            self._emit(e.op, dst, a, b)
            return dst
        if isinstance(e, nodes.Call):
            return self._call(e, want)
        raise CodegenError(f"unknown expression {type(e).__name__}")  # pragma: no cover

    def _call(self, e: nodes.Call, want: int | None):
        if e.fn in ("min", "max"):
            a = self._expr(e.args[0])
            b = self._expr(e.args[1])
            dst = want if want is not None else self._temp()
            self._emit("MIN" if e.fn == "min" else "MAX", dst, a, b)
            return dst
        if e.fn == "abs":
            x = self._expr(e.args[0])
            dst = want if want is not None else self._temp()
            self._emit("ABS", dst, x)
            return dst
        if e.fn == "sel":
            cond = self._expr(e.args[0])
            a = self._expr(e.args[1])
            b = self._expr(e.args[2])
            dst = want if want is not None else self._temp()
            self._emit("SEL", dst, cond, a, b)
            return dst
        if e.fn == "mulfx":
            a = self._expr(e.args[0])
            b = self._expr(e.args[1])
            frac = e.args[2].value                   # typer guarantees a literal 0..63
            dst = want if want is not None else self._temp()
            self._emit("MULFX", dst, a, b, frac)
            return dst
        raise CodegenError(f"unknown builtin {e.fn!r}")  # pragma: no cover

    # ---- helpers ----
    def _addr(self, idx_cell, base: int):
        """A cell holding idx + base. The input window sits at base 0, so indexing it
        needs no add at all -- the index cell IS the address."""
        if base == 0:
            return idx_cell
        dst = self._temp()
        self._emit("ADD", dst, idx_cell, self._cellc(base))
        return dst

    def _bounds_trap(self, idx_cell, length: int) -> None:
        """Trap unless 0 <= mem[idx_cell] < length: four instructions, one temp.

        The in-place temp reuse is exact because the machine reads operands before
        writing the destination. In range the DIV computes 1/1 and is discarded; out
        of range it divides by zero -- a Trap on both VMs, with no memory touched."""
        t = self._temp()
        t2 = self._temp()
        self._emit("GE", t, idx_cell, self._cellc(0))
        self._emit("LT", t2, idx_cell, self._cellc(length))
        self._emit("AND", t, t, t2)
        self._emit("DIV", t, self._cellc(1), t)

    def _trap_now(self) -> None:
        """An unconditional trap: division by the never-written zero cell."""
        t = self._temp()
        self._emit("DIV", t, self._cellc(1), self._cellc(0))


def _scalar_names(prog: nodes.Program) -> list[str]:
    """Every variable name introduced by a `let`, in first-seen order, so the memory
    map -- and therefore the emitted program -- is deterministic."""
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
