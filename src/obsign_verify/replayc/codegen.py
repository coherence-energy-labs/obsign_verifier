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

  BOUNDS-CHECK COALESCING. Along a straight-line run, accesses v[b], v[b+1], v[b+2]
    over one unwritten base share ONE range gadget (b >= -lo && b < len-hi) instead
    of three -- sound because RL has no short-circuit, so every access in the run
    executes unless an earlier trap ends the whole run, and trap-for-trap is the
    machine's observable contract. See _block for the full argument and the
    conservative invalidation rules.

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


class _LoopCtx:
    """Where `break` and `continue` jump for the innermost enclosing loop. For a
    `while`, continue re-evaluates the condition; for a `for`, it lands on the
    increment -- desugaring `for` to `while` naively would send continue past the
    increment and spin forever, which is why For is a real node all the way down."""
    __slots__ = ("brk", "cont")

    def __init__(self, brk: _Label, cont: _Label):
        self.brk = brk
        self.cont = cont


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
        #: bounds-check coalescing state: (array, base-name) -> (lo_off, hi_off)
        #: already PROVEN in range by an emitted gadget, valid only along the current
        #: straight-line run -- cleared at every control statement, dropped when the
        #: base name is written. See _block for the soundness argument.
        self._covered: dict[tuple[str, str], tuple[int, int]] = {}

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
        # each `for` gets a dedicated cell for its upper bound: evaluated once, it must
        # survive across iterations, so it cannot live in the per-statement temp region
        self._for_hi: dict[int, int] = {}
        for node in _for_nodes(self.prog):
            self._for_hi[id(node)] = self._alloc()
        self._temp_base = self._next
        self._temp_ptr = self._temp_base
        self._temp_hi = self._temp_base

        body_cost = self._block(self.prog.body, None)
        mark = len(self.code)
        for i, e in enumerate(self.prog.outputs):
            self._reset_temps()
            c = self._expr(e, want=out_off + i)
            if c != out_off + i:
                self._emit("MOV", out_off + i, c)
        self._emit("HALT")
        tail_cost = len(self.code) - mark          # outputs + HALT, all straight-line

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

        # ---- the step budget: declared beats inferred beats the hard ceiling ----
        # When every loop is statically bounded, the compiler KNOWS the worst-case
        # instruction count exactly (preamble + body + outputs + HALT) and writes it
        # as the budget: the tightest honest `steps` a receipt can carry, computed
        # instead of guessed. An author's explicit #steps always wins -- their
        # contract, their number.
        self.inferred_steps = (None if body_cost is None
                               else len(self.pre) + body_cost + tail_cost)
        if self.prog.steps is not None:
            steps = self.prog.steps
        elif self.inferred_steps is not None:
            # a worst case beyond the VM's hard ceiling clamps to the ceiling: a run
            # that would exceed it traps there regardless, and a break-carrying
            # program may legitimately finish far earlier
            steps = min(self.inferred_steps, MAX_STEPS)
        else:
            steps = MAX_STEPS
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

    # ---- bounds-check coalescing --------------------------------------------
    #
    # WHY THIS IS SOUND. RL has no short-circuit: within one straight-line run of
    # simple statements (Let/Assign/StoreElem -- no branches, no loops, no
    # break/continue between), EVERY array access in the run executes, unless an
    # earlier trap ends the whole run. So for accesses v[b], v[b+1], v[b+2] whose
    # index is the SAME unwritten scalar plus constant offsets, one range check
    #   b >= -lo   AND   b < len - hi        (lo = min offset, hi = max offset)
    # proves every access in range. If the range check trips where a per-access
    # check would have tripped LATER, the observable outcome is identical: a Trap.
    # Trap-for-trap equivalence is the machine's established contract (the trap
    # carries a reason, never partial state), and the differential fuzzer holds the
    # compiled program to the interpreter under exactly that contract.
    #
    # WHY THE INVALIDATION IS CONSERVATIVE. Coverage lives only along the current
    # run: any control statement clears it entirely (a branch may skip the access
    # that widened the range, so pre-emitting for it could trap on a path that
    # never touches it); writing the base name drops its entries (the checked value
    # is gone). Offsets are only coalesced when |offset| <= MAX_MEM, so the range
    # arithmetic cannot wrap; anything else takes the ordinary per-access gadget,
    # which checks the WRAPPED computed index exactly as the interpreter does.

    @staticmethod
    def _pattern(e):
        """(base-name, constant offset) for an index of the shape n / n+k / k+n /
        n-k, else None. Only these participate in coalescing."""
        if isinstance(e, nodes.Name):
            return (e.ident, 0)
        if isinstance(e, nodes.Binary) and isinstance(e.left, nodes.Name) \
                and isinstance(e.right, nodes.IntLit):
            if e.op == "ADD":
                return (e.left.ident, e.right.value)
            if e.op == "SUB":
                return (e.left.ident, -e.right.value)
        if isinstance(e, nodes.Binary) and e.op == "ADD" \
                and isinstance(e.left, nodes.IntLit) and isinstance(e.right, nodes.Name):
            return (e.right.ident, e.left.value)
        return None

    def _scan_expr(self, e, out: dict) -> None:
        """Collect coalescable accesses in E into OUT: (array, name) -> (lo, hi)."""
        if isinstance(e, nodes.Index):
            pat = self._pattern(e.index)
            if pat is not None and abs(pat[1]) <= MAX_MEM and e.array in self.array \
                    and pat[0] in self.scalar:
                key = (e.array, pat[0])
                lo, hi = out.get(key, (pat[1], pat[1]))
                out[key] = (min(lo, pat[1]), max(hi, pat[1]))
            else:
                self._scan_expr(e.index, out)
            return
        if isinstance(e, nodes.Unary):
            self._scan_expr(e.operand, out)
        elif isinstance(e, nodes.Binary):
            self._scan_expr(e.left, out)
            self._scan_expr(e.right, out)
        elif isinstance(e, nodes.Call):
            for a in e.args:
                self._scan_expr(a, out)

    def _stmt_groups(self, s) -> dict:
        out: dict = {}
        if isinstance(s, (nodes.Let, nodes.Assign)):
            self._scan_expr(s.expr, out)
        elif isinstance(s, nodes.StoreElem):
            self._scan_expr(s.index, out)
            self._scan_expr(s.value, out)
        return out

    @staticmethod
    def _writes_of(s) -> set:
        return {s.name} if isinstance(s, (nodes.Let, nodes.Assign)) else set()

    def _range_trap(self, base_cell, lo: int, hi: int, length: int) -> None:
        """Trap unless base+lo >= 0 and base+hi < length, i.e. base in
        [-lo, length-hi). Four instructions whatever the group size; the same
        divide-by-flag refusal as the single-access gadget."""
        t = self._temp()
        t2 = self._temp()
        self._emit("GE", t, base_cell, self._cellc(-lo))
        self._emit("LT", t2, base_cell, self._cellc(length - hi))
        self._emit("AND", t, t, t2)
        self._emit("DIV", t, self._cellc(1), t)

    def _emit_groups_for_expr(self, e) -> None:
        """Range-check the coalescable accesses of a single expression (an if/while
        condition or for bound) right before it is evaluated."""
        groups: dict = {}
        self._scan_expr(e, groups)
        for (arr_name, base_name), (lo, hi) in groups.items():
            cov = self._covered.get((arr_name, base_name))
            if cov is not None and cov[0] <= lo and hi <= cov[1]:
                continue
            if cov is not None:
                lo, hi = min(lo, cov[0]), max(hi, cov[1])
            _b, length = self.array[arr_name]
            self._range_trap(self.scalar[base_name], lo, hi, length)
            self._covered[(arr_name, base_name)] = (lo, hi)

    def _block(self, stmts, loop: "_LoopCtx | None"):
        """Lower a statement block with coalescing; return its worst-case executed
        cost (None-absorbing). For each simple statement, groups not yet covered are
        widened by LOOKING AHEAD through the rest of the run (stopping where the
        base name is written or the run ends), so one gadget serves the whole
        lifetime of the base value."""
        total = 0
        stmts = list(stmts)
        for i, s in enumerate(stmts):
            self._reset_temps()
            if isinstance(s, (nodes.Let, nodes.Assign, nodes.StoreElem)):
                mark = len(self.code)
                for key, (lo, hi) in self._stmt_groups(s).items():
                    arr_name, base_name = key
                    cov = self._covered.get(key)
                    if cov is not None and cov[0] <= lo and hi <= cov[1]:
                        continue
                    # widen over the rest of the run while the base survives
                    for later in stmts[i + 1:]:
                        if not isinstance(later, (nodes.Let, nodes.Assign, nodes.StoreElem)):
                            break
                        for k2, (l2, h2) in self._stmt_groups(later).items():
                            if k2 == key:
                                lo, hi = min(lo, l2), max(hi, h2)
                        if base_name in self._writes_of(later):
                            break
                    if cov is not None:
                        lo, hi = min(lo, cov[0]), max(hi, cov[1])
                    _base, length = self.array[arr_name]
                    self._range_trap(self.scalar[base_name], lo, hi, length)
                    self._covered[key] = (lo, hi)
                c = self._stmt(s, loop)
                for name in self._writes_of(s):
                    for key in [k for k in self._covered if k[1] == name]:
                        del self._covered[key]
                c = len(self.code) - mark        # includes the group gadgets
            else:
                self._covered.clear()
                c = self._stmt(s, loop)
                self._covered.clear()
            total = None if (total is None or c is None) else total + c
        return total

    # ---- statements ----
    #
    # Each statement returns its WORST-CASE executed instruction count, or None when
    # it cannot be bounded statically (a `while`, a `for` with non-constant bounds or
    # a body that writes its own loop variable). generate() composes these into an
    # exact step budget: for straight-line code and taken-worst branches the count is
    # achieved, not merely bounded -- pinned by tests that run at the inferred budget
    # and trap at budget-1.
    def _stmt(self, s: nodes.Stmt, loop: _LoopCtx | None) -> int | None:
        if isinstance(s, (nodes.Let, nodes.Assign)):
            mark = len(self.code)
            dst = self.scalar[s.name]
            c = self._expr(s.expr, want=dst)
            if c != dst:
                self._emit("MOV", dst, c)
            return len(self.code) - mark
        elif isinstance(s, nodes.StoreElem):
            mark = len(self.code)
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
                pat = self._pattern(idx)
                cov = self._covered.get((s.array, pat[0])) if pat is not None else None
                if pat is not None and cov is not None and cov[0] <= pat[1] <= cov[1]:
                    val = self._expr(s.value)
                    name_cell = self.scalar[pat[0]]
                    off = pat[1] + base
                    if off == 0:
                        addr = name_cell
                    else:
                        addr = self._temp()
                        self._emit("ADD", addr, name_cell, self._cellc(off))
                    self._emit("STORE", addr, val)
                else:
                    idx_cell = self._expr(idx)
                    self._bounds_trap(idx_cell, length)
                    val = self._expr(s.value)
                    addr = self._addr(idx_cell, base)
                    self._emit("STORE", addr, val)
            return len(self.code) - mark
        elif isinstance(s, nodes.If):
            mark = len(self.code)
            self._emit_groups_for_expr(s.cond)
            cond = self._expr(s.cond)
            cond_cost = len(self.code) - mark
            self._covered.clear()
            else_l = self._label("else")
            end_l = self._label("end")
            self._emit("JMPZ", cond, else_l)
            then_cost = self._block(s.then, loop)
            self._emit("JMP", end_l)
            self._place(else_l)
            else_cost = self._block(s.els, loop)
            self._place(end_l)
            self._covered.clear()
            if then_cost is None or else_cost is None:
                return None
            # the taken then-branch also executes its trailing JMP
            return cond_cost + 1 + max(then_cost + 1, else_cost)
        elif isinstance(s, nodes.While):
            top = self._label("while")
            end = self._label("endwhile")
            inner = _LoopCtx(brk=end, cont=top)   # continue re-evaluates the condition
            self._place(top)
            self._reset_temps()
            self._covered.clear()            # the back-edge lands here
            self._emit_groups_for_expr(s.cond)   # re-checked every iteration, correctly
            cond = self._expr(s.cond)
            self._emit("JMPZ", cond, end)
            self._covered.clear()
            self._block(s.body, inner)
            self._emit("JMP", top)
            self._place(end)
            self._covered.clear()
            return None                      # a while's trip count is not static
        elif isinstance(s, nodes.For):
            mark = len(self.code)
            var = self.scalar[s.var]
            hi = self._for_hi[id(s)]
            # bounds evaluated ONCE, before the first iteration -- hi into its
            # dedicated cell so it survives the per-iteration temp reset
            self._emit_groups_for_expr(s.lo)     # bounds evaluated once, checked once
            self._emit_groups_for_expr(s.hi)
            lo_c = self._expr(s.lo, want=var)
            if lo_c != var:
                self._emit("MOV", var, lo_c)
            hi_c = self._expr(s.hi, want=hi)
            if hi_c != hi:
                self._emit("MOV", hi, hi_c)
            init_cost = len(self.code) - mark
            top = self._label("for")
            incr = self._label("forincr")
            end = self._label("endfor")
            inner = _LoopCtx(brk=end, cont=incr)  # continue lands ON the increment
            self._place(top)
            self._reset_temps()
            self._covered.clear()                 # the back-edge lands here
            t = self._temp()
            self._emit("LT", t, var, hi)
            self._emit("JMPZ", t, end)
            body_cost = self._block(s.body, inner)
            self._covered.clear()
            self._place(incr)
            self._emit("ADD", var, var, self._cellc(1))
            self._emit("JMP", top)
            self._place(end)
            if (body_cost is None
                    or not isinstance(s.lo, nodes.IntLit)
                    or not isinstance(s.hi, nodes.IntLit)
                    or _writes_var(s.body, s.var)):
                return None
            n = max(0, s.hi.value - s.lo.value)
            # n full iterations (check, body, increment, back-jump) + the final
            # failing check. break/continue only shorten a pass, so this is an upper
            # bound that straight-line bodies achieve exactly.
            return init_cost + n * (2 + body_cost + 2) + 2
        elif isinstance(s, nodes.Break):
            if loop is None:  # pragma: no cover - typer rejects
                raise CodegenError("break outside a loop")
            self._emit("JMP", loop.brk)
            return 1
        elif isinstance(s, nodes.Continue):
            if loop is None:  # pragma: no cover - typer rejects
                raise CodegenError("continue outside a loop")
            self._emit("JMP", loop.cont)
            return 1
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
            pat = self._pattern(e.index)
            if pat is not None:
                cov = self._covered.get((e.array, pat[0]))
                if cov is not None and cov[0] <= pat[1] <= cov[1]:
                    # a coalesced range gadget already proved this access in range;
                    # the offset and the array base fuse into ONE add (or none)
                    name_cell = self.scalar[pat[0]]
                    off = pat[1] + base
                    if off == 0:
                        addr = name_cell
                    else:
                        addr = self._temp()
                        self._emit("ADD", addr, name_cell, self._cellc(off))
                    dst = want if want is not None else self._temp()
                    self._emit("LOAD", dst, addr)
                    return dst
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
        if e.fn == "len":
            arg = e.args[0]
            assert isinstance(arg, nodes.Name)   # typer guarantees
            _, length = self.array[arg.ident]
            return self._cellc(length)
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
        # a user function reaching codegen means the inliner did not run -- a pipeline
        # bug, not a program bug, so it fails loudly at build time
        raise CodegenError(f"internal: call to {e.fn!r} survived inlining")

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


def _csum(costs) -> int | None:
    """Sum of statement costs; None (uninferable) is absorbing."""
    total = 0
    for c in costs:
        if c is None:
            return None
        total += c
    return total


def _writes_var(stmts, var: str) -> bool:
    """Does any statement in STMTS (recursively) write VAR? A for-loop whose body
    writes its own loop variable has a data-dependent trip count -- no inference."""
    for s in stmts:
        if isinstance(s, (nodes.Let, nodes.Assign)) and s.name == var:
            return True
        if isinstance(s, nodes.If) and (_writes_var(s.then, var) or _writes_var(s.els, var)):
            return True
        if isinstance(s, nodes.While) and _writes_var(s.body, var):
            return True
        if isinstance(s, nodes.For) and (s.var == var or _writes_var(s.body, var)):
            return True
    return False


def _scalar_names(prog: nodes.Program) -> list[str]:
    """Every variable name introduced by a `let` or a `for`, in first-seen order, so
    the memory map -- and therefore the emitted program -- is deterministic."""
    seen: list[str] = []
    seen_set: set[str] = set()

    def add(name: str) -> None:
        if name not in seen_set:
            seen_set.add(name)
            seen.append(name)

    def visit_stmt(s: nodes.Stmt) -> None:
        if isinstance(s, nodes.Let):
            add(s.name)
        elif isinstance(s, nodes.If):
            for st in s.then:
                visit_stmt(st)
            for st in s.els:
                visit_stmt(st)
        elif isinstance(s, nodes.While):
            for st in s.body:
                visit_stmt(st)
        elif isinstance(s, nodes.For):
            add(s.var)
            for st in s.body:
                visit_stmt(st)

    for s in prog.body:
        visit_stmt(s)
    return seen


def _for_nodes(prog: nodes.Program) -> list[nodes.For]:
    """Every For node, in the emission order codegen will meet them, so each one's
    dedicated upper-bound cell is allocated deterministically."""
    out: list[nodes.For] = []

    def visit(s: nodes.Stmt) -> None:
        if isinstance(s, nodes.If):
            for st in s.then + s.els:
                visit(st)
        elif isinstance(s, nodes.While):
            for st in s.body:
                visit(st)
        elif isinstance(s, nodes.For):
            out.append(s)
            for st in s.body:
                visit(st)

    for s in prog.body:
        visit(s)
    return out


def generate(prog: nodes.Program) -> dict:
    return Codegen(prog).generate()
