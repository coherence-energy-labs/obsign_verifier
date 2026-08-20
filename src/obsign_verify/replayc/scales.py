"""Fixed-point scale checking -- the bug class that actually burns receipts.

A fixed-point value is an integer TIMES an implicit 2^-N. The machine neither knows
nor cares about N; it multiplies int64s. Which is exactly the danger: adding an fx32
price to an fx16 rate, or feeding mulfx the wrong F, compiles fine, runs fine,
reproduces bit-for-bit on every implementation -- and is WRONG at the business level,
with a receipt faithfully attesting the wrong number forever. The one failure mode
re-execution cannot catch is the author meaning something else; scale checking removes
the most mechanical slice of that.

GRADUAL AND OPT-IN. Scales are declared with `: fxN` on inputs, lets, arrays and
function parameters (fx0 = "definitely a plain integer"). A program with no
annotations skips this pass entirely -- zero friction. Where annotations exist, every
expression gets a scale and the rules below are enforced. An unannotated binding is
POLYMORPHIC: compatible with anything, refined to a concrete scale by its first
concrete use. Integer literals are polymorphic too -- the author wrote a raw number
and owns its scale.

THE RULES (s = concrete scale, p = polymorphic):
  +  -  %  min  max          operands must UNIFY (equal, or one side p) -> that scale
  * : at least one side must be integer-or-p (scaling by a plain count is fine);
      fx * fx is an ERROR -> "the product is fx<a+b>; renormalize with mulfx"
  / : fx<a> / fx<a> -> fx0 (a pure ratio); fx<a> / int -> fx<a>; mixed scales ERROR
  mulfx(x: fx<a>, y: fx<b>, F) -> fx<a+b-F>; a+b-F outside 0..63 is an ERROR
  << >> ~ & | ^ : integers only -- shifting or masking an fx silently changes its
      scale, so it is refused (renormalize with mulfx, or drop the annotation)
  == != < <= > >= : operands unify; the result is fx0 (a boolean)
  neg abs : preserve the scale;  sel(c, a, b): c integer-ish, a/b unify
  if/while conditions, for bounds, array indices : integer-or-p
  output : unrestricted -- the result's scale is the author's business

HONEST LIMITS, stated rather than discovered: this is a static safety net over a
runtime that is already bit-exact, not a full type system. Polymorphic bindings are
refined in statement order, so a variable given DIFFERENT concrete scales in two
branches is reported at the second branch rather than at a join point; annotate the
binding to pin it. The net errs toward refusing, never toward silently passing a
concrete-vs-concrete mismatch.
"""
from __future__ import annotations

from . import nodes
from .nodes import Pos


class ScaleError(Exception):
    def __init__(self, msg: str, pos: Pos):
        super().__init__(f"{pos}: {msg}")
        self.pos = pos


class _Poly:
    """The polymorphic scale: unknown, compatible with anything."""
    __repr__ = lambda self: "poly"   # noqa: E731


POLY = _Poly()
Scale = "int | _Poly"


def _show(s) -> str:
    return "poly" if s is POLY else f"fx{s}"


def _unify(a, b, pos: Pos, what: str):
    if a is POLY:
        return b
    if b is POLY:
        return a
    if a == b:
        return a
    raise ScaleError(f"{what}: scale mismatch {_show(a)} vs {_show(b)} -- these are "
                     f"different fixed-point units; renormalize with mulfx or fix the "
                     f"annotation", pos)


def _want_int(s, pos: Pos, what: str) -> None:
    if s is not POLY and s != 0:
        raise ScaleError(f"{what} must be a plain integer, got {_show(s)}", pos)


def _has_annotations(prog: nodes.Program) -> bool:
    if any(sc is not None for sc in prog.input_scales):
        return True
    if prog.input_array is not None and prog.input_array.scale is not None:
        return True
    if any(a.scale is not None for a in prog.arrays):
        return True
    if any(sc is not None for fn in prog.functions for sc in fn.param_scales):
        return True
    found = False

    def st(s: nodes.Stmt) -> None:
        nonlocal found
        if isinstance(s, nodes.Let) and s.scale is not None:
            found = True
        elif isinstance(s, nodes.If):
            for t in s.then + s.els:
                st(t)
        elif isinstance(s, (nodes.While, nodes.For)):
            for t in s.body:
                st(t)

    for fn in prog.functions:
        for s in fn.body:
            st(s)
    for s in prog.body:
        st(s)
    return found


class _Checker:
    def __init__(self, prog: nodes.Program):
        self.prog = prog
        self.vars: dict[str, object] = {}
        self.arrays: dict[str, object] = {}
        #: fn name -> (param scales, return scale); computed on first use
        self.sigs: dict[str, tuple[list, object]] = {}
        self.fns = {fn.name: fn for fn in prog.functions}

    # ---- driver ----
    def run(self) -> None:
        for name, sc in zip(self.prog.inputs,
                            self.prog.input_scales or (None,) * len(self.prog.inputs)):
            self.vars[name] = POLY if sc is None else sc
        if self.prog.input_array is not None:
            ia = self.prog.input_array
            self.arrays[ia.name] = POLY if ia.scale is None else ia.scale
        for a in self.prog.arrays:
            self.arrays[a.name] = POLY if a.scale is None else a.scale
        for fn in self.prog.functions:      # signatures up front (call graph is acyclic)
            self._sig(fn.name)
        for s in self.prog.body:
            self._stmt(s)
        for e in self.prog.outputs:
            self._expr(e)                    # outputs may be any scale; still checked inside

    def _sig(self, name: str):
        if name in self.sigs:
            return self.sigs[name]
        fn = self.fns[name]
        pscales = [POLY if sc is None else sc
                   for sc in (fn.param_scales or (None,) * len(fn.params))]
        saved_vars = self.vars
        self.vars = {p: sc for p, sc in zip(fn.params, pscales)}
        ret = POLY
        try:
            for s in fn.body[:-1]:
                self._stmt(s)
            tail = fn.body[-1]
            assert isinstance(tail, nodes.Return)
            ret = self._expr(tail.expr)
        finally:
            self.vars = saved_vars
        self.sigs[name] = (pscales, ret)
        return self.sigs[name]

    # ---- statements ----
    def _stmt(self, s: nodes.Stmt) -> None:
        if isinstance(s, nodes.Let):
            got = self._expr(s.expr)
            if s.scale is not None:
                _unify(s.scale, got, s.pos, f"let {s.name}: fx{s.scale}")
                self.vars[s.name] = s.scale
            else:
                self.vars[s.name] = got
        elif isinstance(s, nodes.Assign):
            got = self._expr(s.expr)
            cur = self.vars[s.name]
            merged = _unify(cur, got, s.pos, f"assignment to {s.name}")
            self.vars[s.name] = merged      # a poly var is refined by concrete use
        elif isinstance(s, nodes.StoreElem):
            _want_int(self._expr(s.index), s.pos, f"index into {s.array}")
            got = self._expr(s.value)
            cur = self.arrays[s.array]
            self.arrays[s.array] = _unify(cur, got, s.pos, f"store into {s.array}[]")
        elif isinstance(s, nodes.If):
            _want_int(self._expr(s.cond), s.pos, "if condition")
            for t in s.then:
                self._stmt(t)
            for t in s.els:
                self._stmt(t)
        elif isinstance(s, nodes.While):
            _want_int(self._expr(s.cond), s.pos, "while condition")
            for t in s.body:
                self._stmt(t)
        elif isinstance(s, nodes.For):
            _want_int(self._expr(s.lo), s.pos, "for lower bound")
            _want_int(self._expr(s.hi), s.pos, "for upper bound")
            self.vars[s.var] = 0
            for t in s.body:
                self._stmt(t)
        elif isinstance(s, nodes.Return):
            self._expr(s.expr)   # captured by _sig at the tail
        # Break / Continue: nothing to check

    # ---- expressions ----
    def _expr(self, e: nodes.Expr):
        if isinstance(e, nodes.IntLit):
            return POLY
        if isinstance(e, nodes.Name):
            return self.vars.get(e.ident, POLY)
        if isinstance(e, nodes.Index):
            _want_int(self._expr(e.index), e.pos, f"index into {e.array}")
            return self.arrays.get(e.array, POLY)
        if isinstance(e, nodes.Unary):
            s = self._expr(e.operand)
            if e.op == "not":
                _want_int(s, e.pos, "operand of ~ (bitwise NOT reinterprets an fx)")
                return s
            return s                          # neg preserves the scale
        if isinstance(e, nodes.Binary):
            return self._binary(e)
        if isinstance(e, nodes.Call):
            return self._call(e)
        return POLY  # pragma: no cover

    def _binary(self, e: nodes.Binary):
        l = self._expr(e.left)
        r = self._expr(e.right)
        op = e.op
        if op in ("ADD", "SUB", "MOD"):
            return _unify(l, r, e.pos, {"ADD": "+", "SUB": "-", "MOD": "%"}[op])
        if op in ("EQ", "NE", "LT", "LE", "GT", "GE"):
            _unify(l, r, e.pos, "comparison")
            return 0
        if op == "MUL":
            if l is POLY or l == 0:
                return r
            if r is POLY or r == 0:
                return l
            raise ScaleError(
                f"multiplying {_show(l)} by {_show(r)} yields fx{l + r}, which is "
                f"almost never what you want -- renormalize with "
                f"mulfx(x, y, F)", e.pos)
        if op == "DIV":
            if r is POLY or r == 0:
                return l                     # fx / plain-int keeps the scale
            if l is POLY:
                return POLY                  # cannot decide ratio vs rescale
            if l == r:
                return 0                     # same unit / same unit = a pure ratio
            raise ScaleError(
                f"dividing {_show(l)} by {_show(r)}: different fixed-point units; "
                f"renormalize with mulfx or fix the annotation", e.pos)
        if op in ("SHL", "SHR", "AND", "OR", "XOR"):
            _want_int(l, e.pos, f"left operand of {op} (it silently changes an fx's scale)")
            _want_int(r, e.pos, f"right operand of {op}")
            return 0 if (l == 0 or r == 0) else POLY
        raise ScaleError(f"unknown operator {op}", e.pos)  # pragma: no cover

    def _call(self, e: nodes.Call):
        if e.fn in self.fns:
            pscales, ret = self._sig(e.fn)
            for i, (a, want) in enumerate(zip(e.args, pscales)):
                got = self._expr(a)
                _unify(want, got, e.pos, f"argument {i + 1} of {e.fn}()")
            return ret
        if e.fn == "len":
            return 0
        if e.fn in ("min", "max"):
            return _unify(self._expr(e.args[0]), self._expr(e.args[1]), e.pos, e.fn)
        if e.fn == "abs":
            return self._expr(e.args[0])
        if e.fn == "sel":
            _want_int(self._expr(e.args[0]), e.pos, "sel() condition")
            return _unify(self._expr(e.args[1]), self._expr(e.args[2]), e.pos, "sel() arms")
        if e.fn == "mulfx":
            sx = self._expr(e.args[0])
            sy = self._expr(e.args[1])
            frac = e.args[2]
            assert isinstance(frac, nodes.IntLit)   # typer guarantees
            if sx is POLY or sy is POLY:
                return POLY
            out = sx + sy - frac.value
            if not (0 <= out <= 63):
                raise ScaleError(
                    f"mulfx({_show(sx)}, {_show(sy)}, {frac.value}) yields fx{out}, "
                    f"outside fx0..fx63 -- the F is wrong for these operands", e.pos)
            return out
        return POLY  # pragma: no cover - typer rejects unknown fns


def check_scales(prog: nodes.Program) -> nodes.Program:
    """Enforce the fixed-point rules wherever annotations opt in; a program with no
    annotations passes through untouched."""
    if _has_annotations(prog):
        _Checker(prog).run()
    return prog
