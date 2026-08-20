"""Static checks over the AST, before codegen sees it.

Codegen is allowed to be simple because everything that could make it emit a
malformed program is rejected here first: an unknown name, a builtin or function
called with the wrong arity, a `mulfx` whose fractional count is not a compile-time
constant in 0..63, an integer literal that does not fit int64, a write to something
that is not a declared array, a `break` outside a loop, a `return` outside a
function, a recursive call. By the time codegen runs, every Name resolves, every
array is known, every call site matches a definition, and the call graph is acyclic
-- so codegen never has to decide what to do about a broken tree.

FUNCTIONS ARE CLOSED AND TOTAL BY CONSTRUCTION. A function body sees only its
parameters and its own `let`s -- no globals, no inputs, no arrays -- and recursion,
direct or mutual, is rejected. Closedness is what makes a call a pure int64
computation the compiler can inline and the interpreter can execute natively as two
independent lowerings; the recursion ban is what keeps inlining terminating and the
whole language total, the same property the machine itself is built on. The one
`return` must be the function's final statement: a single, predictable exit that both
lowerings implement identically.

This is name/shape checking, not a value analysis: whether a shift amount or an array
index is in range depends on the inputs and is enforced by the machine at run time as
a Trap. The typer proves the program is well-FORMED; the VM keeps it total.
"""
from __future__ import annotations

from ..replay import INT64_MAX, INT64_MIN
from . import nodes
from .nodes import Pos

_ARITY = {"min": 2, "max": 2, "abs": 1, "sel": 3, "mulfx": 3, "len": 1}


class TypeError_(Exception):
    """A well-formedness error with a source position."""

    def __init__(self, msg: str, pos: Pos):
        super().__init__(f"{pos}: {msg}")
        self.pos = pos


class _Scope:
    def __init__(self, *, in_fn: str | None = None) -> None:
        self.vars: set[str] = set()
        self.arrays: dict[str, int] = {}
        self.in_fn = in_fn            # function name, or None in the main body
        self.loop_depth = 0


class _Ctx:
    def __init__(self, fns: dict[str, nodes.FnDecl]) -> None:
        self.fns = fns


def check(prog: nodes.Program) -> nodes.Program:
    if prog.consts:
        raise TypeError_("internal: consts must be resolved before type checking", prog.pos)

    fns: dict[str, nodes.FnDecl] = {}
    for fn in prog.functions:
        if fn.name in _ARITY:
            raise TypeError_(f"fn {fn.name!r} collides with a builtin", fn.pos)
        if fn.name in fns:
            raise TypeError_(f"duplicate fn {fn.name!r}", fn.pos)
        fns[fn.name] = fn
    ctx = _Ctx(fns)

    # ---- each function: closed scope, tail return, arity of everything it calls ----
    for fn in prog.functions:
        fsc = _Scope(in_fn=fn.name)
        for p in fn.params:
            if p in fsc.vars:
                raise TypeError_(f"duplicate parameter {p!r} in fn {fn.name!r}", fn.pos)
            fsc.vars.add(p)
        if not fn.body or not isinstance(fn.body[-1], nodes.Return):
            raise TypeError_(f"fn {fn.name!r} must end with a `return` -- one exit, "
                             f"as the final statement", fn.pos)
        returns = _count_returns(fn.body)
        if returns != 1:
            raise TypeError_(f"fn {fn.name!r} has {returns} `return`s; exactly one is "
                             f"allowed, as the final statement", fn.pos)
        for s in fn.body:
            _check_stmt(s, fsc, ctx)

    # ---- recursion ban: the call graph must be acyclic ----
    _reject_recursion(fns)

    # ---- the main body ----
    sc = _Scope()
    for name in prog.inputs:
        if name in sc.vars or name in fns:
            raise TypeError_(f"duplicate input {name!r}", prog.pos)
        sc.vars.add(name)
    if prog.input_array is not None:
        ia = prog.input_array
        if ia.length <= 0:
            raise TypeError_(f"input array {ia.name!r} length must be > 0", ia.pos)
        sc.arrays[ia.name] = ia.length
    for arr in prog.arrays:
        if arr.name in sc.arrays or arr.name in sc.vars or arr.name in fns:
            raise TypeError_(f"array {arr.name!r} redeclares a name", arr.pos)
        if arr.length <= 0:
            raise TypeError_(f"array {arr.name!r} length must be > 0", arr.pos)
        sc.arrays[arr.name] = arr.length

    for s in prog.body:
        _check_stmt(s, sc, ctx)
    for e in prog.outputs:
        _check_expr(e, sc, ctx)
    if prog.steps is not None and prog.steps <= 0:
        raise TypeError_("#steps must be > 0", prog.pos)
    return prog


def _count_returns(stmts: tuple[nodes.Stmt, ...]) -> int:
    n = 0
    for s in stmts:
        if isinstance(s, nodes.Return):
            n += 1
        elif isinstance(s, nodes.If):
            n += _count_returns(s.then) + _count_returns(s.els)
        elif isinstance(s, (nodes.While, nodes.For)):
            n += _count_returns(s.body)
    return n


def _reject_recursion(fns: dict[str, nodes.FnDecl]) -> None:
    """DFS over the call graph; a back edge is recursion and is refused. Recursion has
    no lowering on a machine with no call stack, and banning it keeps inlining -- and
    the language -- total."""
    def calls_of(fn: nodes.FnDecl) -> set[str]:
        out: set[str] = set()

        def ex(e: nodes.Expr) -> None:
            if isinstance(e, nodes.Call):
                if e.fn in fns:
                    out.add(e.fn)
                for a in e.args:
                    ex(a)
            elif isinstance(e, nodes.Unary):
                ex(e.operand)
            elif isinstance(e, nodes.Binary):
                ex(e.left)
                ex(e.right)
            elif isinstance(e, nodes.Index):
                ex(e.index)

        def st(s: nodes.Stmt) -> None:
            if isinstance(s, (nodes.Let, nodes.Assign)):
                ex(s.expr)
            elif isinstance(s, nodes.StoreElem):
                ex(s.index)
                ex(s.value)
            elif isinstance(s, nodes.If):
                ex(s.cond)
                for t in s.then + s.els:
                    st(t)
            elif isinstance(s, nodes.While):
                ex(s.cond)
                for t in s.body:
                    st(t)
            elif isinstance(s, nodes.For):
                ex(s.lo)
                ex(s.hi)
                for t in s.body:
                    st(t)
            elif isinstance(s, nodes.Return):
                ex(s.expr)

        for s in fn.body:
            st(s)
        return out

    graph = {name: calls_of(fn) for name, fn in fns.items()}
    WHITE, GREY, BLACK = 0, 1, 2
    color = {n: WHITE for n in graph}

    def dfs(n: str, path: list[str]) -> None:
        color[n] = GREY
        for m in sorted(graph[n]):
            if color[m] == GREY:
                cyc = " -> ".join(path + [n, m])
                raise TypeError_(f"recursion is not allowed (no call stack on the "
                                 f"machine): {cyc}", fns[m].pos)
            if color[m] == WHITE:
                dfs(m, path + [n])
        color[n] = BLACK

    for n in sorted(graph):
        if color[n] == WHITE:
            dfs(n, [])


def _check_stmt(s: nodes.Stmt, sc: _Scope, ctx: _Ctx) -> None:
    if isinstance(s, nodes.Let):
        _check_expr(s.expr, sc, ctx)
        if s.name in sc.arrays:
            raise TypeError_(f"{s.name!r} is an array, not a scalar", s.pos)
        if s.name in ctx.fns:
            raise TypeError_(f"{s.name!r} is a function, not a scalar", s.pos)
        sc.vars.add(s.name)
    elif isinstance(s, nodes.Assign):
        if s.name not in sc.vars:
            raise TypeError_(f"assignment to undefined variable {s.name!r} "
                             f"(use `let {s.name} = ...` to introduce it)", s.pos)
        _check_expr(s.expr, sc, ctx)
    elif isinstance(s, nodes.StoreElem):
        if sc.in_fn is not None:
            raise TypeError_(f"fn {sc.in_fn!r} is closed: arrays are not accessible "
                             f"inside a function", s.pos)
        if s.array not in sc.arrays:
            raise TypeError_(f"{s.array!r} is not a declared array", s.pos)
        _check_expr(s.index, sc, ctx)
        _check_expr(s.value, sc, ctx)
    elif isinstance(s, nodes.If):
        _check_expr(s.cond, sc, ctx)
        for st in s.then:
            _check_stmt(st, sc, ctx)
        for st in s.els:
            _check_stmt(st, sc, ctx)
    elif isinstance(s, nodes.While):
        _check_expr(s.cond, sc, ctx)
        sc.loop_depth += 1
        for st in s.body:
            _check_stmt(st, sc, ctx)
        sc.loop_depth -= 1
    elif isinstance(s, nodes.For):
        _check_expr(s.lo, sc, ctx)
        _check_expr(s.hi, sc, ctx)
        if s.var in sc.arrays or s.var in ctx.fns:
            raise TypeError_(f"for-loop variable {s.var!r} redeclares a name", s.pos)
        sc.vars.add(s.var)
        sc.loop_depth += 1
        for st in s.body:
            _check_stmt(st, sc, ctx)
        sc.loop_depth -= 1
    elif isinstance(s, (nodes.Break, nodes.Continue)):
        if sc.loop_depth == 0:
            kw = "break" if isinstance(s, nodes.Break) else "continue"
            raise TypeError_(f"`{kw}` outside a loop", s.pos)
    elif isinstance(s, nodes.Return):
        if sc.in_fn is None:
            raise TypeError_("`return` outside a function", s.pos)
        _check_expr(s.expr, sc, ctx)
    else:  # pragma: no cover
        raise TypeError_(f"unknown statement {type(s).__name__}", s.pos)


def _check_expr(e: nodes.Expr, sc: _Scope, ctx: _Ctx) -> None:
    if isinstance(e, nodes.IntLit):
        if not (INT64_MIN <= e.value <= INT64_MAX):
            raise TypeError_(f"integer literal {e.value} does not fit in int64", e.pos)
    elif isinstance(e, nodes.Name):
        if e.ident not in sc.vars:
            if e.ident in sc.arrays:
                raise TypeError_(f"{e.ident!r} is an array; index it as {e.ident}[i]", e.pos)
            if e.ident in ctx.fns:
                raise TypeError_(f"{e.ident!r} is a function; call it as {e.ident}(...)", e.pos)
            where = f" (fn {sc.in_fn!r} is closed: only its parameters and own " \
                    f"`let`s are visible)" if sc.in_fn is not None else ""
            raise TypeError_(f"use of undefined variable {e.ident!r}{where}", e.pos)
    elif isinstance(e, nodes.Index):
        if sc.in_fn is not None:
            raise TypeError_(f"fn {sc.in_fn!r} is closed: arrays are not accessible "
                             f"inside a function", e.pos)
        if e.array not in sc.arrays:
            raise TypeError_(f"{e.array!r} is not a declared array", e.pos)
        _check_expr(e.index, sc, ctx)
    elif isinstance(e, nodes.Unary):
        _check_expr(e.operand, sc, ctx)
    elif isinstance(e, nodes.Binary):
        _check_expr(e.left, sc, ctx)
        _check_expr(e.right, sc, ctx)
    elif isinstance(e, nodes.Call):
        if e.fn in ctx.fns:
            fn = ctx.fns[e.fn]
            if len(e.args) != len(fn.params):
                raise TypeError_(f"{e.fn}() takes {len(fn.params)} argument(s), "
                                 f"got {len(e.args)}", e.pos)
            for a in e.args:
                _check_expr(a, sc, ctx)
            return
        if e.fn not in _ARITY:
            raise TypeError_(f"unknown function {e.fn!r}", e.pos)
        want = _ARITY[e.fn]
        if len(e.args) != want:
            raise TypeError_(f"{e.fn}() takes {want} argument(s), got {len(e.args)}", e.pos)
        if e.fn == "len":
            arg = e.args[0]
            if not isinstance(arg, nodes.Name) or arg.ident not in sc.arrays:
                raise TypeError_("len() takes a declared array", e.pos)
            return
        for a in e.args:
            _check_expr(a, sc, ctx)
        if e.fn == "mulfx":
            frac = e.args[2]
            if not isinstance(frac, nodes.IntLit):
                raise TypeError_("mulfx(x, y, F): F must be a literal (or const) number "
                                 "of fractional bits, not a computed value", e.pos)
            if not (0 <= frac.value <= 63):
                raise TypeError_(f"mulfx frac {frac.value} must be 0..63", e.pos)
    else:  # pragma: no cover
        raise TypeError_(f"unknown expression {type(e).__name__}", e.pos)
