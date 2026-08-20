"""Static checks over the AST, before codegen sees it.

Codegen is allowed to be simple because everything that could make it emit a
malformed program is rejected here first: an unknown name, a builtin called with the
wrong arity, a `mulfx` whose fractional count is not a compile-time constant in
0..63, an integer literal that does not fit int64, a write to something that is not a
declared array. By the time codegen runs, every Name resolves, every array is known,
and every mulfx immediate is a literal -- so codegen never has to decide what to do
about a broken tree.

This is name/shape checking, not a value analysis: whether a shift amount or an array
index is in range depends on the inputs and is enforced by the machine at run time as
a Trap. The typer proves the program is well-FORMED; the VM keeps it total.
"""
from __future__ import annotations

from ..replay import INT64_MAX, INT64_MIN
from . import nodes
from .nodes import Pos

_ARITY = {"min": 2, "max": 2, "abs": 1, "sel": 3, "mulfx": 3}


class TypeError_(Exception):
    """A well-formedness error with a source position."""

    def __init__(self, msg: str, pos: Pos):
        super().__init__(f"{pos}: {msg}")
        self.pos = pos


class _Scope:
    def __init__(self) -> None:
        self.vars: set[str] = set()
        self.arrays: dict[str, int] = {}


def check(prog: nodes.Program) -> nodes.Program:
    sc = _Scope()

    # inputs first; duplicate names would silently alias one memory cell
    for name in prog.inputs:
        if name in sc.vars:
            raise TypeError_(f"duplicate input {name!r}", prog.pos)
        sc.vars.add(name)
    if prog.input_array is not None:
        ia = prog.input_array
        if ia.length <= 0:
            raise TypeError_(f"input array {ia.name!r} length must be > 0", ia.pos)
        sc.arrays[ia.name] = ia.length
    for arr in prog.arrays:
        if arr.name in sc.arrays or arr.name in sc.vars:
            raise TypeError_(f"array {arr.name!r} redeclares a name", arr.pos)
        if arr.length <= 0:
            raise TypeError_(f"array {arr.name!r} length must be > 0", arr.pos)
        sc.arrays[arr.name] = arr.length

    for s in prog.body:
        _check_stmt(s, sc)
    for e in prog.outputs:
        _check_expr(e, sc)
    if prog.steps is not None and prog.steps <= 0:
        raise TypeError_("#steps must be > 0", prog.pos)
    return prog


def _check_stmt(s: nodes.Stmt, sc: _Scope) -> None:
    if isinstance(s, nodes.Let):
        _check_expr(s.expr, sc)
        # a `let` may shadow-redefine; both resolve to the same cell in codegen, which
        # is the intended "reassign" behaviour -- but it must not collide with an array.
        if s.name in sc.arrays:
            raise TypeError_(f"{s.name!r} is an array, not a scalar", s.pos)
        sc.vars.add(s.name)
    elif isinstance(s, nodes.Assign):
        if s.name not in sc.vars:
            raise TypeError_(f"assignment to undefined variable {s.name!r} "
                             f"(use `let {s.name} = ...` to introduce it)", s.pos)
        _check_expr(s.expr, sc)
    elif isinstance(s, nodes.StoreElem):
        if s.array not in sc.arrays:
            raise TypeError_(f"{s.array!r} is not a declared array", s.pos)
        _check_expr(s.index, sc)
        _check_expr(s.value, sc)
    elif isinstance(s, nodes.If):
        _check_expr(s.cond, sc)
        for st in s.then:
            _check_stmt(st, sc)
        for st in s.els:
            _check_stmt(st, sc)
    elif isinstance(s, nodes.While):
        _check_expr(s.cond, sc)
        for st in s.body:
            _check_stmt(st, sc)
    else:  # pragma: no cover
        raise TypeError_(f"unknown statement {type(s).__name__}", s.pos)


def _check_expr(e: nodes.Expr, sc: _Scope) -> None:
    if isinstance(e, nodes.IntLit):
        if not (INT64_MIN <= e.value <= INT64_MAX):
            raise TypeError_(f"integer literal {e.value} does not fit in int64", e.pos)
    elif isinstance(e, nodes.Name):
        if e.ident not in sc.vars:
            if e.ident in sc.arrays:
                raise TypeError_(f"{e.ident!r} is an array; index it as {e.ident}[i]", e.pos)
            raise TypeError_(f"use of undefined variable {e.ident!r}", e.pos)
    elif isinstance(e, nodes.Index):
        if e.array not in sc.arrays:
            raise TypeError_(f"{e.array!r} is not a declared array", e.pos)
        _check_expr(e.index, sc)
    elif isinstance(e, nodes.Unary):
        _check_expr(e.operand, sc)
    elif isinstance(e, nodes.Binary):
        _check_expr(e.left, sc)
        _check_expr(e.right, sc)
    elif isinstance(e, nodes.Call):
        want = _ARITY[e.fn]
        if len(e.args) != want:
            raise TypeError_(f"{e.fn}() takes {want} argument(s), got {len(e.args)}", e.pos)
        for a in e.args:
            _check_expr(a, sc)
        if e.fn == "mulfx":
            frac = e.args[2]
            # The fractional count is the MULFX immediate; it must be knowable at
            # compile time. A register-valued shift would be a different instruction
            # the machine does not have.
            if not isinstance(frac, nodes.IntLit):
                raise TypeError_("mulfx(x, y, F): F must be a literal number of "
                                 "fractional bits, not a computed value", e.pos)
            if not (0 <= frac.value <= 63):
                raise TypeError_(f"mulfx frac {frac.value} must be 0..63", e.pos)
    else:  # pragma: no cover
        raise TypeError_(f"unknown expression {type(e).__name__}", e.pos)
