"""Constant folding -- compile-side only, trap-preserving by construction.

This pass runs on the COMPILE path and never on the interpreter's: the oracle
evaluates the unfolded tree, so a folding bug is a divergence the differential suite
catches, not an error both sides share. That asymmetry is the whole safety argument
for having an optimizer inside a receipt compiler at all.

THE RULE THAT GOVERNS EVERY CASE HERE: folding may only replace an expression with the
value the machine would have computed, and only when the machine could not have TRAPPED
computing it. A constant `x / 0` is not an error to report at compile time -- it is a
trap to preserve at run time (the branch it sits on may never execute), so it is left
unfolded. Likewise `sel(1, a, b)` may only drop `b` when dropping it cannot remove a
trap: the machine evaluates both arms, so the discarded arm must be statically
trap-free (a literal or a plain variable read).

Arithmetic uses the VM's own primitives (_wrap, _trunc_div) -- the folder computes
exactly what the machine computes, bit for bit, including int64 wraparound.
"""
from __future__ import annotations

from ..replay import _trunc_div, _wrap
from . import nodes


def _lit(value: int, pos: nodes.Pos) -> nodes.IntLit:
    return nodes.IntLit(value, pos)


def _is_trap_free(e: nodes.Expr) -> bool:
    """Statically incapable of trapping: literals and plain scalar reads. Anything
    else (array index, division, shift, nested call) is treated as potentially
    trapping and therefore never discarded."""
    return isinstance(e, (nodes.IntLit, nodes.Name))


def fold_expr(e: nodes.Expr) -> nodes.Expr:
    if isinstance(e, (nodes.IntLit, nodes.Name)):
        return e

    if isinstance(e, nodes.Index):
        return nodes.Index(e.array, fold_expr(e.index), e.pos)

    if isinstance(e, nodes.Unary):
        x = fold_expr(e.operand)
        if isinstance(x, nodes.IntLit):
            if e.op == "neg":
                return _lit(_wrap(-x.value), e.pos)
            if e.op == "not":
                return _lit(_wrap(~x.value), e.pos)
        return nodes.Unary(e.op, x, e.pos)

    if isinstance(e, nodes.Binary):
        l, r = fold_expr(e.left), fold_expr(e.right)
        if isinstance(l, nodes.IntLit) and isinstance(r, nodes.IntLit):
            a, b = l.value, r.value
            op = e.op
            if op == "ADD":
                return _lit(_wrap(a + b), e.pos)
            if op == "SUB":
                return _lit(_wrap(a - b), e.pos)
            if op == "MUL":
                return _lit(_wrap(a * b), e.pos)
            if op == "DIV" and b != 0:
                return _lit(_wrap(_trunc_div(a, b)), e.pos)
            if op == "MOD" and b != 0:
                return _lit(_wrap(a - _trunc_div(a, b) * b), e.pos)
            if op == "AND":
                return _lit(_wrap(a & b), e.pos)
            if op == "OR":
                return _lit(_wrap(a | b), e.pos)
            if op == "XOR":
                return _lit(_wrap(a ^ b), e.pos)
            if op in ("SHL", "SHR") and 0 <= b <= 63:
                return _lit(_wrap(a << b) if op == "SHL" else _wrap(a >> b), e.pos)
            if op in ("EQ", "NE", "LT", "LE", "GT", "GE"):
                v = {"EQ": a == b, "NE": a != b, "LT": a < b,
                     "LE": a <= b, "GT": a > b, "GE": a >= b}[op]
                return _lit(int(v), e.pos)
            # DIV/MOD by constant zero, shift by constant out of range: the machine
            # traps here, so the expression survives to trap at run time.
        return nodes.Binary(e.op, l, r, e.pos)

    if isinstance(e, nodes.Call):
        args = tuple(fold_expr(a) for a in e.args)
        lits = [a.value for a in args if isinstance(a, nodes.IntLit)]
        all_lit = len(lits) == len(args)
        if e.fn == "min" and all_lit:
            return _lit(lits[0] if lits[0] < lits[1] else lits[1], e.pos)
        if e.fn == "max" and all_lit:
            return _lit(lits[0] if lits[0] > lits[1] else lits[1], e.pos)
        if e.fn == "abs" and all_lit:
            return _lit(_wrap(abs(lits[0])), e.pos)
        if e.fn == "mulfx" and all_lit:
            # frac is typer-guaranteed 0..63; exact product then truncate then wrap,
            # the machine's own order of operations
            return _lit(_wrap(_trunc_div(lits[0] * lits[1], 1 << lits[2])), e.pos)
        if e.fn == "sel" and isinstance(args[0], nodes.IntLit):
            taken = args[1] if args[0].value != 0 else args[2]
            dropped = args[2] if args[0].value != 0 else args[1]
            # the machine evaluates BOTH arms; dropping one may only happen when the
            # dropped arm could never have trapped
            if _is_trap_free(dropped):
                return taken
        return nodes.Call(e.fn, args, e.pos)

    return e  # pragma: no cover - exhaustive over the AST


def fold_stmt(s: nodes.Stmt) -> nodes.Stmt:
    if isinstance(s, nodes.Let):
        return nodes.Let(s.name, fold_expr(s.expr), s.pos)
    if isinstance(s, nodes.Assign):
        return nodes.Assign(s.name, fold_expr(s.expr), s.pos)
    if isinstance(s, nodes.StoreElem):
        return nodes.StoreElem(s.array, fold_expr(s.index), fold_expr(s.value), s.pos)
    if isinstance(s, nodes.If):
        # Branches are folded but never REMOVED, even on a constant condition: a `let`
        # in a dead branch still declares its cell, and the not-taken arm costs nothing
        # at run time anyway (it is jumped over).
        return nodes.If(fold_expr(s.cond),
                        tuple(fold_stmt(t) for t in s.then),
                        tuple(fold_stmt(t) for t in s.els), s.pos)
    if isinstance(s, nodes.While):
        return nodes.While(fold_expr(s.cond), tuple(fold_stmt(t) for t in s.body), s.pos)
    return s  # pragma: no cover


def fold_program(p: nodes.Program) -> nodes.Program:
    return nodes.Program(
        inputs=p.inputs,
        arrays=p.arrays,
        body=tuple(fold_stmt(s) for s in p.body),
        outputs=tuple(fold_expr(e) for e in p.outputs),
        steps=p.steps,
        input_array=p.input_array,
        pos=p.pos,
    )
