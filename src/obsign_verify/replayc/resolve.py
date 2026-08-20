"""Resolve `const` declarations and constant-expression array lengths.

This pass is the ONE piece of lowering both the compile path and the interpreter
share, because it decides facts they must agree on before either runs: the value of
every named constant and the concrete length of every array. Everything downstream --
folding, inlining, code generation on one side; direct evaluation on the other -- stays
split, which is what keeps the differential suite meaningful. The pass itself is plain
substitution and is pinned by its own tests.

Rules:
  * a `const NAME = expr;` is evaluated in declaration order; its expression may use
    only literals and previously declared consts (no inputs, no variables -- a constant
    that depends on run-time data is not a constant);
  * const names are substituted as literals everywhere they are READ -- including
    inside function bodies, except where a function's own parameter or `let` shadows
    the name is REJECTED instead: a binding that collides with a const is almost
    certainly a bug, so it refuses rather than silently shadowing;
  * array lengths (`arr xs[N]`, `input v[N]`) must reduce to an int64 literal.
"""
from __future__ import annotations

from . import nodes
from .fold import fold_expr
from .nodes import Pos


class ResolveError(Exception):
    def __init__(self, msg: str, pos: Pos):
        super().__init__(f"{pos}: {msg}")
        self.pos = pos


def _subst_expr(e: nodes.Expr, env: dict[str, int]) -> nodes.Expr:
    if isinstance(e, nodes.Name):
        if e.ident in env:
            return nodes.IntLit(env[e.ident], e.pos)
        return e
    if isinstance(e, nodes.IntLit):
        return e
    if isinstance(e, nodes.Index):
        return nodes.Index(e.array, _subst_expr(e.index, env), e.pos)
    if isinstance(e, nodes.Unary):
        return nodes.Unary(e.op, _subst_expr(e.operand, env), e.pos)
    if isinstance(e, nodes.Binary):
        return nodes.Binary(e.op, _subst_expr(e.left, env), _subst_expr(e.right, env), e.pos)
    if isinstance(e, nodes.Call):
        return nodes.Call(e.fn, tuple(_subst_expr(a, env) for a in e.args), e.pos)
    return e  # pragma: no cover


def _subst_stmt(s: nodes.Stmt, env: dict[str, int]) -> nodes.Stmt:
    if isinstance(s, nodes.Let):
        _no_collision(s.name, env, s.pos, "let")
        return nodes.Let(s.name, _subst_expr(s.expr, env), s.pos, s.scale)
    if isinstance(s, nodes.Assign):
        _no_collision(s.name, env, s.pos, "assignment target")
        return nodes.Assign(s.name, _subst_expr(s.expr, env), s.pos)
    if isinstance(s, nodes.StoreElem):
        return nodes.StoreElem(s.array, _subst_expr(s.index, env), _subst_expr(s.value, env), s.pos)
    if isinstance(s, nodes.If):
        return nodes.If(_subst_expr(s.cond, env),
                        tuple(_subst_stmt(t, env) for t in s.then),
                        tuple(_subst_stmt(t, env) for t in s.els), s.pos)
    if isinstance(s, nodes.While):
        return nodes.While(_subst_expr(s.cond, env),
                           tuple(_subst_stmt(t, env) for t in s.body), s.pos)
    if isinstance(s, nodes.For):
        _no_collision(s.var, env, s.pos, "for-loop variable")
        return nodes.For(s.var, _subst_expr(s.lo, env), _subst_expr(s.hi, env),
                         tuple(_subst_stmt(t, env) for t in s.body), s.pos)
    if isinstance(s, nodes.Return):
        return nodes.Return(_subst_expr(s.expr, env), s.pos)
    return s   # Break / Continue


def _no_collision(name: str, env: dict[str, int], pos: Pos, what: str) -> None:
    if name in env:
        raise ResolveError(
            f"{what} {name!r} collides with a `const` of the same name -- a binding "
            f"that shadows a constant is almost certainly a bug, so it is refused", pos)


def _const_value(e: nodes.Expr, env: dict[str, int], pos: Pos, what: str) -> int:
    folded = fold_expr(_subst_expr(e, env))
    if not isinstance(folded, nodes.IntLit):
        raise ResolveError(
            f"{what} must reduce to an integer constant at compile time "
            f"(literals, previously declared consts, and operators over them)", pos)
    return folded.value


def resolve(prog: nodes.Program) -> nodes.Program:
    """Return an equivalent Program with consts substituted and lengths concrete."""
    env: dict[str, int] = {}
    for name, expr in prog.consts:
        if name in env:
            raise ResolveError(f"duplicate const {name!r}", prog.pos)
        env[name] = _const_value(expr, env, prog.pos, f"const {name!r}")

    def _decl(a: nodes.ArrayDecl) -> nodes.ArrayDecl:
        _no_collision(a.name, env, a.pos, "array")
        if isinstance(a.length, int):
            return a
        return nodes.ArrayDecl(a.name, _const_value(a.length, env, a.pos,
                                                    f"length of array {a.name!r}"),
                               a.pos, a.scale)

    for name in prog.inputs:
        _no_collision(name, env, prog.pos, "input")

    functions = []
    for fn in prog.functions:
        _no_collision(fn.name, env, fn.pos, "function")
        for p in fn.params:
            _no_collision(p, env, fn.pos, f"parameter of fn {fn.name!r}")
        functions.append(nodes.FnDecl(fn.name, fn.params,
                                      tuple(_subst_stmt(s, env) for s in fn.body),
                                      fn.pos, fn.param_scales))

    return nodes.Program(
        inputs=prog.inputs,
        arrays=tuple(_decl(a) for a in prog.arrays),
        body=tuple(_subst_stmt(s, env) for s in prog.body),
        outputs=tuple(_subst_expr(e, env) for e in prog.outputs),
        steps=prog.steps,
        input_array=_decl(prog.input_array) if prog.input_array is not None else None,
        functions=tuple(functions),
        consts=(),
        input_scales=prog.input_scales,
        pos=prog.pos,
    )
