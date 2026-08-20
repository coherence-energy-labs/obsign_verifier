"""Inline every function call -- the compile path's lowering of functions.

The machine has no call stack, so functions cannot be lowered as calls; they are
inlined. The typer has already guaranteed everything that makes this terminate and
stay faithful: functions are CLOSED (a body reads only its parameters and own lets,
so splicing it anywhere cannot capture an outer name), the call graph is ACYCLIC (so
inlining bottoms out), and the single `return` is the body's final statement (so the
spliced body has one predictable place to bind its result).

The interpreter never sees this pass -- it executes calls natively in a fresh frame.
Two independent lowerings of the same semantics is the point: an inlining bug shows
up as a differential failure, not as an error both sides share.

MECHANICS. Functions are processed callees-first, so every body being spliced is
already call-free. At each call site:
  1. the argument expressions are evaluated ONCE each, in order, into fresh `let`s
     (exactly the interpreter's call-by-value order, traps included);
  2. the body is spliced with every parameter and local renamed to a fresh
     `__inl<n>_` name -- collision-proof because `__` names cannot be written in
     source (the lexer accepts them, but the namespace is reserved by construction:
     nothing else generates them);
  3. the tail `return e` becomes a `let` of the result variable, and the call
     expression is replaced by a read of it.

Because a call can sit anywhere an expression can, statements are rewritten to hoist
the generated `let`s in front of the statement that contained the call. Two positions
need care, and each is pinned by a test:
  * a WHILE condition re-evaluates every iteration, so its hoisted work must re-run
    every iteration too: the loop is rewritten to `while 1 { <hoisted>; if cond {}
    else { break; } <body> }`, which the machine executes with the same trap and
    value behaviour;
  * FOR bounds are evaluated once, so their hoisted work runs once, before the loop.
"""
from __future__ import annotations

from . import nodes
from .nodes import Pos


class _Inliner:
    def __init__(self, prog: nodes.Program):
        self.prog = prog
        self._n = 0
        # callees-first: inline each body's own calls before it is ever spliced
        self.flat: dict[str, nodes.FnDecl] = {}
        for fn in self._topo(prog.functions):
            body = self._rewrite_block(fn.body)
            self.flat[fn.name] = nodes.FnDecl(fn.name, fn.params, body, fn.pos)

    def _topo(self, fns: tuple[nodes.FnDecl, ...]) -> list[nodes.FnDecl]:
        by_name = {f.name: f for f in fns}
        done: dict[str, nodes.FnDecl] = {}
        order: list[nodes.FnDecl] = []

        def visit(fn: nodes.FnDecl) -> None:
            if fn.name in done:
                return
            done[fn.name] = fn
            for callee in sorted(self._callees(fn.body, by_name)):
                visit(by_name[callee])
            order.append(fn)

        for fn in fns:
            visit(fn)
        return order

    def _callees(self, stmts, by_name) -> set[str]:
        out: set[str] = set()

        def ex(e):
            if isinstance(e, nodes.Call):
                if e.fn in by_name:
                    out.add(e.fn)
                for a in e.args:
                    ex(a)
            elif isinstance(e, nodes.Unary):
                ex(e.operand)
            elif isinstance(e, nodes.Binary):
                ex(e.left), ex(e.right)
            elif isinstance(e, nodes.Index):
                ex(e.index)

        def st(s):
            if isinstance(s, (nodes.Let, nodes.Assign)):
                ex(s.expr)
            elif isinstance(s, nodes.StoreElem):
                ex(s.index), ex(s.value)
            elif isinstance(s, nodes.If):
                ex(s.cond)
                for t in s.then + s.els:
                    st(t)
            elif isinstance(s, (nodes.While,)):
                ex(s.cond)
                for t in s.body:
                    st(t)
            elif isinstance(s, nodes.For):
                ex(s.lo), ex(s.hi)
                for t in s.body:
                    st(t)
            elif isinstance(s, nodes.Return):
                ex(s.expr)

        for s in stmts:
            st(s)
        return out

    # ---- fresh names ----
    def _fresh(self, base: str) -> str:
        self._n += 1
        return f"__inl{self._n}_{base}"

    # ---- expression rewriting: hoist calls into pre-statements ----
    def _rw_expr(self, e: nodes.Expr) -> tuple[list[nodes.Stmt], nodes.Expr]:
        if isinstance(e, (nodes.IntLit, nodes.Name)):
            return [], e
        if isinstance(e, nodes.Index):
            pre, idx = self._rw_expr(e.index)
            return pre, nodes.Index(e.array, idx, e.pos)
        if isinstance(e, nodes.Unary):
            pre, x = self._rw_expr(e.operand)
            return pre, nodes.Unary(e.op, x, e.pos)
        if isinstance(e, nodes.Binary):
            pl, l = self._rw_expr(e.left)
            pr, r = self._rw_expr(e.right)
            return pl + pr, nodes.Binary(e.op, l, r, e.pos)
        if isinstance(e, nodes.Call):
            pres: list[nodes.Stmt] = []
            args: list[nodes.Expr] = []
            for a in e.args:
                pa, a2 = self._rw_expr(a)
                pres += pa
                args.append(a2)
            if e.fn not in self.flat:
                return pres, nodes.Call(e.fn, tuple(args), e.pos)
            return self._splice(self.flat[e.fn], args, pres, e.pos)
        return [], e  # pragma: no cover

    def _splice(self, fn: nodes.FnDecl, args: list[nodes.Expr],
                pres: list[nodes.Stmt], pos: Pos) -> tuple[list[nodes.Stmt], nodes.Expr]:
        rename: dict[str, str] = {}
        for p, a in zip(fn.params, args):
            rename[p] = self._fresh(p)
            pres.append(nodes.Let(rename[p], a, pos))
        for name in _locals_of(fn.body):
            rename.setdefault(name, self._fresh(name))
        ret = self._fresh("ret")
        for s in fn.body[:-1]:
            pres.append(_rename_stmt(s, rename))
        tail = fn.body[-1]
        assert isinstance(tail, nodes.Return)   # typer guarantees
        pres.append(nodes.Let(ret, _rename_expr(tail.expr, rename), pos))
        return pres, nodes.Name(ret, pos)

    # ---- statement rewriting ----
    def _rewrite_block(self, stmts: tuple[nodes.Stmt, ...]) -> tuple[nodes.Stmt, ...]:
        out: list[nodes.Stmt] = []
        for s in stmts:
            out.extend(self._rw_stmt(s))
        return tuple(out)

    def _rw_stmt(self, s: nodes.Stmt) -> list[nodes.Stmt]:
        if isinstance(s, nodes.Let):
            pre, e = self._rw_expr(s.expr)
            return pre + [nodes.Let(s.name, e, s.pos)]
        if isinstance(s, nodes.Assign):
            pre, e = self._rw_expr(s.expr)
            return pre + [nodes.Assign(s.name, e, s.pos)]
        if isinstance(s, nodes.StoreElem):
            pi, idx = self._rw_expr(s.index)
            pv, val = self._rw_expr(s.value)
            return pi + pv + [nodes.StoreElem(s.array, idx, val, s.pos)]
        if isinstance(s, nodes.If):
            pre, cond = self._rw_expr(s.cond)
            return pre + [nodes.If(cond, self._rewrite_block(s.then),
                                   self._rewrite_block(s.els), s.pos)]
        if isinstance(s, nodes.While):
            pre, cond = self._rw_expr(s.cond)
            body = self._rewrite_block(s.body)
            if not pre:
                return [nodes.While(cond, body, s.pos)]
            # The condition contains a call, and a while condition re-evaluates every
            # iteration -- so its hoisted work must re-run every iteration. Rewrite to
            # an unconditional loop whose first act is the hoisted work and a
            # conditional break. Value- and trap-equivalent to re-evaluating the call.
            guard = nodes.If(cond, (), (nodes.Break(s.pos),), s.pos)
            return [nodes.While(nodes.IntLit(1, s.pos),
                                tuple(pre) + (guard,) + body, s.pos)]
        if isinstance(s, nodes.For):
            pl, lo = self._rw_expr(s.lo)
            ph, hi = self._rw_expr(s.hi)
            # for-bounds are evaluated once, so their hoisted work runs once, before
            return pl + ph + [nodes.For(s.var, lo, hi, self._rewrite_block(s.body), s.pos)]
        if isinstance(s, nodes.Return):
            pre, e = self._rw_expr(s.expr)
            return pre + [nodes.Return(e, s.pos)]
        return [s]   # Break / Continue


def _locals_of(stmts) -> list[str]:
    out: list[str] = []

    def st(s):
        if isinstance(s, nodes.Let):
            if s.name not in out:
                out.append(s.name)
        elif isinstance(s, nodes.If):
            for t in s.then + s.els:
                st(t)
        elif isinstance(s, nodes.While):
            for t in s.body:
                st(t)
        elif isinstance(s, nodes.For):
            if s.var not in out:
                out.append(s.var)
            for t in s.body:
                st(t)

    for s in stmts:
        st(s)
    return out


def _rename_expr(e: nodes.Expr, m: dict[str, str]) -> nodes.Expr:
    if isinstance(e, nodes.Name):
        return nodes.Name(m.get(e.ident, e.ident), e.pos)
    if isinstance(e, nodes.IntLit):
        return e
    if isinstance(e, nodes.Index):
        return nodes.Index(e.array, _rename_expr(e.index, m), e.pos)
    if isinstance(e, nodes.Unary):
        return nodes.Unary(e.op, _rename_expr(e.operand, m), e.pos)
    if isinstance(e, nodes.Binary):
        return nodes.Binary(e.op, _rename_expr(e.left, m), _rename_expr(e.right, m), e.pos)
    if isinstance(e, nodes.Call):
        return nodes.Call(e.fn, tuple(_rename_expr(a, m) for a in e.args), e.pos)
    return e  # pragma: no cover


def _rename_stmt(s: nodes.Stmt, m: dict[str, str]) -> nodes.Stmt:
    if isinstance(s, nodes.Let):
        return nodes.Let(m.get(s.name, s.name), _rename_expr(s.expr, m), s.pos)
    if isinstance(s, nodes.Assign):
        return nodes.Assign(m.get(s.name, s.name), _rename_expr(s.expr, m), s.pos)
    if isinstance(s, nodes.StoreElem):  # pragma: no cover - fns are closed, no arrays
        return nodes.StoreElem(s.array, _rename_expr(s.index, m), _rename_expr(s.value, m), s.pos)
    if isinstance(s, nodes.If):
        return nodes.If(_rename_expr(s.cond, m),
                        tuple(_rename_stmt(t, m) for t in s.then),
                        tuple(_rename_stmt(t, m) for t in s.els), s.pos)
    if isinstance(s, nodes.While):
        return nodes.While(_rename_expr(s.cond, m),
                           tuple(_rename_stmt(t, m) for t in s.body), s.pos)
    if isinstance(s, nodes.For):
        return nodes.For(m.get(s.var, s.var), _rename_expr(s.lo, m), _rename_expr(s.hi, m),
                         tuple(_rename_stmt(t, m) for t in s.body), s.pos)
    if isinstance(s, nodes.Return):
        return nodes.Return(_rename_expr(s.expr, m), s.pos)
    return s   # Break / Continue


def inline_program(prog: nodes.Program) -> nodes.Program:
    """Return an equivalent, call-free Program (functions=())."""
    if not prog.functions:
        return prog
    inl = _Inliner(prog)
    body = list(inl._rewrite_block(prog.body))
    # outputs may contain calls too; their hoisted work is appended to the body,
    # which runs immediately before the outputs are written -- the same point at
    # which the interpreter evaluates them
    outs: list[nodes.Expr] = []
    for e in prog.outputs:
        pre, e2 = inl._rw_expr(e)
        body += pre
        outs.append(e2)
    return nodes.Program(
        inputs=prog.inputs,
        arrays=prog.arrays,
        body=tuple(body),
        outputs=tuple(outs),
        steps=prog.steps,
        input_array=prog.input_array,
        functions=(),
        consts=(),
        pos=prog.pos,
    )
