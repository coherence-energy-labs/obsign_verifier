"""The abstract syntax tree for RL, the small language that compiles to a replay
program (`obsign/replay/1`).

RL exists for one reason: a replay program is hand-written int64 assembly today, and
a stranger who wants to trust their OWN number should not have to hand-allocate memory
cells and back-patch jump targets to get one. RL is a readable surface that lowers to
exactly that assembly -- and, because the compiler is standard-library-only and ships
in the public verifier, authoring a program needs no more of a private toolchain than
verifying one does. That is the circularity the replay VM's docstring calls out, closed
from the other side.

Every node carries a source position so the frontend, the typer and codegen can all
point at the exact character that is wrong. Nothing here evaluates or lowers anything;
the interpreter (interp.py) and codegen (codegen.py) each walk this tree, and the whole
correctness argument is that those two independent walks agree.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Pos:
    """A source position, 1-indexed line and column, for diagnostics."""
    line: int
    col: int

    def __str__(self) -> str:
        return f"{self.line}:{self.col}"


# --------------------------------------------------------------------------- expressions
class Expr:
    pos: Pos


@dataclass(frozen=True)
class IntLit(Expr):
    value: int          # a Python int; range-checked to int64 by the typer
    pos: Pos


@dataclass(frozen=True)
class Name(Expr):
    ident: str
    pos: Pos


@dataclass(frozen=True)
class Index(Expr):
    """`arr[expr]` -- an array element read, lowered with LOAD."""
    array: str
    index: Expr
    pos: Pos


@dataclass(frozen=True)
class Unary(Expr):
    op: str             # 'neg' | 'not'  (source '-x' / '~x')
    operand: Expr
    pos: Pos


@dataclass(frozen=True)
class Binary(Expr):
    op: str             # 'ADD','SUB','MUL','DIV','MOD','AND','OR','XOR','SHL','SHR',
                        # 'EQ','NE','LT','LE','GT','GE'  (VM opcode names, deliberately)
    left: Expr
    right: Expr
    pos: Pos


@dataclass(frozen=True)
class Call(Expr):
    """A builtin: min/max/abs/sel/mulfx. Kept as named intrinsics rather than
    operators so their lowering is unambiguous -- especially mulfx, whose fractional
    bits are a compile-time constant that becomes the MULFX immediate."""
    fn: str             # 'min'|'max'|'abs'|'sel'|'mulfx'
    args: tuple[Expr, ...]
    pos: Pos


# --------------------------------------------------------------------------- statements
class Stmt:
    pos: Pos


@dataclass(frozen=True)
class Let(Stmt):
    name: str
    expr: Expr
    pos: Pos


@dataclass(frozen=True)
class Assign(Stmt):
    name: str
    expr: Expr
    pos: Pos


@dataclass(frozen=True)
class StoreElem(Stmt):
    """`arr[index] = value` -- an array element write, lowered with STORE."""
    array: str
    index: Expr
    value: Expr
    pos: Pos


@dataclass(frozen=True)
class If(Stmt):
    cond: Expr
    then: tuple[Stmt, ...]
    els: tuple[Stmt, ...]        # empty tuple if no else
    pos: Pos


@dataclass(frozen=True)
class While(Stmt):
    cond: Expr
    body: tuple[Stmt, ...]
    pos: Pos


@dataclass(frozen=True)
class For(Stmt):
    """`for VAR in LO..HI { body }` -- VAR takes LO, LO+1, ..., HI-1 (upper-exclusive).

    Bounds are evaluated ONCE, before the first iteration. VAR is an ordinary scalar:
    the body may assign it and the assignment affects iteration, because both the
    machine (which increments the cell) and the interpreter (which re-reads the
    variable) see the same store."""
    var: str
    lo: Expr
    hi: Expr
    body: tuple[Stmt, ...]
    pos: Pos


@dataclass(frozen=True)
class Break(Stmt):
    pos: Pos


@dataclass(frozen=True)
class Continue(Stmt):
    pos: Pos


@dataclass(frozen=True)
class Return(Stmt):
    """Only inside a function, and only as its final statement (tail return)."""
    expr: Expr
    pos: Pos


@dataclass(frozen=True)
class FnDecl:
    """A CLOSED function: its body sees only its parameters and its own `let`s --
    no globals, no arrays, no inputs. That makes every call a pure int64 -> int64
    computation (traps aside), which is what lets the compiler inline it and the
    interpreter execute it natively as two independent lowerings of the same
    semantics. Recursion (direct or mutual) is rejected: totality by construction,
    the same property the machine itself is built on."""
    name: str
    params: tuple[str, ...]
    body: tuple[Stmt, ...]           # last statement is the Return
    pos: Pos


# --------------------------------------------------------------------------- program
@dataclass(frozen=True)
class ArrayDecl:
    name: str
    length: int                       # parser may hold an Expr; resolve() makes it int
    pos: Pos


@dataclass(frozen=True)
class Program:
    inputs: tuple[str, ...]          # scalar input names, in input-window order
    arrays: tuple[ArrayDecl, ...]
    body: tuple[Stmt, ...]
    outputs: tuple[Expr, ...]        # expressions, in output-window order
    steps: Optional[int] = None      # declared step budget (#steps pragma), or None
    input_array: Optional[ArrayDecl] = None   # `input xs[N];` -- the window as an array
    functions: tuple[FnDecl, ...] = ()
    consts: tuple[tuple[str, "Expr"], ...] = ()   # raw `const` decls; emptied by resolve()
    pos: Pos = field(default_factory=lambda: Pos(1, 1))
