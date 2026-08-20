"""Lexer and parser: RL source text -> AST.

The grammar is deliberately tiny and C-flavoured. There are NO floating-point
literals -- the machine has no float, so neither does its language, and a `1.5` in
source is a syntax error rather than a silent rounding. Fixed-point is written
explicitly with `mulfx(x, y, F)`, whose F is a literal number of fractional bits.

  program   := pragma? item*
  pragma    := '#steps' INT
  item      := input | array | output | stmt
  input     := 'input' IDENT (',' IDENT)* ';'
  array     := 'arr' IDENT '[' INT ']' ';'
  output    := 'output' expr (',' expr)* ';'
  stmt      := 'let' IDENT '=' expr ';'
             | IDENT '=' expr ';'
             | IDENT '[' expr ']' '=' expr ';'
             | 'if' expr block ('else' block)?
             | 'while' expr block
  block     := '{' stmt* '}'
  expr      := bitor
  bitor     := bitxor ('|' bitxor)*
  bitxor    := bitand ('^' bitand)*
  bitand    := equality ('&' equality)*
  equality  := relational (('=='|'!=') relational)*
  relational:= shift (('<'|'<='|'>'|'>=') shift)*
  shift     := additive (('<<'|'>>') additive)*
  additive  := multiplicative (('+'|'-') multiplicative)*
  multiplicative := unary (('*'|'/'|'%') unary)*
  unary     := ('-'|'~') unary | primary
  primary   := INT | IDENT | IDENT '[' expr ']' | builtin '(' args ')' | '(' expr ')'
  builtin   := 'min'|'max'|'abs'|'sel'|'mulfx'

Comparisons yield 0 or 1, so boolean logic is bitwise (`a < b & c < d`); there is no
short-circuit operator, because short-circuit is control flow and the machine already
spells control flow `if`.

SCALARS ARE ZERO UNTIL ASSIGNED. There is no block scoping: a `let` anywhere is visible
for the rest of the program, and a scalar reads 0 until it is assigned on the path that
actually runs. This is not a convenience -- it is the machine's own behaviour, whose
memory starts zeroed, made a language rule so the compiled program and the reference
interpreter cannot disagree about a variable written only inside a branch that did not
execute. (A name that is never declared at all is still a compile error.)
"""
from __future__ import annotations

import re
from typing import NoReturn

from . import nodes
from .nodes import Pos

#: CPython's own decimal-conversion limit, so a literal this lexer accepts is a
#: literal every implementation can convert.
MAX_INT_DIGITS = 4300
INT64_MIN, INT64_MAX = -(1 << 63), (1 << 63) - 1

KEYWORDS = {"input", "output", "let", "if", "else", "while", "arr",
            "fn", "return", "for", "in", "break", "continue", "const"}
BUILTINS = {"min", "max", "abs", "sel", "mulfx", "len"}

# Longest-match first so '<<' beats '<' and '<=' beats '<'.
_SYMBOLS = ["<<", ">>", "<=", ">=", "==", "!=", "..", "|", "^", "&", "<", ">",
            "+", "-", "*", "/", "%", "~", "=", "(", ")", "[", "]", "{", "}", ",", ";", ":"]


class ParseError(Exception):
    """A syntax error with a source position. Never escapes compile() as anything
    else -- a malformed program is a refusal with a reason, like everything here."""

    def __init__(self, msg: str, pos: Pos):
        super().__init__(f"{pos}: {msg}")
        self.pos = pos


class _Tok:
    __slots__ = ("kind", "text", "value", "pos")

    def __init__(self, kind: str, text: str, pos: Pos, value: int | None = None):
        self.kind = kind      # 'int' | 'ident' | 'kw' | 'builtin' | 'sym' | 'pragma' | 'eof'
        self.text = text
        self.value = value
        self.pos = pos

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Tok({self.kind},{self.text!r}@{self.pos})"


def lex(src: str) -> list[_Tok]:
    toks: list[_Tok] = []
    line, col, i, n = 1, 1, 0, len(src)

    def adv(k: int) -> None:
        nonlocal i, line, col
        for _ in range(k):
            if src[i] == "\n":
                line += 1
                col = 1
            else:
                col += 1
            i += 1

    while i < n:
        c = src[i]
        if c in " \t\r\n":
            adv(1)
            continue
        if src.startswith("//", i):                      # line comment
            while i < n and src[i] != "\n":
                adv(1)
            continue
        pos = Pos(line, col)
        if src.startswith("#steps", i):
            adv(len("#steps"))
            toks.append(_Tok("pragma", "#steps", pos))
            continue
        # `c.isdigit()` is true for Unicode digits the ASCII pattern below cannot
        # match -- Arabic-Indic, superscripts, circled numerals -- so the gate and
        # the pattern disagreed and `m` came back None. `m.group(0)` then raised
        # AttributeError straight past the caller, and a compiler that crashes on
        # hostile source has failed to REFUSE it: an auditor gets a traceback where
        # a diagnostic belongs.
        if c.isdigit():
            m = re.match(r"0[xX][0-9a-fA-F][0-9a-fA-F_]*|[0-9][0-9_]*", src[i:])
            if m is None:
                raise ParseError(f"unexpected character {c!r}: numbers must be ASCII", pos)
            text = m.group(0)
            base = 16 if text[:2].lower() == "0x" else 10
            digits = text.replace("_", "")
            # CPython refuses to convert a decimal literal longer than 4300 digits
            # and the ValueError escapes with no position. Refuse it ourselves,
            # with one. Hex has no such conversion limit on the way IN, which is how
            # an unbounded integer reached three `raise` statements that interpolate
            # it into their own diagnostic and fall over there instead.
            if len(digits) > MAX_INT_DIGITS:
                raise ParseError(
                    f"integer literal has {len(digits)} digits, limit is {MAX_INT_DIGITS}", pos)
            # The int64 RANGE check stays in the typer, where it already lived and
            # where its diagnostic is written. Only the conversion limit belongs
            # here, because that one crashes before any later stage can speak.
            value = int(digits, base)
            toks.append(_Tok("int", text, pos, value))
            adv(len(text))
            continue
        # Same disagreement in the other direction: `isalpha()` admits every
        # Unicode letter while the pattern accepts ASCII only.
        if c.isalpha() or c == "_":
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", src[i:])
            if m is None:
                raise ParseError(
                    f"unexpected character {c!r}: identifiers must be ASCII", pos)
            text = m.group(0)
            kind = "kw" if text in KEYWORDS else "builtin" if text in BUILTINS else "ident"
            toks.append(_Tok(kind, text, pos))
            adv(len(text))
            continue
        for sym in _SYMBOLS:
            if src.startswith(sym, i):
                toks.append(_Tok("sym", sym, pos))
                adv(len(sym))
                break
        else:
            raise ParseError(f"unexpected character {c!r}", pos)
    toks.append(_Tok("eof", "", Pos(line, col)))
    return toks


# comparison / bitwise op text -> VM opcode name used in the AST
_BINOP = {"|": "OR", "^": "XOR", "&": "AND", "==": "EQ", "!=": "NE",
          "<": "LT", "<=": "LE", ">": "GT", ">=": "GE", "<<": "SHL", ">>": "SHR",
          "+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV", "%": "MOD"}


class Parser:
    def __init__(self, toks: list[_Tok]):
        self.toks = toks
        self.i = 0

    # ---- token helpers ----
    def _peek(self) -> _Tok:
        return self.toks[self.i]

    def _next(self) -> _Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def _at(self, kind: str, text: str | None = None) -> bool:
        t = self._peek()
        return t.kind == kind and (text is None or t.text == text)

    def _eat(self, kind: str, text: str | None = None) -> _Tok:
        t = self._peek()
        if t.kind != kind or (text is not None and t.text != text):
            want = text if text is not None else kind
            self._err(f"expected {want!r}, got {t.text or t.kind!r}")
        return self._next()

    def _err(self, msg: str) -> NoReturn:
        raise ParseError(msg, self._peek().pos)

    # ---- program ----
    def parse(self) -> nodes.Program:
        steps = None
        if self._at("pragma"):
            self._next()
            steps = self._eat("int").value
        inputs: list[str] = []
        arrays: list[nodes.ArrayDecl] = []
        outputs: list[nodes.Expr] = []
        body: list[nodes.Stmt] = []
        functions: list[nodes.FnDecl] = []
        consts: list[tuple[str, nodes.Expr]] = []
        input_array: nodes.ArrayDecl | None = None
        self.input_scales: list[int | None] = []
        seen_output = False
        while not self._at("eof"):
            if self._at("kw", "input"):
                if body or inputs or input_array is not None:
                    self._err("`input` must be declared once, before any statement")
                input_array = self._parse_input(inputs)
            elif self._at("kw", "arr"):
                arrays.append(self._parse_array())
            elif self._at("kw", "fn"):
                functions.append(self._parse_fn())
            elif self._at("kw", "const"):
                t = self._next()
                name = self._eat("ident").text
                self._eat("sym", "=")
                consts.append((name, self._parse_expr()))
                self._eat("sym", ";")
            elif self._at("kw", "output"):
                self._parse_output(outputs)
                seen_output = True
            else:
                if seen_output:
                    self._err("no statements may follow `output`")
                body.append(self._parse_stmt())
        if not outputs:
            self._err("program has no `output` -- a receipt with nothing to hash is a collision")
        pos = self.toks[0].pos
        return nodes.Program(tuple(inputs), tuple(arrays), tuple(body), tuple(outputs),
                             steps, input_array, tuple(functions), tuple(consts),
                             tuple(self.input_scales), pos)

    def _parse_fn(self) -> nodes.FnDecl:
        t = self._eat("kw", "fn")
        name = self._eat("ident").text
        self._eat("sym", "(")
        params: list[str] = []
        pscales: list[int | None] = []
        if not self._at("sym", ")"):
            params.append(self._eat("ident").text)
            pscales.append(self._parse_scale())
            while self._at("sym", ","):
                self._next()
                params.append(self._eat("ident").text)
                pscales.append(self._parse_scale())
        self._eat("sym", ")")
        body = self._parse_block()
        return nodes.FnDecl(name, tuple(params), body, t.pos, tuple(pscales))

    def _parse_scale(self) -> int | None:
        """An optional `: fxN` fixed-point scale annotation, N in 0..63. fx0 is a
        deliberate spelling for "definitely a plain integer" -- it differs from no
        annotation, which means "unknown, compatible with anything"."""
        if not self._at("sym", ":"):
            return None
        self._next()
        t = self._eat("ident")
        m = re.fullmatch(r"fx([0-9]+)", t.text)
        if not m or int(m.group(1)) > 63:
            raise ParseError(f"scale annotation must be fx0..fx63, got {t.text!r}", t.pos)
        return int(m.group(1))

    def _parse_input(self, inputs: list[str]) -> nodes.ArrayDecl | None:
        """Either `input a, b, c;` (scalars) or `input xs[N];` (the window as an array).
        The length may be any const-expression; resolve() reduces it to an int."""
        self._eat("kw", "input")
        first = self._eat("ident")
        if self._at("sym", "["):
            self._next()
            length = self._parse_expr()
            self._eat("sym", "]")
            scale = self._parse_scale()
            self._eat("sym", ";")
            return nodes.ArrayDecl(first.text, length, first.pos, scale)
        inputs.append(first.text)
        self.input_scales.append(self._parse_scale())
        while self._at("sym", ","):
            self._next()
            inputs.append(self._eat("ident").text)
            self.input_scales.append(self._parse_scale())
        self._eat("sym", ";")
        return None

    def _parse_array(self) -> nodes.ArrayDecl:
        t = self._eat("kw", "arr")
        name = self._eat("ident").text
        self._eat("sym", "[")
        length = self._parse_expr()      # a const-expression; resolve() makes it an int
        self._eat("sym", "]")
        scale = self._parse_scale()
        self._eat("sym", ";")
        return nodes.ArrayDecl(name, length, t.pos, scale)

    def _parse_output(self, outputs: list[nodes.Expr]) -> None:
        self._eat("kw", "output")
        outputs.append(self._parse_expr())
        while self._at("sym", ","):
            self._next()
            outputs.append(self._parse_expr())
        self._eat("sym", ";")

    # ---- statements ----
    #: Statement nesting bound. `if a { if a { ... } }` recurses through
    #: _parse_block/_parse_stmt, which the expression guard never sees, and every
    #: later stage walks that tree recursively too. One bound, stated once, for
    #: every recursive descent the language has.
    MAX_BLOCK_DEPTH = 48

    def _parse_block(self) -> tuple[nodes.Stmt, ...]:
        self._bdepth = getattr(self, "_bdepth", 0) + 1
        try:
            if self._bdepth > self.MAX_BLOCK_DEPTH:
                raise ParseError(
                    f"blocks nested deeper than {self.MAX_BLOCK_DEPTH}", self._peek().pos)
            return self._parse_block_inner()
        finally:
            self._bdepth -= 1

    def _parse_block_inner(self) -> tuple[nodes.Stmt, ...]:
        self._eat("sym", "{")
        stmts: list[nodes.Stmt] = []
        while not self._at("sym", "}"):
            if self._at("eof"):
                self._err("unterminated block")
            stmts.append(self._parse_stmt())
        self._eat("sym", "}")
        return tuple(stmts)

    def _parse_stmt(self) -> nodes.Stmt:
        t = self._peek()
        if t.kind == "kw" and t.text == "let":
            self._next()
            name = self._eat("ident").text
            scale = self._parse_scale()
            self._eat("sym", "=")
            e = self._parse_expr()
            self._eat("sym", ";")
            return nodes.Let(name, e, t.pos, scale)
        if t.kind == "kw" and t.text == "if":
            self._next()
            cond = self._parse_expr()
            then = self._parse_block()
            els: tuple[nodes.Stmt, ...] = ()
            if self._at("kw", "else"):
                self._next()
                els = self._parse_block()
            return nodes.If(cond, then, els, t.pos)
        if t.kind == "kw" and t.text == "while":
            self._next()
            cond = self._parse_expr()
            body = self._parse_block()
            return nodes.While(cond, body, t.pos)
        if t.kind == "kw" and t.text == "for":
            self._next()
            var = self._eat("ident").text
            self._eat("kw", "in")
            lo = self._parse_expr()
            self._eat("sym", "..")
            hi = self._parse_expr()
            body = self._parse_block()
            return nodes.For(var, lo, hi, body, t.pos)
        if t.kind == "kw" and t.text == "break":
            self._next()
            self._eat("sym", ";")
            return nodes.Break(t.pos)
        if t.kind == "kw" and t.text == "continue":
            self._next()
            self._eat("sym", ";")
            return nodes.Continue(t.pos)
        if t.kind == "kw" and t.text == "return":
            self._next()
            e = self._parse_expr()
            self._eat("sym", ";")
            return nodes.Return(e, t.pos)
        if t.kind == "ident":
            name = self._next().text
            if self._at("sym", "["):
                self._next()
                idx = self._parse_expr()
                self._eat("sym", "]")
                self._eat("sym", "=")
                val = self._parse_expr()
                self._eat("sym", ";")
                return nodes.StoreElem(name, idx, val, t.pos)
            self._eat("sym", "=")
            e = self._parse_expr()
            self._eat("sym", ";")
            return nodes.Assign(name, e, t.pos)
        self._err(f"expected a statement, got {t.text or t.kind!r}")

    # ---- expressions (precedence climbing) ----
    #: How deeply expressions may nest. The parser descends 8 precedence tiers per
    #: parenthesis, so CPython's ~1000-frame limit was reached at 82 nested parens
    #: -- and a RecursionError is not a refusal: it escapes past every handler
    #: `replayc/__main__.py` catches and lands in an auditor's terminal as a
    #: traceback. The grammar never stated a nesting bound, so there was nothing to
    #: refuse against; now it states one, and refuses with a position.
    MAX_EXPR_DEPTH = 48

    def _parse_expr(self) -> nodes.Expr:
        self._depth = getattr(self, "_depth", 0) + 1
        if self._depth > self.MAX_EXPR_DEPTH:
            self._depth -= 1
            raise ParseError(
                f"expression nested deeper than {self.MAX_EXPR_DEPTH}", self._peek().pos)
        try:
            e = self._bin(0)
        finally:
            self._depth -= 1
        # The parse-time guard counts RECURSION, and `a+a+a+...` does not recurse --
        # precedence climbing loops for left-associativity, then hands back a tree
        # 512 deep that the typer, folder and codegen all walk recursively. So the
        # tree itself is bounded, measured iteratively so the check cannot be the
        # thing that overflows.
        if self._depth == 0:
            stack, deepest = [(e, 1)], 0
            while stack:
                node, d = stack.pop()
                if d > deepest:
                    deepest = d
                    if deepest > self.MAX_EXPR_DEPTH:
                        raise ParseError(
                            f"expression tree deeper than {self.MAX_EXPR_DEPTH}",
                            getattr(node, "pos", None) or self._peek().pos)
                for f in ("left", "right", "operand", "cond", "index", "base"):
                    child = getattr(node, f, None)
                    if child is not None and hasattr(child, "pos"):
                        stack.append((child, d + 1))
                for f in ("args", "items"):
                    for child in getattr(node, f, ()) or ():
                        if hasattr(child, "pos"):
                            stack.append((child, d + 1))
        return e

    #: precedence tiers, lowest first; each is a set of symbol texts
    _TIERS = [{"|"}, {"^"}, {"&"}, {"==", "!="}, {"<", "<=", ">", ">="},
              {"<<", ">>"}, {"+", "-"}, {"*", "/", "%"}]

    def _bin(self, tier: int) -> nodes.Expr:
        if tier >= len(self._TIERS):
            return self._unary()
        left = self._bin(tier + 1)
        while self._peek().kind == "sym" and self._peek().text in self._TIERS[tier]:
            op = self._next()
            right = self._bin(tier + 1)
            left = nodes.Binary(_BINOP[op.text], left, right, op.pos)
        return left

    def _unary(self) -> nodes.Expr:
        t = self._peek()
        if t.kind == "sym" and t.text in ("-", "~"):
            # A unary chain recurses WITHOUT passing through _parse_expr, so the
            # depth guard there never saw it: `output ----...----a;` walked straight
            # to a RecursionError. Every recursive descent needs the bound, not just
            # the one that happened to be measured first.
            self._depth = getattr(self, "_depth", 0) + 1
            if self._depth > self.MAX_EXPR_DEPTH:
                self._depth -= 1
                raise ParseError(
                    f"expression nested deeper than {self.MAX_EXPR_DEPTH}", t.pos)
            try:
                self._next()
                operand = self._unary()
            finally:
                self._depth -= 1
            return nodes.Unary("neg" if t.text == "-" else "not", operand, t.pos)
        return self._primary()

    def _primary(self) -> nodes.Expr:
        t = self._peek()
        if t.kind == "int":
            self._next()
            return nodes.IntLit(t.value, t.pos)
        if t.kind == "sym" and t.text == "(":
            self._next()
            e = self._parse_expr()
            self._eat("sym", ")")
            return e
        if t.kind == "builtin":
            self._next()
            self._eat("sym", "(")
            args = [self._parse_expr()]
            while self._at("sym", ","):
                self._next()
                args.append(self._parse_expr())
            self._eat("sym", ")")
            return nodes.Call(t.text, tuple(args), t.pos)
        if t.kind == "ident":
            self._next()
            if self._at("sym", "["):
                self._next()
                idx = self._parse_expr()
                self._eat("sym", "]")
                return nodes.Index(t.text, idx, t.pos)
            if self._at("sym", "("):
                # a user-function call; the typer decides whether the name exists
                self._next()
                args: list[nodes.Expr] = []
                if not self._at("sym", ")"):
                    args.append(self._parse_expr())
                    while self._at("sym", ","):
                        self._next()
                        args.append(self._parse_expr())
                self._eat("sym", ")")
                return nodes.Call(t.text, tuple(args), t.pos)
            return nodes.Name(t.text, t.pos)
        self._err(f"expected an expression, got {t.text or t.kind!r}")


def parse(src: str) -> nodes.Program:
    return Parser(lex(src)).parse()
