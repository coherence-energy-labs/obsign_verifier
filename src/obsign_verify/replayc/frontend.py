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

KEYWORDS = {"input", "output", "let", "if", "else", "while", "arr"}
BUILTINS = {"min", "max", "abs", "sel", "mulfx"}

# Longest-match first so '<<' beats '<' and '<=' beats '<'.
_SYMBOLS = ["<<", ">>", "<=", ">=", "==", "!=", "|", "^", "&", "<", ">",
            "+", "-", "*", "/", "%", "~", "=", "(", ")", "[", "]", "{", "}", ",", ";"]


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
        if c.isdigit():
            m = re.match(r"0[xX][0-9a-fA-F][0-9a-fA-F_]*|[0-9][0-9_]*", src[i:])
            text = m.group(0)
            base = 16 if text[:2].lower() == "0x" else 10
            value = int(text.replace("_", ""), base)
            toks.append(_Tok("int", text, pos, value))
            adv(len(text))
            continue
        if c.isalpha() or c == "_":
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", src[i:])
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
        input_array: nodes.ArrayDecl | None = None
        seen_output = False
        while not self._at("eof"):
            if self._at("kw", "input"):
                if body or arrays or inputs or input_array is not None:
                    self._err("`input` must be declared once, before any statement or array")
                input_array = self._parse_input(inputs)
            elif self._at("kw", "arr"):
                arrays.append(self._parse_array())
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
                             steps, input_array, pos)

    def _parse_input(self, inputs: list[str]) -> nodes.ArrayDecl | None:
        """Either `input a, b, c;` (scalars) or `input xs[N];` (the window as an array)."""
        self._eat("kw", "input")
        first = self._eat("ident")
        if self._at("sym", "["):
            self._next()
            length = self._eat("int").value
            self._eat("sym", "]")
            self._eat("sym", ";")
            return nodes.ArrayDecl(first.text, length, first.pos)
        inputs.append(first.text)
        while self._at("sym", ","):
            self._next()
            inputs.append(self._eat("ident").text)
        self._eat("sym", ";")
        return None

    def _parse_array(self) -> nodes.ArrayDecl:
        t = self._eat("kw", "arr")
        name = self._eat("ident").text
        self._eat("sym", "[")
        length = self._eat("int").value
        self._eat("sym", "]")
        self._eat("sym", ";")
        return nodes.ArrayDecl(name, length, t.pos)

    def _parse_output(self, outputs: list[nodes.Expr]) -> None:
        self._eat("kw", "output")
        outputs.append(self._parse_expr())
        while self._at("sym", ","):
            self._next()
            outputs.append(self._parse_expr())
        self._eat("sym", ";")

    # ---- statements ----
    def _parse_block(self) -> tuple[nodes.Stmt, ...]:
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
            self._eat("sym", "=")
            e = self._parse_expr()
            self._eat("sym", ";")
            return nodes.Let(name, e, t.pos)
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
    def _parse_expr(self) -> nodes.Expr:
        return self._bin(0)

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
            self._next()
            operand = self._unary()
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
            return nodes.Name(t.text, t.pos)
        self._err(f"expected an expression, got {t.text or t.kind!r}")


def parse(src: str) -> nodes.Program:
    return Parser(lex(src)).parse()
