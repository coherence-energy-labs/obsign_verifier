"""Generators of hostile RL SOURCE, for the four-lowering differential.

`test_replayc_fuzz.py` generates programs that type-check, and asks whether the
interpreter, the two VMs and the compiler compute the same number. That is the right
question one layer up from here. It never asks what happens to source that is NOT a
program, and the compiler's front end is exactly as reachable by a stranger as the
receipt parser is: `obsign-replayc check prog.rl` is a documented command, `attest`
reads a source file someone hands you, and the whole pitch is that an auditor compiles
YOUR source to check YOUR receipt.

So this module emits text, most of which is not a program, and the differential asks:

  1. does the front end REFUSE, rather than crash? The machine's contract is that a
     trap is "a refusal with a reason, never an exception that escapes into the
     caller". The front end is held to the same rule: ParseError, ResolveError,
     TypeError_, ScaleError and CodegenError are refusals. A RecursionError, an
     AttributeError or a raw ValueError is the compiler falling over, and `__main__.py`
     catches exactly the five declared types -- anything else reaches the user as a
     traceback rather than as a diagnosis.
  2. do the ORACLE and the COMPILER accept the same programs, and
  3. for a program both accept, do the interpreter, the Python VM and the JS VM return
     the same numbers, or all three trap? Trap-for-trap parity is the contract; WHICH
     trap is not.

Three generators. `pathological()` enumerates the constructs where a recursive-descent
parser, a Unicode-aware lexer and an unbounded integer meet their limits -- boundaries
are enumerated because a random walk finds them only by luck. `Mutator` corrupts the
shipped examples token by token, which is what a real hostile `.rl` looks like: mostly
valid, wrong in one place. `Grammar` builds adversarial but well-formed programs biased
towards the int64 edges, the trapping operators and the control flow that makes the
compiler's lowering differ most from the oracle's.
"""
from __future__ import annotations

import random
import re
from collections.abc import Iterator
from pathlib import Path

from obsign_verify.replay import INT64_MAX, INT64_MIN

_REPO = Path(__file__).resolve().parent.parent

#: The int64 values that break wrapping arithmetic if anything is off by one bit.
EDGE_INTS: tuple[int, ...] = (
    0, 1, -1, 2, -2, 3, -3, 7, -7, 255, 256, -256,
    INT64_MAX, INT64_MIN, INT64_MAX - 1, INT64_MIN + 1,
    1 << 31, -(1 << 31), 1 << 32, 1 << 40, 1 << 62, -(1 << 62),
    (1 << 53) - 1, 1 << 53, (1 << 53) + 1, 3037000500, -3037000499,
)

#: Literal spellings, including the ones that are not int64 and the ones CPython
#: cannot even convert.
HOSTILE_LITERALS: tuple[str, ...] = (
    "0", "1", "-1", "0x0", "0xFF", "0Xff", "1_000", "1__0", "0x_1", "1_",
    "9223372036854775807", "-9223372036854775808", "9223372036854775808",
    "18446744073709551616", "0x7fffffffffffffff", "0xffffffffffffffff",
    "0x1" + "0" * 20,
    "1" * 4300, "1" * 4301, "9" * 5000,          # CPython's int(str) conversion limit
    "0x" + "f" * 5000,                            # no digit limit in base 16
    "01", "007", "0b1", "0o7", "1.5", "1e3", ".5", "1.", "0x", "0xg",
)

#: Characters and words a lexer must classify. The Unicode entries are the point:
#: `str.isdigit()` and `str.isalpha()` are Unicode-aware and the token regexes are
#: ASCII-only, so anything in this group reaches the gap between them.
HOSTILE_TOKENS: tuple[str, ...] = (
    "", " ", "\t", "\n", "\r", "\f", "\v", "\x00", "\x1b",
    "//", "/*", "*/", "#", "#steps", "#step", "##", "$", "@", "`", "?", "!", "'",
    '"', "\\", ".", "..", "...", ":", ";", ",", "(", ")", "[", "]", "{", "}",
    "=", "==", "===", "!=", "<", "<=", ">", ">=", "<<", ">>", ">>>", "&", "&&",
    "|", "||", "^", "~", "+", "-", "*", "/", "%", "**",
    "let", "input", "output", "arr", "fn", "return", "if", "else", "while",
    "for", "in", "break", "continue", "const", "min", "max", "abs", "sel",
    "mulfx", "len", "fx0", "fx63", "fx64", "fx99", "fx",
    # non-ASCII that `isalpha()` / `isdigit()` accept and the token regexes do not
    "é", "Ω", "中", "٣", "²", "Ⅰ", "ÿ",
    "１", "\U0001d7d8", "\U0001f600", "\u200b", " ",
)

_SEED_INLINE: tuple[str, ...] = (
    "input a; output a;",
    "input a, b; output a + b, a * b;",
    "input a; let x = 0; for i in 0..8 { x = x + a; } output x;",
    "#steps 100000\ninput a; arr m[4]; m[0] = a; output m[0], len(m);",
    "fn f(x) { return x * 2; } input a; output f(f(a));",
    "const N = 4; input v[4]; let s = 0; for i in 0..N { s = s + v[i]; } output s;",
    "input a: fx32, b: fx32; output mulfx(a, b, 32);",
    "input a; let i = 0; while i < a { i = i + 1; } output i;",
)


def seed_sources() -> list[tuple[str, str]]:
    """The shipped examples plus a few small programs, as TEXT.

    The examples are the right mutation targets because they are what an auditor
    actually feeds the compiler: real fixed-point, real loops, real functions.
    """
    out: list[tuple[str, str]] = []
    d = _REPO / "examples" / "rl"
    if d.is_dir():
        for p in sorted(d.glob("*.rl")):
            out.append((p.name, p.read_text(encoding="utf-8")))
    out.extend((f"inline{i}", s) for i, s in enumerate(_SEED_INLINE))
    return out


# ------------------------------------------------------------------- pathological

def pathological() -> list[tuple[str, str]]:
    """Sources aimed at a specific structural limit, enumerated rather than sampled."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(name: str, src: str) -> None:
        # Ids must be UNIQUE. They are truncated for readability, and `1`*4300 and
        # `1`*4301 truncate to the same twenty characters -- a duplicate id in a
        # differential harness pairs one implementation's answer about one input with
        # another's about a different one, which manufactures findings.
        if name in seen:
            name = f"{name}#{len(src)}"
        assert name not in seen, f"duplicate vector id {name!r}"
        seen.add(name)
        out.append((name, src))

    add("honest", "input a; output a;")

    # Recursive descent through eight precedence tiers costs eight Python frames per
    # nesting level, so the parser's own stack is the first limit any hostile source
    # meets -- long before any limit the language documents.
    for n in (8, 32, 64, 80, 96, 128, 512, 4096):
        add(f"parens-{n}", "input a; output " + "(" * n + "a" + ")" * n + ";")
    for n in (64, 512, 2048, 8192):
        add(f"unary-minus-{n}", "input a; output " + "-" * n + "a;")
        add(f"unary-not-{n}", "input a; output " + "~" * n + "a;")
        add(f"chain-add-{n}", "input a; output " + "+".join(["a"] * n) + ";")
        add(f"chain-mixed-{n}",
            "input a; output " + "".join(f"a {op} " for op in
                                         ["+", "*", "|", "&", "^", "-", "/", "%"] * (n // 8)) + "a;")
    for n in (32, 256, 1024):
        add(f"nested-if-{n}", "input a; " + "if a { " * n + "let z = 1;" + " }" * n + " output a;")
        add(f"nested-blocks-{n}", "input a; " + "if a { " * n + " }" * n + " output a;")
        add(f"nested-calls-{n}",
            "fn f(x) { return x + 1; } input a; output " + "f(" * n + "a" + ")" * n + ";")
    add("nested-index-64",
        "input a; arr m[2]; output " + "m[" * 64 + "0" + "]" * 64 + ";")

    # Literals: the width where CPython's decimal conversion refuses, and the same
    # magnitude in hex, where it does not.
    for lit in HOSTILE_LITERALS:
        add(f"lit::{lit[:20]}", f"input a; output {lit};")
        add(f"lit-arr::{lit[:20]}", f"input a; arr m[{lit}]; output a;")
        add(f"lit-steps::{lit[:20]}", f"#steps {lit}\ninput a; output a;")

    # A lexer that gates on Unicode `isdigit()`/`isalpha()` and then matches an
    # ASCII-only regex has a gap exactly the width of the non-ASCII letters and digits.
    for ch in ("é", "Ω", "中", "٣", "²", "Ⅰ",
               "１", "\U0001d7d8", "µ", "⁹"):
        add(f"unicode-ident::{ch}", f"input a; let {ch} = 1; output a;")
        add(f"unicode-expr::{ch}", f"input a; output {ch};")
        add(f"unicode-after::{ch}", f"input a; output a{ch};")

    # Declarations and control flow at their edges
    add("no-output", "input a; let x = 1;")
    add("output-first", "output 1; input a;")
    add("empty", "")
    add("only-comment", "// nothing here\n")
    add("unterminated-block", "input a; if a { output a;")
    add("unterminated-comment", "input a; /* output a;")
    add("break-outside-loop", "input a; break; output a;")
    add("continue-outside-loop", "input a; continue; output a;")
    add("return-outside-fn", "input a; return a; output a;")
    add("break-in-fn", "fn f(x) { break; return x; } input a; output f(a);")
    add("return-not-last", "fn f(x) { return x; let y = 1; } input a; output f(a);")
    add("fn-no-return", "fn f(x) { let y = x; } input a; output f(a);")
    add("recursion-direct", "fn f(x) { return f(x); } input a; output f(a);")
    add("recursion-mutual",
        "fn f(x) { return g(x); } fn g(x) { return f(x); } input a; output f(a);")
    add("recursion-deep",
        "fn a1(x){return x;} fn a2(x){return a1(x)+a1(x);} fn a3(x){return a2(x)+a2(x);} "
        "fn a4(x){return a3(x)+a3(x);} fn a5(x){return a4(x)+a4(x);} "
        "fn a6(x){return a5(x)+a5(x);} fn a7(x){return a6(x)+a6(x);} "
        "fn a8(x){return a7(x)+a7(x);} fn a9(x){return a8(x)+a8(x);} "
        "fn a10(x){return a9(x)+a9(x);} fn a11(x){return a10(x)+a10(x);} "
        "fn a12(x){return a11(x)+a11(x);} input a; output a12(a);")
    add("input-twice", "input a; input b; output a;")
    add("input-both-forms", "input a; input v[3]; output a;")
    add("input-after-stmt", "let x = 1; input a; output a;")
    add("dup-input", "input a, a; output a;")
    add("dup-fn", "fn f(x){return x;} fn f(y){return y;} input a; output f(a);")
    add("const-self", "const N = N; input a; output a;")
    add("const-shadow", "const N = 4; input a; let N = 1; output a;")
    add("arr-zero", "input a; arr m[0]; output a;")
    add("arr-negative", "input a; arr m[0-1]; output a;")
    add("arr-enormous", "input a; arr m[99999999]; output a;")
    # The memory limit from BOTH sides plus the two lengths in between, where a guard
    # that bounds the declared length rather than the total cell count still lets the
    # oracle and the compiler admit different languages.
    for n in (1_048_574, 1_048_575, 1_048_576, 1_048_577):
        add(f"arr-at-max-mem-{n}", f"input a; arr m[{n}]; output a;")
    add("arr-many", "input a; " + "".join(f"arr m{i}[8]; " for i in range(600)) + "output a;")
    add("steps-zero", "#steps 0\ninput a; output a;")
    add("steps-negative", "#steps -1\ninput a; output a;")
    add("steps-over-ceiling", "#steps 999999999\ninput a; output a;")
    add("steps-twice", "#steps 10\n#steps 20\ninput a; output a;")
    add("mulfx-frac-64", "input a; output mulfx(a, a, 64);")
    add("mulfx-frac-negative", "input a; output mulfx(a, a, 0 - 1);")
    add("mulfx-frac-dynamic", "input a; output mulfx(a, a, a);")
    add("mulfx-arity", "input a; output mulfx(a, a);")
    add("len-of-scalar", "input a; output len(a);")
    add("len-of-nothing", "input a; output len();")
    add("min-one-arg", "input a; output min(a);")
    add("min-three-args", "input a; output min(a, a, a);")
    add("sel-two-args", "input a; output sel(a, a);")
    add("call-unknown", "input a; output nosuch(a);")
    add("call-wrong-arity", "fn f(x, y) { return x; } input a; output f(a);")
    add("index-scalar", "input a; output a[0];")
    add("store-to-scalar", "input a; a[0] = 1; output a;")
    add("assign-undeclared", "input a; b = 1; output a;")
    add("read-undeclared", "input a; output q;")
    add("for-reversed", "input a; let s=0; for i in 8..0 { s = s + 1; } output s;")
    add("for-huge", "#steps 1000\ninput a; let s=0; for i in 0..1000000 { s=s+1; } output s;")
    add("while-forever", "#steps 1000\ninput a; let i=0; while 1 { i=i+1; } output i;")
    add("while-no-steps", "input a; let i=0; while 1 { i=i+1; } output i;")
    add("for-writes-own-var",
        "#steps 100000\ninput a; let s=0; for i in 0..8 { i = i - 1; s = s + 1; "
        "if s > 20 { break; } } output s;")
    add("scale-mismatch", "input a: fx32, b: fx16; output a + b;")
    add("scale-bitop", "input a: fx32; output a & 1;")
    add("scale-product", "input a: fx32, b: fx32; output a * b;")
    add("scale-bad-annotation", "input a: fx64; output a;")
    add("scale-not-fx", "input a: q32; output a;")
    add("output-many", "input a; output " + ", ".join("a" for _ in range(2000)) + ";")
    add("many-lets", "input a; " + "".join(f"let v{i} = a + {i}; " for i in range(2000))
        + "output a;")
    return out


# ----------------------------------------------------------------------- mutator

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9a-fA-F_]+|[0-9][0-9_]*"
                       r"|<<|>>|<=|>=|==|!=|\.\.|//[^\n]*|\S")


class Mutator:
    """Token-level corruption of a real `.rl` file."""

    def __init__(self, rng: random.Random):
        self.rng = rng

    def __call__(self, src: str) -> str:
        for _ in range(self.rng.choice((1, 1, 1, 2, 3))):
            src = self._one(src)
        return src

    def _one(self, s: str) -> str:
        r = self.rng
        toks = [m.span() for m in _TOKEN_RE.finditer(s)]
        k = r.random()
        if not toks or k < 0.08:
            i = r.randrange(len(s)) if s else 0
            return s[:i] + r.choice(HOSTILE_TOKENS) + s[i:]
        a, b = r.choice(toks)
        if k < 0.22:                                   # replace a token
            return s[:a] + r.choice(HOSTILE_TOKENS) + s[b:]
        if k < 0.34:                                   # delete a token
            return s[:a] + s[b:]
        if k < 0.44:                                   # duplicate a token
            return s[:b] + " " + s[a:b] + s[b:]
        if k < 0.54:                                   # replace a literal
            return s[:a] + r.choice(HOSTILE_LITERALS) + s[b:]
        if k < 0.62:                                   # truncate here
            return s[:a]
        if k < 0.70:                                   # swap two tokens
            c, d = r.choice(toks)
            if c == a:
                return s
            (a, b), (c, d) = sorted(((a, b), (c, d)))
            return s[:a] + s[c:d] + s[b:c] + s[a:b] + s[d:]
        if k < 0.80:                                   # wrap an expression in parens
            n = r.choice((1, 2, 40, 90, 200))
            return s[:a] + "(" * n + s[a:b] + ")" * n + s[b:]
        if k < 0.88:                                   # negate a token
            return s[:a] + r.choice(("-", "~", "0 - ")) * r.choice((1, 1, 90)) + s[a:b] + s[b:]
        if k < 0.94:                                   # splice a whole statement
            return s[:a] + r.choice((
                "break; ", "continue; ", "return 1; ", "let x = 1; ", "output 1; ",
                "input z; ", "arr q[2]; ", "#steps 5\n", "const C = 1; ",
                "if 1 { } ", "while 1 { } ", "for i in 0..2 { } ")) + s[a:]
        i = r.randrange(len(s))                        # one arbitrary code point
        return s[:i] + chr(r.randrange(0x110000)) + s[i:]


# ----------------------------------------------------------------------- grammar

_BINOPS = ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>",
           "<", "<=", ">", ">=", "==", "!=")

#: The step budget every generated program declares. Small on purpose: the generator
#: emits `for` loops whose body assigns the induction variable, so some programs run
#: until their budget stops them, and a differential that spends ten seconds proving
#: two engines both gave up is a differential nobody runs. Loops are bounded to a
#: handful of iterations, so an honest generated program finishes in hundreds of steps.
_GEN_STEPS = 50_000


class Grammar:
    """Adversarial but well-formed programs.

    Deliberately different from `test_replayc_fuzz.py`'s generator, which aims for
    programs that type-check and stay in range. This one aims AT the edges: int64
    limits as literals, shift amounts around 0 and 63, `mulfx` fractions at both ends,
    array indices at and past the bound, loops that write their own induction variable.
    The point is not that these programs are sensible; it is that the compiler and the
    oracle must lower them the same way or refuse them together.
    """

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.scalars: list[str] = []
        self.arrays: dict[str, int] = {}
        self.fns: dict[str, int] = {}
        self.loop_depth = 0
        self._uid = 0

    def _name(self, p: str) -> str:
        self._uid += 1
        return f"{p}{self._uid}"

    def _lit(self) -> str:
        r = self.rng
        if r.random() < 0.35:
            v = r.choice(EDGE_INTS)
            return f"({v})" if v < 0 else str(v)
        return str(r.randint(-64, 64))

    def expr(self, depth: int) -> str:
        r = self.rng
        if depth <= 0 or r.random() < 0.3:
            if self.scalars and r.random() < 0.55:
                return r.choice(self.scalars)
            if self.arrays and r.random() < 0.4:
                arr = r.choice(list(self.arrays))
                n = self.arrays[arr]
                # Indices AT the bound and one past it, so the bounds trap is reached
                # from both sides by construction rather than by luck -- weighted
                # towards in-range, because a differential where most runs trap is
                # mostly testing that both engines can say no.
                idx = r.choice((0, 0, 1, n - 1, n - 1, r.randint(0, max(0, n - 1)),
                                n, -1, r.randint(-2, n + 1)))
                return f"{arr}[{idx if idx >= 0 else f'(0 - {-idx})'}]"
            return self._lit()
        k = r.random()
        if k < 0.44:
            op = r.choice(_BINOPS)
            if op in ("<<", ">>"):
                amt = r.choice((0, 1, 31, 62, 63, 64, 65))
                return f"({self.expr(depth - 1)} {op} {amt})"
            return f"({self.expr(depth - 1)} {op} {self.expr(depth - 1)})"
        if k < 0.56:
            return f"(0 - {self.expr(depth - 1)})" if r.random() < 0.5 \
                else f"(~{self.expr(depth - 1)})"
        if k < 0.66 and self.fns:
            name = r.choice(list(self.fns))
            return f"{name}({', '.join(self.expr(depth - 1) for _ in range(self.fns[name]))})"
        if k < 0.78:
            return f"{r.choice(('min', 'max'))}({self.expr(depth - 1)}, {self.expr(depth - 1)})"
        if k < 0.86:
            return f"abs({self.expr(depth - 1)})"
        if k < 0.93:
            return (f"sel({self.expr(depth - 1)}, {self.expr(depth - 1)}, "
                    f"{self.expr(depth - 1)})")
        return (f"mulfx({self.expr(depth - 1)}, {self.expr(depth - 1)}, "
                f"{r.choice((0, 1, 16, 31, 32, 62, 63))})")

    def fn_decl(self) -> str:
        r = self.rng
        name, arity = self._name("fx"), r.randint(1, 3)
        params = [self._name("p") for _ in range(arity)]
        saved = self.scalars, self.arrays
        self.scalars, self.arrays = list(params), {}
        body = self.expr(r.randint(1, 3))
        self.scalars, self.arrays = saved
        self.fns[name] = arity
        return f"fn {name}({', '.join(params)}) {{ return {body}; }}"

    def stmt(self, depth: int) -> str:
        r = self.rng
        k = r.random()
        if k < 0.3 or not self.scalars:
            n = self._name("t")
            e = self.expr(2)
            self.scalars.append(n)
            return f"let {n} = {e};"
        if k < 0.45:
            return f"{r.choice(self.scalars)} = {self.expr(2)};"
        if k < 0.58 and self.arrays:
            arr = r.choice(list(self.arrays))
            return f"{arr}[{self.expr(1)}] = {self.expr(2)};"
        if k < 0.68 and depth > 0:
            body = " ".join(self.stmt(depth - 1) for _ in range(r.randint(1, 2)))
            els = f" else {{ {self.stmt(depth - 1)} }}" if r.random() < 0.5 else ""
            return f"if {self.expr(1)} {{ {body} }}{els}"
        if k < 0.76 and self.loop_depth > 0:
            return f"if {self.expr(1)} {{ {r.choice(('break', 'continue'))}; }}"
        if depth > 0 and r.random() < 0.55:
            v = self._name("f")
            self.scalars.append(v)
            self.loop_depth += 1
            body = " ".join(self.stmt(depth - 1) for _ in range(r.randint(1, 2)))
            self.loop_depth -= 1
            return f"for {v} in {r.randint(-2, 2)}..{r.randint(0, 5)} {{ {body} }}"
        if depth > 0:
            # A while that terminates BY CONSTRUCTION: the counter is incremented
            # first, the body is generated before the counter exists so nothing in it
            # can assign the counter, and a generated `continue` therefore cannot skip
            # the increment. A fuzzer that hangs is a fuzzer nobody runs.
            bound = r.randint(0, 5)
            self.loop_depth += 1
            body = " ".join(self.stmt(depth - 1) for _ in range(r.randint(1, 2)))
            self.loop_depth -= 1
            c = self._name("k")
            self.scalars.append(c)
            return f"let {c} = 0; while {c} < {bound} {{ {c} = {c} + 1; {body} }}"
        return f"let {self._name('t')} = {self.expr(1)};"

    def program(self) -> tuple[str, int]:
        r = self.rng
        fns = "\n".join(self.fn_decl() for _ in range(r.randint(0, 2)))
        n_in = r.randint(1, 4)
        self.scalars = [self._name("in") for _ in range(n_in)]
        head = "input " + ", ".join(self.scalars) + ";\n"
        arrs = ""
        for _ in range(r.randint(0, 2)):
            an, ln = self._name("a"), r.randint(1, 4)
            self.arrays[an] = ln
            arrs += f"arr {an}[{ln}];\n"
        body = "\n".join(self.stmt(2) for _ in range(r.randint(1, 5)))
        outs = ", ".join(self.expr(2) for _ in range(r.randint(1, 3)))
        return (f"#steps {_GEN_STEPS}\n{fns}\n{head}{arrs}{body}\noutput {outs};\n", n_in)


# ---------------------------------------------------------------------- campaign

def campaign(seed: int, count: int) -> Iterator[tuple[str, str]]:
    """`count` hostile sources: mutated examples and adversarial generated programs."""
    seeds = seed_sources()
    for i in range(count):
        rng = random.Random(seed * 1_000_003 + i)
        if i % 2 == 0:
            name, text = seeds[rng.randrange(len(seeds))]
            yield f"mut/{seed}/{i}/{name}", Mutator(rng)(text)
        else:
            yield f"gen/{seed}/{i}", Grammar(rng).program()[0]


def valid_campaign(seed: int, count: int) -> Iterator[tuple[str, str, int]]:
    """Generated programs only, with their input arity -- for the results differential."""
    for i in range(count):
        src, n_in = Grammar(random.Random(seed * 7_919 + i)).program()
        yield f"gen/{seed}/{i}", src, n_in


def inputs_for(rng: random.Random, n: int) -> list[int]:
    return [rng.choice(EDGE_INTS) if rng.random() < 0.6
            else rng.randint(INT64_MIN, INT64_MAX) for _ in range(n)]
