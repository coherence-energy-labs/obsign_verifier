"""Generators of hostile receipt TEXT, for the raw-byte differential.

The fuzzers already in this suite work on OBJECTS: they build a receipt or a program
and ask whether the implementations compute the same thing about it. That skips the
layer where the two measured wire-format splits actually lived. `1e400`, the
5000-digit integer and the 2000-level nest were never disagreements about semantics --
they were disagreements about what is a document at all, decided inside a parser
before any verification ran, and reachable only by handing the parsers BYTES.

So this module never builds an object. It emits text, including text that is not JSON,
and the differential asks two questions of every implementation:

  1. does it LOAD? -- and every implementation must answer the same. A receipt one
     verifier reads and another refuses is a receipt an adversary hands to whichever
     one gives the answer they want.
  2. if it loads, what canonical BYTES does it produce? -- and those must be identical,
     because the canonical bytes are the hash is the claim.

Two generators, because they find different things. The MUTATOR starts from receipts
that really shipped and corrupts them, which reaches the states a real file passes
through when a pipeline rewrites it -- re-encoded, truncated, re-serialised by another
language. The GRAMMAR generator builds documents out of a bank of leaves chosen for
where parsers are known to disagree: the int/float boundary, 2^53 and 2^63, CPython's
4300-digit conversion limit, the non-finite spellings, surrogates, and the structural
limits at their exact edge. Neither alone covers the other's ground.
"""
from __future__ import annotations

import json
import random
import re
from collections.abc import Iterator
from pathlib import Path

from obsign_verify.canonical import (
    MAX_DEPTH,
    MAX_INT_DIGITS,
    MAX_MEMBERS_PER_OBJECT,
    MAX_RECEIPT_BYTES,
    MAX_STRING_BYTES,
)

_REPO = Path(__file__).resolve().parent.parent

# Characters that are easier to reason about by name than by glyph.
BOM = "﻿"
NBSP = " "
LINE_SEP = " "
ASTRAL = "\U0001f600"


# --------------------------------------------------------------------------- leaves
#
# Every entry is here because some parser somewhere reads it differently from some
# other parser. Plain values are included too: a generator that emits only poison
# never exercises the agreement it is supposed to be measuring.

#: Numeric literals. The comment on each group names the split it probes.
HOSTILE_NUMBERS: tuple[str, ...] = (
    # the int/float distinction, which canonicalises to different bytes
    "1", "1.0", "1e0", "1E0", "1.0e0", "0", "0.0", "-0", "-0.0", "0e0", "-0e-0",
    # 2^53: the last integer a double holds exactly. Beyond it a JSON.parse-based
    # reader silently rounds and a BigInt reader does not.
    "9007199254740992", "9007199254740993", "-9007199254740993",
    "9007199254740994", "18014398509481985",
    # 2^63: the int64 the replay machine is built on, and its neighbours
    "9223372036854775807", "9223372036854775808", "-9223372036854775808",
    "-9223372036854775809", "18446744073709551616",
    # CPython refuses a decimal integer conversion beyond 4300 digits; BigInt does not
    "1" * MAX_INT_DIGITS, "1" * (MAX_INT_DIGITS + 1), "-" + "1" * (MAX_INT_DIGITS + 1),
    "9" * 20, "1" * 100,
    # non-finite by literal rather than by name -- these never reach parse_constant
    "1e400", "-1e400", "1e309", "1e-400", "-1e-400", "1e-323", "5e-324", "2.5e-324",
    "1.7976931348623157e308", "1.7976931348623159e308",
    # exponent shapes
    "1e+2", "1e-2", "1E+2", "1e00000000000000000002", "1e999999999999999999",
    # malformed shapes RFC 8259 forbids and various readers forgive
    "01", "00", "+1", ".5", "5.", "1.", "1.e5", "-", "- 1", "1_000", "0x10", "0b1",
    "1e", "1e+", "--1", "1.2.3", "٣", "１",
    # the bare non-finite names: Python's json accepts these by default
    "NaN", "-NaN", "Infinity", "-Infinity", "nan", "inf", "infinity",
    # plain values, so agreement gets measured too
    "2", "-7", "3.25", "0.1", "1e-5", "1e16", "1e15", "1e21", "123456789012345678",
)

#: String literals, written as they appear in the document (quotes included).
HOSTILE_STRINGS: tuple[str, ...] = (
    '""', '"a"', '"obsign/receipt/v1"',
    # escapes: the legal set, the illegal set, and the truncated set
    r'"\u0000"', r'"\u001f"', r'"\u007f"', r'"\/"', r'"\\"', r'"\""',
    r'"\uD83D\uDE00"', r'"\ud83d\ude00"',
    r'"\b\f\n\r\t"', r'"\x41"', r'"\U0041"', r'"\a"', r'"\u00"', r'"\uZZZZ"',
    r'"\u{41}"', '"\\"',
    # raw control characters: RFC 8259 forbids them unescaped inside a string
    '"\x01"', '"\x1f"', '"\n"', '"\t"', '"\x7f"',
    # surrogates. A lone one has no UTF-8 encoding; a pair must combine to one code
    # point before the key sort and the \uXXXX escaping ever see it.
    r'"\ud800"', r'"\udc00"', r'"\udead"', r'"𐀀"', r'"\ud800\ud800"',
    r'"\udc00\ud800"', r'"😀"', r'"\ud800A"',
    # non-ASCII that ensure_ascii=True must escape, including astral and a BOM
    '"é"', '"€"', '""', '"￿"', '"' + BOM + '"', '"' + ASTRAL + '"',
    '"\U0010ffff"', '"é"', '"́e"',
    # the string-length limit, at the edge in BYTES rather than characters
    '"' + "x" * (MAX_STRING_BYTES - 1) + '"',
    '"' + "x" * MAX_STRING_BYTES + '"',
    '"' + "x" * (MAX_STRING_BYTES + 1) + '"',
    '"' + "é" * (MAX_STRING_BYTES // 2) + '"',
    # unterminated
    '"abc', '"abc\\"',
)

#: Literal tokens and fragments spliced in by the mutator.
HOSTILE_TOKENS: tuple[str, ...] = (
    "", " ", "\t", "\n", "\r", "\f", "\v", NBSP, LINE_SEP, "　",
    BOM, "\x00", "\x1a",
    "{", "}", "[", "]", ",", ":", '"', "\\", "//", "/*", "*/", "#",
    "true", "false", "null", "True", "None", "undefined",
    "NaN", "Infinity", "-Infinity",
)


def targeted_vectors(include_huge: bool = False) -> list[tuple[str, str]]:
    """The vectors chosen by hand, at exactly the edges the limits name.

    A random walk reaches `MAX_DEPTH` eventually and reaches `MAX_DEPTH + 1` only by
    luck. Every off-by-one this file has found lived on one of these boundaries, so
    they are enumerated rather than sampled.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(name: str, text: str) -> None:
        # Ids must be UNIQUE. They are truncated for readability, and the first cut of
        # this file truncated `1`*4300 and `1`*4301 to the same 24 characters -- so the
        # differential paired one implementation's answer about one document with
        # another implementation's answer about a different one, and reported two
        # divergences that did not exist. A duplicate id in a differential harness is
        # not an inconvenience; it manufactures findings.
        if name in seen:
            name = f"{name}#{len(text)}"
        assert name not in seen, f"duplicate vector id {name!r}"
        seen.add(name)
        out.append((name, text))

    add("honest-minimal", '{"spec":"obsign/receipt/v1","n":1,"f":1.5}')
    add("honest-nested", '{"a":{"b":[1,2.0,"x",null,true,false]},"z":-0.0}')

    # --- duplicate members, at every position a document can carry one
    add("dup-top", '{"a":1,"a":2}')
    add("dup-nested", '{"p":{"x":1,"x":2}}')
    add("dup-in-array", '{"p":[{"x":1,"x":2}]}')
    add("dup-same-value", '{"a":1,"a":1}')
    add("dup-escaped-key", r'{"a":1,"a":2}')
    add("dup-proto", '{"__proto__":1,"__proto__":2}')
    add("proto-key", '{"__proto__":{"lit":"9"},"a":1}')

    # --- structural limits, each at limit-1 / limit / limit+1
    for n in (MAX_DEPTH - 1, MAX_DEPTH, MAX_DEPTH + 1, MAX_DEPTH + 2):
        add(f"depth-obj-leaf-{n}", '{"a":' * n + "1" + "}" * n)
        add(f"depth-obj-empty-{n}", '{"a":' * (n - 1) + "{}" + "}" * (n - 1))
        add(f"depth-arr-empty-{n}", '{"a":' + "[" * (n - 1) + "]" * (n - 1) + "}")
        add(f"depth-arr-leaf-{n}", '{"a":' + "[" * (n - 1) + "1" + "]" * (n - 1) + "}")
    for n in (MAX_MEMBERS_PER_OBJECT - 1, MAX_MEMBERS_PER_OBJECT, MAX_MEMBERS_PER_OBJECT + 1):
        add(f"members-{n}", "{" + ",".join(f'"k{i}":1' for i in range(n)) + "}")

    # --- integer width
    for d in (MAX_INT_DIGITS - 1, MAX_INT_DIGITS, MAX_INT_DIGITS + 1):
        add(f"int-digits-{d}", '{"a":' + "1" * d + "}")
        add(f"int-digits-neg-{d}", '{"a":-' + "1" * d + "}")

    # --- string length, in bytes not characters
    for n in (MAX_STRING_BYTES - 1, MAX_STRING_BYTES, MAX_STRING_BYTES + 1):
        add(f"string-bytes-{n}", '{"a":"' + "x" * n + '"}')
        add(f"key-bytes-{n}", '{"' + "x" * n + '":1}')
    add("string-multibyte-over-limit",
        '{"a":"' + "é" * (MAX_STRING_BYTES // 2 + 1) + '"}')

    # --- the document as a whole
    add("empty", "")
    add("whitespace-only", "   \t\n")
    add("bom-then-object", BOM + "{}")
    add("object-then-bom", "{}" + BOM)
    add("top-level-null", "null")
    add("top-level-number", "1")
    add("top-level-string", '"x"')
    add("top-level-array", "[]")
    add("top-level-true", "true")
    add("trailing-nul", '{"a":1}\x00')
    add("trailing-newline", '{"a":1}\n')
    add("trailing-object", '{"a":1}{"b":2}')
    add("trailing-comma-object", '{"a":1,}')
    add("trailing-comma-array", '{"a":[1,]}')
    add("leading-comma", '{,"a":1}')
    add("unquoted-key", "{a:1}")
    add("single-quoted-key", "{'a':1}")
    add("comment-line", '{"a":1} // hi')
    add("comment-block", '{/*x*/"a":1}')
    add("nul-in-key", '{"a\x00b":1}')
    add("form-feed-between-tokens", '{\f"a":1}')
    add("nbsp-between-tokens", "{" + NBSP + '"a":1}')
    add("lineseparator-between-tokens", "{" + LINE_SEP + '"a":1}')
    add("truncated-object", '{"a":')
    add("truncated-string", '{"a":"x')
    add("unbalanced-close", '{"a":1}}')

    # --- one hostile leaf per document, so a split names its own cause
    for lit in HOSTILE_NUMBERS:
        add(f"num::{lit[:24]}", '{"a":' + lit + "}")
    for s in HOSTILE_STRINGS:
        if len(s) > 4096 and not include_huge:
            continue
        if s.startswith('"'):
            add(f"key::{s[:24]}", "{" + s + ":1}")
        add(f"val::{s[:24]}", '{"k":' + s + "}")

    if include_huge:
        # 4 MiB is the cheapest refusal in either implementation and the only limit
        # checked before a single token is read. These live in the long campaign only,
        # because the transport cost of an 8 MB round trip per run is not worth paying
        # on every commit.
        pad = MAX_RECEIPT_BYTES - len('{"a":""}')
        add("size-at-limit", '{"a":"' + "x" * (pad - 2) + '"}')
        add("size-over-limit", '{"a":"' + "x" * pad + '"}')
        add("array-at-limit", '{"a":[' + ",".join("0" for _ in range(1 << 20)) + "]}")

    return out


# --------------------------------------------------------------------------- seeds

def seed_texts() -> list[tuple[str, str]]:
    """Receipts that really shipped, read as TEXT rather than parsed.

    The mutator needs documents with the shape of the real thing -- signature blocks,
    nested params, float metrics, hex digests -- because the interesting corruptions
    are the ones a real pipeline could produce, and those are shaped by the original.
    """
    roots = [_REPO / "src" / "obsign_verify" / "data",
             _REPO / "examples",
             _REPO / "js" / "test" / "fixtures"]
    out: list[tuple[str, str]] = []
    for root in roots:
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*.json")):
            text = p.read_text(encoding="utf-8")
            if not text.lstrip().startswith("{") or len(text) > 200_000:
                continue
            out.append((p.name, text))
    # A synthetic seed so the mutator has a small target too: corrupting a 30 KB
    # receipt at a random offset almost always lands in a hex digest and produces the
    # same class of finding every time.
    out.append(("synthetic", json.dumps(
        {"spec": "obsign/receipt/v1", "params": {"grid": 8, "gamma": 0.0, "d": 1e-06},
         "metrics": {"mean": -3e-05, "n": 1024}, "tags": ["a", "b"],
         "receipt_sha256": "0" * 64}, separators=(",", ":"))))
    return out


# --------------------------------------------------------------------------- mutator

_NUM_SPAN = re.compile(r"(?<=[:\[,])-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")
_INT_SPAN = re.compile(r"(?<=[:\[,])-?\d+(?![.\d eE])")
_STR_SPAN = re.compile(r'"(?:[^"\\]|\\.)*"')
_MEMBER_SPAN = re.compile(
    r'"(?:[^"\\]|\\.)*"\s*:\s*(?:-?\d+(?:\.\d+)?|"(?:[^"\\]|\\.)*"|true|false|null)')
_VALUE_SPAN = re.compile(
    r'(?<=:)(?:-?\d+(?:\.\d+)?|"(?:[^"\\]|\\.)*"|true|false|null)')
_SHORT_STRINGS = tuple(s for s in HOSTILE_STRINGS if len(s) < 512)


class Mutator:
    """Byte-level corruption of a real receipt's text."""

    def __init__(self, rng: random.Random):
        self.rng = rng

    def __call__(self, text: str) -> str:
        for _ in range(self.rng.choice((1, 1, 1, 2, 3))):
            text = self._one(text)
        return text

    def _one(self, t: str) -> str:
        r = self.rng
        if not t:
            return r.choice(HOSTILE_TOKENS)
        i = r.randrange(len(t))
        k = r.random()
        if k < 0.14:                                  # splice a hostile token
            return t[:i] + r.choice(HOSTILE_TOKENS) + t[i:]
        if k < 0.24:                                  # delete a run
            return t[:i] + t[min(len(t), i + r.randint(1, 8)):]
        if k < 0.32:                                  # truncate
            return t[:i]
        if k < 0.40:                                  # flip one character's low bits
            return t[:i] + chr(ord(t[i]) ^ (1 << r.randrange(7))) + t[i + 1:]
        if k < 0.48:                                  # repeat a run
            j = min(len(t), i + r.randint(1, 16))
            return t[:j] + t[i:j] + t[j:]
        if k < 0.60:
            return self._sub(t, _NUM_SPAN, r.choice(HOSTILE_NUMBERS))
        if k < 0.70:
            return self._sub(t, _STR_SPAN, r.choice(_SHORT_STRINGS))
        if k < 0.78:
            return self._dup_member(t)
        if k < 0.86:
            return self._wrap(t)
        if k < 0.92:
            return self._retype_number(t)
        if k < 0.96:                                  # prepend / append junk
            tok = r.choice(HOSTILE_TOKENS)
            return tok + t if r.random() < 0.5 else t + tok
        return t[:i] + chr(r.randrange(0x110000)) + t[i:]   # any code point at all

    # -- structure-aware edits, applied to the TEXT so malformed output is possible

    def _sub(self, t: str, pat: re.Pattern[str], repl: str) -> str:
        sp = [m.span() for m in pat.finditer(t)]
        if not sp:
            return t
        a, b = self.rng.choice(sp)
        return t[:a] + repl + t[b:]

    def _retype_number(self, t: str) -> str:
        """`1` <-> `1.0`: the same value, different canonical bytes, different hash.
        The one corruption the whole int/float apparatus exists to survive."""
        sp = [m.span() for m in _INT_SPAN.finditer(t)]
        if not sp:
            return t
        _a, b = self.rng.choice(sp)
        return t[:b] + self.rng.choice((".0", ".00", "e0", ".0e0")) + t[b:]

    def _dup_member(self, t: str) -> str:
        sp = [m.span() for m in _MEMBER_SPAN.finditer(t)]
        if not sp:
            return t
        a, b = self.rng.choice(sp)
        return t[:b] + "," + t[a:b] + t[b:]

    def _wrap(self, t: str) -> str:
        sp = [m.span() for m in _VALUE_SPAN.finditer(t)]
        if not sp:
            return t
        a, b = self.rng.choice(sp)
        n = self.rng.choice((1, 2, 3, MAX_DEPTH - 2, MAX_DEPTH, MAX_DEPTH + 1))
        inner = t[a:b]
        if self.rng.random() < 0.5:
            return t[:a] + "[" * n + inner + "]" * n + t[b:]
        return t[:a] + '{"w":' * n + inner + "}" * n + t[b:]


# --------------------------------------------------------------------------- grammar

_GEN_KEYS = ("a", "b", "spec", "params", "metrics", "z", "\\u0041",
             "\\ud83d\\ude00", "\\ue000", "__proto__", "receipt_sha256",
             "env", "signature", "case", "_x")
_GEN_WS = ("", "", "", " ", "\n", "\t", "\r", "  ", "\f", NBSP)


class Grammar:
    """Documents assembled from the hostile leaf bank, with hostile formatting."""

    def __init__(self, rng: random.Random, max_depth: int = 6, max_width: int = 5):
        self.rng = rng
        self.max_depth = max_depth
        self.max_width = max_width

    def document(self) -> str:
        r = self.rng
        pre = r.choice(("", "", "", " ", "\n", "\t", BOM, "\r\n"))
        post = r.choice(("", "", "", " ", "\n", "\x00", "{}", ",", BOM))
        return pre + self._object(0) + post

    def _ws(self) -> str:
        return self.rng.choice(_GEN_WS)

    def _key(self) -> str:
        r = self.rng
        if r.random() < 0.25:
            s = r.choice(_SHORT_STRINGS)
            return s if s.startswith('"') else '"k"'
        return '"' + r.choice(_GEN_KEYS) + '"'

    def _value(self, depth: int) -> str:
        r = self.rng
        if depth >= self.max_depth or r.random() < 0.55:
            k = r.random()
            if k < 0.45:
                return r.choice(HOSTILE_NUMBERS)
            if k < 0.80:
                return r.choice(_SHORT_STRINGS)
            return r.choice(("true", "false", "null"))
        return self._object(depth + 1) if r.random() < 0.5 else self._array(depth + 1)

    def _object(self, depth: int) -> str:
        r = self.rng
        n = r.randint(0, self.max_width)
        keys = [self._key() for _ in range(n)]
        if n >= 2 and r.random() < 0.2:              # a deliberate duplicate member
            keys[r.randrange(n)] = keys[r.randrange(n)]
        parts = [f"{self._ws()}{k}{self._ws()}:{self._ws()}{self._value(depth)}{self._ws()}"
                 for k in keys]
        return "{" + ",".join(parts) + "}"

    def _array(self, depth: int) -> str:
        r = self.rng
        n = r.randint(0, self.max_width)
        return "[" + ",".join(f"{self._ws()}{self._value(depth)}{self._ws()}"
                              for _ in range(n)) + "]"


# --------------------------------------------------------------------------- campaign

def campaign(seed: int, count: int) -> Iterator[tuple[str, str]]:
    """`count` generated cases, half mutated from real receipts, half grammar-built.

    Seeded end to end: the same seed and count give the same bytes on every machine and
    every run, so a failure prints an id that reproduces exactly.
    """
    seeds = seed_texts()
    for i in range(count):
        rng = random.Random(seed * 1_000_003 + i)
        if i % 2 == 0:
            name, text = seeds[rng.randrange(len(seeds))]
            yield f"mut/{seed}/{i}/{name}", Mutator(rng)(text)
        else:
            yield f"gen/{seed}/{i}", Grammar(rng).document()
