"""Four lowerings of RL, and text that is not a program.

`test_replayc_fuzz.py` generates programs that type-check and proves the interpreter,
the Python VM and the JavaScript VM compute the same numbers. That is the right
question one layer up from here, and it is already answered. This file asks the two
questions underneath it, both about SOURCE:

  IS A REFUSAL A REFUSAL? The machine's whole design is that partial operations trap,
  and "a trap is a refusal with a reason, never an exception that escapes into the
  caller". The front end is reachable by exactly the same stranger -- `obsign-replayc
  check prog.rl` is documented, `attest` reads a source file someone hands you, and the
  pitch is that an auditor compiles YOUR source to check YOUR receipt -- so it is held
  to the same rule. `__main__.py` catches ParseError, ResolveError, TypeError_,
  ScaleError and CodegenError. Anything else reaches the user as a traceback.

  DO THE LOWERINGS AGREE? The oracle (`interp.interpret` on the checked AST) and the
  compiler (`inline -> fold -> generate`, then a VM) share only the parse/check front
  half, which can only reject. For every program both accept, every VM must return the
  same numbers or every one must trap. Trap-for-trap parity is the contract; WHICH trap
  is not, and this file does not compare trap messages. Three VMs are compared when
  they are available -- Python always, the JS VM whenever node is installed, and the
  Rust VM whenever somebody has already built the crate. Rust is the one that fails
  differently: Python and JavaScript both compute in arbitrary-precision integers and
  narrow with an explicit `wrap`, so a mistake in that shared strategy is invisible to
  both, while Rust runs native i64 with `overflow-checks` on.

WHAT THE CAMPAIGN FOUND

Zero result divergences: the interpreter, the Python VM, the JS VM and the Rust VM
agreed on every program and every input the campaign reached, traps included. Five
defect classes, over nine frozen vectors under `corpus/rl_source/`:

    a Unicode gap in the lexer                      AttributeError, not a refusal
    unbounded recursion in the parser               RecursionError at 82 nested parens
    an unbounded integer conversion on the way IN   ValueError out of lex()
    three diagnostics that format one on the way OUT  ValueError raised inside a raise
    an oracle with no MAX_MEM and no #steps ceiling  it runs what the compiler refuses

Every one is pinned below by an `xfail(strict=True)` test that explains it, and
tolerated by the campaign only through the signature its corpus file records. A crash
signature the corpus does not name fails the campaign.

`OBSIGN_FUZZ=full` runs the long campaign; `OBSIGN_FUZZ_CASES` and `OBSIGN_FUZZ_SEEDS`
set the knobs directly.
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

import fuzz_rl_source as fuzz
import pytest

from obsign_verify.replay import Trap
from obsign_verify.replay import run as vm_run
from obsign_verify.replayc.codegen import CodegenError
from obsign_verify.replayc import compile_source, parse_program
from obsign_verify.replayc import interp as _interp
from obsign_verify.replayc.codegen import CodegenError
from obsign_verify.replayc.frontend import ParseError
from obsign_verify.replayc.resolve import ResolveError
from obsign_verify.replayc.scales import ScaleError
from obsign_verify.replayc.typer import TypeError_

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
_RUNNER = _HERE / "replayc_js_runner.mjs"
_CORPUS = _HERE / "corpus" / "rl_source"

#: The Rust crate's VM, if somebody has already built it. A fourth execution of the
#: same compiled program, by another author, native i64 with overflow-checks on rather
#: than arbitrary-precision-then-wrap. Never built here and never required: this file
#: must not make `pytest -q` wait on a compiler.
_RUST = _REPO / "rust" / "target" / "release" / "obsign-verify-rs"
_HAS_RUST = _RUST.is_file() and os.access(_RUST, os.X_OK)

_HAS_NODE = shutil.which("node") is not None
_REQUIRE = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_FULL = os.environ.get("OBSIGN_FUZZ", "").lower() in ("full", "long", "1", "true")
_CASES = int(os.environ.get("OBSIGN_FUZZ_CASES", "3000" if _FULL else "400"))
_SEEDS = int(os.environ.get("OBSIGN_FUZZ_SEEDS", "5" if _FULL else "1"))

#: The refusals the CLI catches. This tuple IS the contract; it is copied from
#: `_compile_or_die` in replayc/__main__.py, and a compiler exit outside it is a
#: traceback in a stranger's terminal rather than a diagnosis.
DECLARED = (ParseError, ResolveError, TypeError_, ScaleError, CodegenError)

#: The interpreter's budget, matched to the `#steps` every generated program declares.
#: Its own docstring says the tree-walk's "steps" are not the machine's instruction
#: count and the number "is NOT part of any cross-checked contract", so the two budgets
#: are not comparable and a budget trap on ONE side alone is reported separately from a
#: real trap-parity break. It is small because the generator deliberately emits `for`
#: loops whose body assigns the induction variable: those run until something stops
#: them, and a differential that spends ten seconds proving two engines both gave up is
#: a differential nobody runs.
_INTERP_BUDGET = fuzz._GEN_STEPS


# ------------------------------------------------------------------------- outcomes

def _site(e: BaseException) -> str:
    """`module.function` of the deepest compiler frame that raised.

    Part of a crash's name, because two crashes can carry the same CPython message from
    two entirely different holes -- an over-wide decimal literal dies in the LEXER
    building the value, and an over-wide hex literal dies in the TYPER formatting its
    own diagnosis. One signature for both would let a fix to either hide the other.

    A RecursionError is the exception: the frame that happens to run out of stack is
    arbitrary, so it is named by message alone.
    """
    if isinstance(e, RecursionError):
        return ""
    frames = traceback.extract_tb(e.__traceback__)
    mine = [f for f in frames if "obsign_verify" in f.filename] or frames
    return f"{Path(mine[-1].filename).stem}.{mine[-1].name}"


def front_end(src: str, fn) -> tuple[str, str, object]:
    """(kind, detail, value) for one front-end call, where kind is accept/refuse/CRASH."""
    try:
        return ("accept", "", fn(src))
    except DECLARED as e:
        return ("refuse", f"{type(e).__name__}: {e}", None)
    except Exception as e:                             # noqa: BLE001 - that is the point
        where = _site(e)
        return ("CRASH", f"{type(e).__name__}{' in ' + where if where else ''}: {e}", None)


_CRASH_NORM = (
    # CPython words a RecursionError three different ways depending on which frame ran
    # out of stack ("", "while calling a Python object", "in __instancecheck__"); they
    # are one defect and must collapse to one name.
    (re.compile(r"maximum recursion depth exceeded.*"), "maximum recursion depth exceeded"),
    (re.compile(r"\d+:\d+: "), ""),
    (re.compile(r"'[^']*'"), "X"),
    (re.compile(r'"[^"]*"'), "X"),
    (re.compile(r"\b\d+\b"), "N"),
)


def crash_signature(detail: str) -> str:
    """Name a crash by its CLASS, not by the source that produced it.

    Fifty mutations of one hole in the lexer must collapse to one name, or the corpus
    becomes a list of duplicates and stops meaning anything.
    """
    kind, _, rest = detail.partition(": ")
    for pat, rep in _CRASH_NORM:
        rest = pat.sub(rep, rest)
    return f"{kind}: {rest[:60]}".strip().rstrip(":")


def corpus_entries() -> list[dict]:
    out = []
    for p in sorted(_CORPUS.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        d["path"] = p
        out.append(d)
    return out


def corpus_source(entry: dict) -> str:
    """The vector's RL source.

    Stored JSON-escaped, or as a repeat spec for the ones that are thousands of
    identical characters -- never raw, so no vector carries a literal CR or LF into a
    Windows checkout that `.gitattributes` does not cover.
    """
    if "source_repeat" in entry:
        r = entry["source_repeat"]
        body = r["unit"] * r["count"] + r.get("middle", "")
        if "after_unit" in r:
            body += r["after_unit"] * r["count"]
        return r["before"] + body + r["after"]
    return entry["source"]


_KNOWN_CRASHES = {e["signature"] for e in corpus_entries()
                  if e["kind"] == "front-end-crash"}
_KNOWN_SPLITS = {e["signature"] for e in corpus_entries()
                 if e["kind"] == "accept-split"}


# ------------------------------------------------------------------------- vacuity

def test_the_generators_are_not_vacuous():
    """A fuzzer that emits nothing hostile passes every differential ever written."""
    paths = fuzz.pathological()
    assert len(paths) >= 200, f"only {len(paths)} pathological sources"
    ids = [n for n, _ in paths]
    assert len(set(ids)) == len(ids), (
        "two pathological sources share an id: "
        + ", ".join(sorted({i for i in ids if ids.count(i) > 1}))[:200])
    for must in ("parens-96", "unicode-ident::é", "lit::11111111111111111111",
                 "recursion-mutual", "steps-over-ceiling", "arr-enormous"):
        assert must in set(ids), f"the pathological set lost {must!r}"
    seeds = fuzz.seed_sources()
    assert len(seeds) >= 8, f"only {len(seeds)} seed programs -- mutation has no target"
    assert any(n.endswith(".rl") for n, _ in seeds), \
        "the shipped examples are not being mutated"
    gen = [s for _, s, _ in fuzz.valid_campaign(0, 60)]
    compiled = sum(1 for s in gen if front_end(s, compile_source)[0] == "accept")
    assert compiled >= 30, (
        f"only {compiled}/60 generated programs compile -- the results differential "
        f"would be running on almost nothing")


# --------------------------------------------------------------- front-end totality

def _front_end_campaign(seed: int, count: int):
    """Returns (checked, crashes-by-signature, accept-splits-by-signature)."""
    cases = (fuzz.pathological() if seed == 0 else []) + list(fuzz.campaign(seed, count))
    crashes: dict[str, tuple[str, str]] = {}
    splits: dict[str, tuple[str, str]] = {}
    for cid, src in cases:
        kp, dp, _ast = front_end(src, parse_program)
        kc, dc, _prog = front_end(src, compile_source)
        for kind, detail in ((kp, dp), (kc, dc)):
            if kind == "CRASH":
                crashes.setdefault(crash_signature(detail), (cid, src))
        if kp == "accept" and kc == "refuse":
            splits.setdefault("oracle-accepts compiler-refuses: "
                              + crash_signature(dc), (cid, src))
        elif kp == "refuse" and kc == "accept":
            splits.setdefault("oracle-refuses compiler-accepts: "
                              + crash_signature(dp), (cid, src))
    return len(cases), crashes, splits


@pytest.mark.parametrize("seed", range(_SEEDS))
def test_hostile_source_is_refused_and_never_crashes_the_compiler(seed):
    """The campaign. A crash class the corpus does not already name fails here.

    Pure Python, so it runs on every platform in the matrix whether or not node is
    installed -- the compiler only exists here.
    """
    checked, crashes, splits = _front_end_campaign(seed, _CASES)
    assert checked > 300, f"only {checked} sources reached the front end"
    new = {k: v for k, v in crashes.items() if k not in _KNOWN_CRASHES}
    assert not new, (
        f"{len(new)} NEW crash class(es): the compiler fell over on hostile source "
        f"instead of refusing it, and nothing in corpus/rl_source/ describes this:\n  "
        + "\n  ".join(f"{k}\n      [{cid}] {src[:140]!r}" for k, (cid, src) in new.items()))
    new_splits = {k: v for k, v in splits.items() if k not in _KNOWN_SPLITS}
    assert not new_splits, (
        f"{len(new_splits)} NEW accept/reject split between the oracle and the "
        f"compiler:\n  "
        + "\n  ".join(f"{k}\n      [{cid}] {src[:140]!r}"
                      for k, (cid, src) in new_splits.items()))
    print(f"[rl-frontend seed={seed}] {checked} sources, {len(crashes)} crash "
          f"class(es), {len(splits)} accept-split(s), all already frozen")


# ------------------------------------------------------- results and traps, Python

@pytest.mark.parametrize("seed", range(_SEEDS))
def test_the_oracle_and_the_python_vm_agree_on_every_generated_program(seed):
    """Adversarial programs: int64 edges as literals, shift amounts at 0/63/64/65,
    `mulfx` fractions at both ends, array indices at and one past the bound, loops that
    assign their own induction variable. Compile once, run over many inputs.
    """
    ran = trapped = budget_only = 0
    for cid, src, _n_in in fuzz.valid_campaign(seed, _CASES // 4):
        kc, _dc, prog = front_end(src, compile_source)
        kp, _dp, ast = front_end(src, parse_program)
        if kc != "accept" or kp != "accept":
            continue
        rng = random.Random(seed * 104_729 + len(src))
        for _ in range(3):
            inp = fuzz.inputs_for(rng, prog["input"]["length"])
            vm = ref = None
            vm_trap = ref_trap = ""
            try:
                vm = vm_run(prog, list(inp))
            except Trap as e:
                vm_trap = str(e) or "trap"
            try:
                ref = _interp.interpret(ast, list(inp), _INTERP_BUDGET)
            except Trap as e:
                ref_trap = str(e) or "trap"
            ran += 1
            if vm_trap and ref_trap:
                trapped += 1
                continue
            if bool(vm_trap) != bool(ref_trap):
                # The two budgets count different things and the interpreter's is
                # documented as outside the contract, so a budget trap on one side
                # alone is not a divergence. Anything else is.
                if "budget" in vm_trap + ref_trap:
                    budget_only += 1
                    continue
                pytest.fail(
                    f"TRAP PARITY BROKEN [{cid}] inputs={inp}\n{src}\n"
                    f"python VM {vm_trap or f'returned {vm}'}, "
                    f"the oracle {ref_trap or f'returned {ref}'}")
            assert vm == ref, (f"RESULT DIVERGED [{cid}] inputs={inp}\n{src}\n"
                               f"vm={vm} interp={ref}")
    assert ran >= 100, f"only {ran} differential runs -- the campaign found no programs"
    assert trapped >= 1, ("not one run trapped -- the generator is not reaching the "
                          "partial operations, so trap parity is untested here")
    assert ran - trapped - budget_only >= 20, (
        f"only {ran - trapped - budget_only} of {ran} runs produced a NUMBER -- both "
        f"engines mostly agreed on refusing, which is the cheap half of the contract")
    assert budget_only < ran // 2, (
        f"{budget_only} of {ran} runs were excused as budget-only -- the generated "
        f"programs are spending their budget instead of computing, and this "
        f"differential is mostly measuring nothing")
    print(f"[rl-oracle-vs-vm seed={seed}] {ran} differential runs, {trapped} trapped "
          f"in both, {budget_only} excused as budget-only")


# ------------------------------------------------------------ results and traps, JS

@pytest.mark.skipif(not _HAS_NODE and "node" not in _REQUIRE, reason="node not installed")
@pytest.mark.parametrize("seed", range(_SEEDS))
def test_the_javascript_vm_agrees_with_the_python_side(seed):
    """The third lowering, reached exactly as a receipt reaches it.

    `replayc_js_runner.mjs` loads the program through js/src/canonical.js, so integers
    arrive as BigInt, and takes inputs as decimal STRINGS -- an int64 above 2^53 would
    lose precision through JSON.parse, which is the trap this whole system is built
    around.
    """
    assert _HAS_NODE, "OBSIGN_REQUIRE=node was set but node is not installed"
    cases, expected, sources = [], [], []
    for cid, src, _n_in in fuzz.valid_campaign(seed + 500, _CASES // 8):
        kc, _dc, prog = front_end(src, compile_source)
        if kc != "accept":
            continue
        rng = random.Random(seed * 7_919 + len(src))
        text = json.dumps(prog)
        for _ in range(2):
            inp = fuzz.inputs_for(rng, prog["input"]["length"])
            try:
                expected.append(("ok", [str(x) for x in vm_run(prog, list(inp))]))
            except Trap:
                expected.append(("trap", None))
            cases.append({"programText": text, "inputs": [str(x) for x in inp]})
            sources.append((cid, src, inp))
    assert len(cases) >= 60, f"only {len(cases)} programs reached the JS VM"

    fd, name = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    tmp = Path(name)
    try:
        tmp.write_text(json.dumps(cases), encoding="utf-8")
        proc = subprocess.run(["node", str(_RUNNER), str(tmp)], capture_output=True,
                              text=True, timeout=900, check=False)
    finally:
        tmp.unlink(missing_ok=True)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    js = json.loads(proc.stdout.strip().splitlines()[-1])

    assert sum(1 for k, _ in expected if k == "ok") >= 15, (
        "almost every generated program trapped -- the JS comparison would be "
        "measuring refusals rather than arithmetic")
    for (kind, val), got, (cid, src, inp) in zip(expected, js, sources):
        assert "error" not in got, (
            f"the JS VM raised something that is not a Trap [{cid}]: {got['error']}\n"
            f"{src}\ninputs={inp}")
        if kind == "trap":
            assert got.get("trap") is True, (
                f"TRAP PARITY BROKEN [{cid}]: the Python VM trapped, the JS VM "
                f"returned {got}\n{src}\ninputs={inp}")
        else:
            assert got.get("ok") == val, (
                f"RESULT DIVERGED [{cid}]\n{src}\ninputs={inp}\n"
                f"python={val} javascript={got}")
    print(f"[rl-three-way seed={seed}] {len(cases)} checks across the interpreter, "
          f"the Python VM and the JS VM")


# ------------------------------------------------------------- the frozen defects

def test_a_non_ascii_letter_is_a_syntax_error_not_a_crash():
    """`input a; output é;` takes the compiler down with an AttributeError.

    `lex()` decides what kind of token starts here with `c.isalpha()` and `c.isdigit()`,
    which are Unicode-aware: 'é', 'Ω', '中', '٣' (Arabic-Indic three) and '²' all
    answer True. It then matches `[A-Za-z_][A-Za-z0-9_]*` or `[0-9][0-9_]*`, which are
    ASCII-only, and calls `m.group(0)` without checking for None. An emoji takes the
    correct path and gets a clean "unexpected character" ParseError; a Greek letter
    does not.

    The gap is exactly the width of the non-ASCII letters and digits, and everything in
    it is a traceback out of `obsign-replayc check` rather than a diagnosis with a
    source position.
    """
    kind, detail, _ = front_end("input a; output é;", parse_program)
    assert kind == "refuse", f"the lexer raised {detail}"


def test_a_deeply_parenthesised_expression_is_refused_not_a_stack_overflow():
    """Eighty-two open parentheses is enough to crash the compiler.

    `_bin` walks eight precedence tiers, so each level of nesting costs eight Python
    frames plus `_unary` and `_primary` -- against a default recursion limit of 1000.
    82 nested parens, 82 nested calls `f(f(f(...)))`, 82 nested index expressions and
    82 parens inside an `arr` length all hit it; `----...` and `a+a+a+...` reach it at
    around 980 tokens.

    canonical.py treats this exact failure as a defect and converts it: json.loads'
    RecursionError becomes a WireFormatError because "a RecursionError escaping a
    loader reads as a crash rather than a refusal, and a verifier that crashes on
    hostile input has failed open in the eyes of whoever handed it the file". The same
    sentence applies to a compiler that an auditor is invited to run on a file someone
    handed them. There is no depth limit in the RL grammar to refuse against, which is
    the other half of the finding.
    """
    src = "input a; output " + "(" * 82 + "a" + ")" * 82 + ";"
    kind, detail, _ = front_end(src, parse_program)
    assert kind == "refuse", f"the parser raised {detail}"


def test_an_over_wide_decimal_literal_is_refused_with_a_position():
    """RL says "all literals fit int64 or fail to compile". This one fails differently.

    `lex()` builds the value with `int(text.replace("_", ""), base)` the moment it sees
    the digits. Past 4300 decimal digits CPython refuses the conversion itself, and the
    ValueError escapes with no source position and no diagnosis -- while a 4300-digit
    literal gets the proper "does not fit in int64" TypeError_ from the typer one pass
    later. The refusal is right; the way it is delivered is not, and it is outside the
    five exception types `__main__.py` catches.

    The receipt parser hit the identical CPython limit and closed it deliberately with
    MAX_INT_DIGITS. The compiler front end has no equivalent.
    """
    kind, detail, _ = front_end("input a; output " + "9" * 4301 + ";", parse_program)
    assert kind == "refuse", f"the lexer raised {detail}"


_HUGE_HEX = "0x" + "f" * 5000


@pytest.mark.parametrize("src,site", [
    (f"input a; output {_HUGE_HEX};", "typer._check_expr"),
    (f"input a; arr m[{_HUGE_HEX}]; output a;", "codegen._alloc"),
    (f"#steps {_HUGE_HEX}\ninput a; output a;", "codegen.generate"),
], ids=["literal", "array-length", "steps-pragma"])
def test_a_diagnostic_does_not_crash_while_refusing(src, site):
    """The refusal path falls over while refusing. `0x` + 5000 hex digits, three sites.

    Hex has no conversion limit in CPython, so `lex()` builds a 20,000-bit integer
    happily and each of the three checks below correctly decides to refuse it. Then
    each writes its diagnosis:

        raise TypeError_(f"integer literal {e.value} does not fit in int64", e.pos)

    and interpolating that integer into an f-string IS a decimal conversion, which is
    exactly what CPython caps at 4300 digits. The ValueError is raised from inside the
    raise. The verdict was right and the sentence explaining it is what fell over.

    Note the shape: a DECIMAL literal this wide is stopped in the lexer (corpus 003),
    so all three sites are reachable only through hex -- no conversion limit on the way
    in, the full one on the way out. This is the branch that only ever runs on input
    somebody else wrote.
    """
    kind, detail, _ = front_end(src, compile_source)
    assert kind == "refuse", f"{site} raised {detail} while refusing"


def test_the_oracle_refuses_an_array_the_machine_could_never_hold():
    """`arr m[99999999]` -- the compiler refuses it, the oracle allocates it.

    `codegen` refuses with "program needs N cells, over the 1048576 limit", which is
    MAX_MEM from replay.py: "1M cells. A receipt is a document, not a workload."
    `interp.Interpreter.run` does `[0] * arr.length` with no limit at all, so
    `interpret_source` -- a public entry point, exported in `replayc.__all__` --
    accepts the same program and allocates the cells. `arr m[99999999]` costs 800 MB;
    one more zero and it is a MemoryError, which is not a Trap and not a refusal.

    RESOLVED by moving MAX_MEM and the step ceiling into `parse_program`, the last
    step both paths share. They are STATIC properties -- knowable without running an
    instruction -- so they are compile-time refusals (CodegenError) on both sides
    rather than a runtime Trap on one, and the two doors now admit one language.

    Two things are wrong at once. The oracle and the compiler disagree about which
    programs exist, which is the same class of split as any two parsers disagreeing
    about which receipts exist; and the oracle, which is supposed to carry "the SAME
    totality as the machine", has one bound the machine has and it does not.
    """
    # 2,000,000 cells, just past MAX_MEM's 1,048,576. The corpus vector uses
    # 99,999,999 because that is the sharp witness; this proves the same split without
    # asking a CI runner for 800 MB to do it.
    src = "input a; arr m[2000000]; output a;"
    compiler = front_end(src, compile_source)[0]
    assert compiler == "refuse", "precondition: the compiler refuses this program"
    try:
        _interp.interpret(parse_program(src), [0], _INTERP_BUDGET)
        accepted = True
    except (Trap, MemoryError, CodegenError):
        accepted = False
    assert not accepted, (
        "interpret_source ran a program the compiler refuses as too large -- the "
        "oracle enforces no MAX_MEM")


@pytest.mark.skipif(not _HAS_RUST, reason="rust/target/release/obsign-verify-rs is not built")
@pytest.mark.parametrize("seed", range(_SEEDS))
def test_the_rust_vm_agrees_with_the_python_vm(seed):
    """The same compiled programs on a fourth machine, written by another author.

    Python and JavaScript both compute in arbitrary-precision integers and narrow with
    an explicit `wrap`, so a mistake in that shared strategy is invisible to both. Rust
    computes in native i64 with `overflow-checks = true`, which is the point: it fails
    differently. The generated programs put INT64_MIN, INT64_MAX and 2^53 into
    multiplications, `mulfx` fractions at 0 and 63, and shifts at 63, 64 and 65, which
    is exactly where a wrapping strategy and a checked one part company.

    `rust/` belongs to another author: this drives the `--harness vm` interface it
    already exposes and treats any failure of the binary as "no Rust column".
    """
    cases, expected, sources = [], [], []
    for cid, src, _n_in in fuzz.valid_campaign(seed + 900, _CASES // 8):
        kc, _dc, prog = front_end(src, compile_source)
        if kc != "accept":
            continue
        rng = random.Random(seed * 31_337 + len(src))
        text = json.dumps(prog)
        for _ in range(2):
            inp = fuzz.inputs_for(rng, prog["input"]["length"])
            try:
                expected.append(("ok", [str(x) for x in vm_run(prog, list(inp))]))
            except Trap:
                expected.append(("trap", None))
            cases.append([f"c{len(cases)}", {"program": text,
                                             "inputs": [str(x) for x in inp]}])
            sources.append((cid, src, inp))
    assert len(cases) >= 60, f"only {len(cases)} programs reached the rust VM"

    fd, name = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    tmp = Path(name)
    try:
        tmp.write_text(json.dumps(cases), encoding="utf-8")
        proc = subprocess.run([str(_RUST), "--harness", "vm", str(tmp)],
                              capture_output=True, text=True, timeout=900, check=False)
    finally:
        tmp.unlink(missing_ok=True)
    if proc.returncode != 0:
        pytest.skip(f"the rust harness failed -- treated as absent: {proc.stderr[:200]}")
    got = json.loads(proc.stdout.strip().splitlines()[-1])

    traps = 0
    assert sum(1 for k, _ in expected if k == "ok") >= 15, (
        "almost every generated program trapped -- the Rust comparison would be "
        "measuring refusals rather than arithmetic")
    for (cid_case, _payload), (kind, val), (cid, src, inp) in zip(cases, expected, sources):
        r = got[cid_case]
        if kind == "trap":
            traps += 1
            assert r.get("ok") is False, (
                f"TRAP PARITY BROKEN [{cid}]: the Python VM trapped, the Rust VM "
                f"returned {r}\n{src}\ninputs={inp}")
        else:
            assert r.get("ok") is True and r.get("out") == val, (
                f"RESULT DIVERGED [{cid}]\n{src}\ninputs={inp}\n"
                f"python={val} rust={r}")
    print(f"[rl-rust-vm seed={seed}] {len(cases)} checks against the Rust VM, "
          f"{traps} trapped in both")


# ------------------------------------------------------------------- the corpus

def test_the_corpus_is_present_and_describes_itself():
    entries = corpus_entries()
    # An EMPTY corpus is the goal state, not a broken harness: every vector
    # here was a real divergence, and each is deleted only when all
    # implementations agree on it. The machinery stays so the next one has
    # somewhere to land.
    for e in entries:
        assert e.get("path"), "corpus entry has no path"
    for e in entries:
        assert e.get("note"), f"{e['path'].name} has no prose saying what it proves"
        assert e.get("signature"), f"{e['path'].name} has no signature"
        assert e.get("kind") in ("front-end-crash", "accept-split"), e["path"].name
        assert "source" in e or "source_repeat" in e, e["path"].name


@pytest.mark.parametrize("entry", corpus_entries(),
                         ids=[e["path"].stem for e in corpus_entries()])
def test_every_frozen_vector_still_behaves_as_recorded(entry):
    """If this fails the defect was fixed or moved, and the vector comes out with it."""
    src = corpus_source(entry)
    kp, dp, _ = front_end(src, parse_program)
    kc, dc, _ = front_end(src, compile_source)
    if entry["kind"] == "front-end-crash":
        got = [crash_signature(d) for k, d in ((kp, dp), (kc, dc)) if k == "CRASH"]
        assert entry["signature"] in got, (
            f"{entry['path'].name}: expected the crash {entry['signature']!r}, got "
            f"parse={kp}({dp[:80]}) compile={kc}({dc[:80]}). {entry['note']}")
    else:
        assert kp == "accept" and kc == "refuse", (
            f"{entry['path'].name}: the oracle/compiler split closed -- "
            f"parse={kp} compile={kc}. {entry['note']}")
        assert entry["signature"].endswith(crash_signature(dc)), \
            f"{entry['path'].name}: the refusal changed to {dc[:100]!r}"


def test_the_recursion_limit_is_the_default_this_corpus_assumes():
    """The parens vector is a number, and the number depends on this.

    If a plugin or a conftest raises the recursion limit, the depth vectors stop
    reproducing and start passing for a reason that has nothing to do with the defect.
    Say so out loud rather than letting the corpus quietly go green.
    """
    assert sys.getrecursionlimit() == 1000, (
        f"recursion limit is {sys.getrecursionlimit()}, not CPython's default 1000 -- "
        f"the parser-depth vectors are calibrated against the default")
