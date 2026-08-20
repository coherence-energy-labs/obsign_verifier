"""Randomised differential fuzzing of the compiler.

The gadget tests prove each operator in isolation. This proves them in COMBINATION:
it generates random well-typed programs -- nested arithmetic, if/else, bounded loops,
array reads and writes -- and requires the reference interpreter and the replay VM to
agree on every one, over random int64 inputs. Where either refuses (a div-by-zero or an
out-of-range index the random inputs happen to hit), BOTH must refuse. A subset is also
run through the JavaScript VM, so the agreement is three-way.

Generation is seeded, so a failure prints a seed that reproduces the exact program and
inputs -- the fuzzer is a finder, not a flake.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from obsign_verify.replay import INT64_MAX, INT64_MIN, Trap
from obsign_verify.replay import run as vm_run
from obsign_verify.replayc import compile_source, interpret_source, run_source
from obsign_verify.replayc import interp as _interp
from obsign_verify.replayc import parse_program

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = "node" in {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_RUNNER = Path(__file__).resolve().parent / "replayc_js_runner.mjs"

_BINOPS = ["+", "-", "*", "/", "%", "&", "|", "^", "<", "<=", ">", ">=", "==", "!="]
_EDGE_INPUTS = [0, 1, -1, INT64_MAX, INT64_MIN, 2, -2, 1 << 40, -(1 << 40), 255, -256]


class _Gen:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.scalars: list[str] = []
        self.arrays: dict[str, int] = {}
        self.fns: dict[str, int] = {}      # name -> arity
        self.loop_depth = 0
        self._uid = 0

    def _name(self, p: str) -> str:
        self._uid += 1
        return f"{p}{self._uid}"

    def expr(self, depth: int) -> str:
        r = self.rng
        if depth <= 0 or not self.scalars or r.random() < 0.35:
            choice = r.random()
            if self.scalars and choice < 0.5:
                return r.choice(self.scalars)
            if self.arrays and choice < 0.7:
                arr = r.choice(list(self.arrays))
                # index kept simple so a fair fraction land in range (both may still trap)
                return f"{arr}[{self.expr(0)}]"
            return str(r.randint(-8, 300))
        kind = r.random()
        if kind < 0.5:
            op = r.choice(_BINOPS)
            if op in ("<<", ">>"):
                return f"({self.expr(depth - 1)} {op} {r.randint(0, 63)})"
            return f"({self.expr(depth - 1)} {op} {self.expr(depth - 1)})"
        if kind < 0.62:
            return f"(0 - {self.expr(depth - 1)})" if r.random() < 0.5 else f"(~{self.expr(depth - 1)})"
        if kind < 0.74 and self.fns:
            # a user-function call: the inliner's lowering vs the oracle's native call
            name = r.choice(list(self.fns))
            args = ", ".join(self.expr(depth - 1) for _ in range(self.fns[name]))
            return f"{name}({args})"
        if kind < 0.85:
            fn = r.choice(["min", "max"])
            return f"{fn}({self.expr(depth - 1)}, {self.expr(depth - 1)})"
        if kind < 0.93:
            return f"abs({self.expr(depth - 1)})"
        if kind < 0.97:
            return f"sel({self.expr(depth - 1)}, {self.expr(depth - 1)}, {self.expr(depth - 1)})"
        return f"mulfx({self.expr(depth - 1)}, {self.expr(depth - 1)}, {self.rng.randint(0, 63)})"

    def fn_decl(self) -> str:
        """A closed function over its params only: expression-bodied, arithmetic-rich.
        Its body expression is generated with the scalar pool swapped to the params,
        so it cannot reference globals (which the typer would reject)."""
        r = self.rng
        name = self._name("fx")
        arity = r.randint(1, 3)
        params = [self._name("p") for _ in range(arity)]
        saved_scalars, saved_arrays, saved_fns = self.scalars, self.arrays, self.fns
        self.scalars, self.arrays = list(params), {}
        self.fns = dict(saved_fns)          # calls to earlier fns allowed (acyclic)
        body = self.expr(2)
        self.scalars, self.arrays, self.fns = saved_scalars, saved_arrays, saved_fns
        self.fns[name] = arity
        return f"fn {name}({', '.join(params)}) {{ return {body}; }}"

    def stmt(self, depth: int) -> str:
        r = self.rng
        k = r.random()
        if k < 0.4 or not self.scalars:
            n = self._name("t")
            e = self.expr(2)
            self.scalars.append(n)
            return f"let {n} = {e};"
        if k < 0.6:
            return f"{r.choice(self.scalars)} = {self.expr(2)};"
        if k < 0.75 and self.arrays:
            arr = r.choice(list(self.arrays))
            return f"{arr}[{self.expr(1)}] = {self.expr(2)};"
        if k < 0.82 and depth > 0:
            body = " ".join(self.stmt(depth - 1) for _ in range(r.randint(1, 2)))
            els = f"else {{ {self.stmt(depth - 1)} }}" if r.random() < 0.5 else ""
            return f"if {self.expr(1)} {{ {body} }} {els}"
        if k < 0.9 and self.loop_depth > 0:
            # break/continue somewhere inside a loop -- usually guarded, so the loop
            # still exercises later iterations on most paths
            kw = r.choice(["break", "continue"])
            return f"if {self.expr(1)} {{ {kw}; }}"
        if depth > 0 and r.random() < 0.5:
            # a for loop over a small constant range; break/continue may appear inside
            v = self._name("f")
            self.scalars.append(v)
            self.loop_depth += 1
            body = " ".join(self.stmt(depth - 1) for _ in range(r.randint(1, 2)))
            self.loop_depth -= 1
            return f"for {v} in {r.randint(-2, 2)}..{r.randint(0, 6)} {{ {body} }}"
        if depth > 0:
            # A definitely-terminating while. The counter increments FIRST, so a
            # generated `continue` in the body cannot skip it and spin forever; and the
            # body is generated BEFORE the counter exists, so nothing in it can assign
            # the counter either. Terminating by construction, break/continue included.
            bound = r.randint(0, 6)
            self.loop_depth += 1
            body = " ".join(self.stmt(depth - 1) for _ in range(r.randint(1, 2)))
            self.loop_depth -= 1
            c = self._name("k")
            self.scalars.append(c)
            return f"let {c} = 0; while {c} < {bound} {{ {c} = {c} + 1; {body} }}"
        return f"let {self._name('t')} = {self.expr(1)};"

    def program(self) -> tuple[str, int]:
        r = self.rng
        fn_decls = "\n".join(self.fn_decl() for _ in range(r.randint(0, 2)))
        n_in = r.randint(1, 4)
        self.scalars = [self._name("in") for _ in range(n_in)]
        header_inputs = "input " + ", ".join(self.scalars) + ";\n"
        arr_decls = ""
        for _ in range(r.randint(0, 2)):
            an = self._name("a")
            ln = r.randint(1, 4)
            self.arrays[an] = ln
            arr_decls += f"arr {an}[{ln}];\n"
        body = "\n".join(self.stmt(2) for _ in range(r.randint(1, 6)))
        outs = ", ".join(self.expr(2) for _ in range(r.randint(1, 3)))
        src = f"#steps 300000\n{fn_decls}\n{header_inputs}{arr_decls}{body}\noutput {outs};\n"
        return src, n_in


_INTERP_BUDGET = 300_000


def _gen_valid_program(seed: int):
    """Generate until one type-checks, returning (src, n_in, program, ast) so callers
    never recompile. Most generated programs are valid; a rare one is discarded."""
    for s in range(seed, seed + 50):
        g = _Gen(random.Random(s))
        src, n_in = g.program()
        try:
            prog = compile_source(src)
            ast = parse_program(src)
            return src, n_in, prog, ast
        except Exception:
            continue
    raise AssertionError(f"could not generate a valid program from seed {seed}")


def _inputs_for(rng: random.Random, n: int) -> list[int]:
    return [rng.choice(_EDGE_INPUTS) if rng.random() < 0.5 else rng.randint(INT64_MIN, INT64_MAX)
            for _ in range(n)]


@pytest.mark.parametrize("batch", range(0, 20))
def test_random_program_interp_equals_vm(batch):
    """20 batches x 20 programs x 8 inputs = 3200 differential checks. Each program is
    compiled and parsed ONCE, then run over many inputs directly on the VM and the
    interpreter -- no per-input recompilation, so this stays fast enough to live in the
    default suite."""
    for k in range(20):
        seed = batch * 20 + k
        src, n_in, prog, ast = _gen_valid_program(seed * 1009 + 1)
        rng = random.Random(seed * 7919 + 1)
        for _ in range(8):
            inp = _inputs_for(rng, n_in)
            try:
                vm = vm_run(prog, inp)
                trapped = False
            except Trap:
                trapped = True
            if trapped:
                with pytest.raises(Trap):
                    _interp.interpret(ast, inp, _INTERP_BUDGET)
            else:
                ref = _interp.interpret(ast, inp, _INTERP_BUDGET)
                assert vm == ref, f"seed={seed} DIVERGED\n{src}\ninputs={inp}\nvm={vm} interp={ref}"


@pytest.mark.skipif(not _HAS_NODE and not _REQUIRED, reason="node not installed")
def test_random_programs_also_agree_on_the_js_vm():
    """A smaller batch, checked three-way: interpreter, Python VM, JS VM."""
    cases, expected = [], []
    for seed in range(0, 60):
        src, n_in, prog, _ast = _gen_valid_program(seed * 2003 + 5)
        prog_text = json.dumps(prog)
        rng = random.Random(seed * 104729 + 3)
        for _ in range(3):
            inp = _inputs_for(rng, n_in)
            cases.append({"programText": prog_text, "inputs": [str(x) for x in inp]})
            try:
                py = run_source(src, inp)
                expected.append(("ok", [str(x) for x in py]))
            except Trap:
                expected.append(("trap", None))

    fd, name = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    tmp = Path(name)
    try:
        tmp.write_text(json.dumps(cases), encoding="utf-8")
        proc = subprocess.run(["node", str(_RUNNER), str(tmp)],
                              capture_output=True, text=True, timeout=180, check=False)
    finally:
        tmp.unlink(missing_ok=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    js = json.loads(proc.stdout.strip().splitlines()[-1])

    for (kind, val), got, case in zip(expected, js, cases):
        if kind == "trap":
            assert got.get("trap") is True, f"py trapped, js did not: {got} inputs={case['inputs']}"
        else:
            assert got.get("ok") == val, f"js {got} != py {val} inputs={case['inputs']}"
