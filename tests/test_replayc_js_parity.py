"""The compiler's output must run identically on the OTHER VM.

The whole point of a replay program is that any independent implementation re-derives
the same bytes. A program this compiler emits is no exception: it has to reproduce on
the JavaScript VM exactly what it reproduces on the Python one, or a receipt minted
with the compiler would verify for its author and read as forged for everyone using the
browser verifier. This runs a battery of compiled programs and inputs through both VMs
(and the reference interpreter) and requires all three to agree -- on the number when
it succeeds, and on refusing when it traps.

Skipped when Node is absent, failed when OBSIGN_REQUIRE=node (CI sets it), matching the
other cross-language gates in this repo.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from obsign_verify.replay import Trap, output_sha256
from obsign_verify.replayc import compile_source, interpret_source, run_source

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = "node" in {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_RUNNER = Path(__file__).resolve().parent / "replayc_js_runner.mjs"
CONF = Path(__file__).resolve().parent.parent / "src/obsign_verify/data/conformance/producer_signed_replay.json"

# (source, [input vectors]) -- a spread of features, signs and edge magnitudes
_BATTERY = [
    ("input a,b; output a+b, a-b, a*b, a&b, a|b, a^b;", [[3, 5], [-9, 7], [(1 << 62), (1 << 62)]]),
    ("input a,b; output a/b, a%b;", [[20, 6], [-20, 6], [20, -6], [-20, -6]]),
    ("input x; output mulfx(x, x, 16), mulfx(x, x, 32);", [[123456], [-987654], [1 << 40]]),
    ("input x; let r=0; if x<0 { r=0-x; } else { r=x; } output r, abs(x);", [[-5], [5], [0]]),
    ("#steps 100000\ninput n; let a=0; let i=1; while i<=n { a=a+i; i=i+1; } output a;", [[0], [10], [1000]]),
    ("#steps 100000\ninput v[6]; let s=0; let i=0; while i<6 { s=s+v[i]; i=i+1; } output s;",
     [[1, 2, 3, 4, 5, 6], [-1, -2, -3, -4, -5, -6]]),
    ("input a,b; output a<<b, a>>b;", [[1, 10], [-1, 5], [(1 << 40), 20]]),
    ("input a,b; output min(a,b), max(a,b), sel(a,b,99);", [[3, 7], [0, 7], [-2, 7]]),
    ("input x; arr a[3]; a[0]=1; output a[x];", [[0], [3], [-1]]),      # includes OOB -> TRAP
]


def _run_js(cases: list[dict]) -> list[dict]:
    tmp = Path(subprocess.run(["mktemp"], capture_output=True, text=True).stdout.strip())
    try:
        tmp.write_text(json.dumps(cases), encoding="utf-8")
        proc = subprocess.run(["node", str(_RUNNER), str(tmp)],
                              capture_output=True, text=True, timeout=120, check=False)
    finally:
        tmp.unlink(missing_ok=True)
    assert proc.returncode == 0, f"js runner failed:\n{proc.stdout}\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(not _HAS_NODE and not _REQUIRED, reason="node not installed")
def test_compiled_programs_agree_on_python_and_js_vms():
    assert _HAS_NODE, "OBSIGN_REQUIRE=node was set but node is not installed"

    cases, expected = [], []
    for src, inputs in _BATTERY:
        prog = compile_source(src)
        program_text = json.dumps(prog)
        for inp in inputs:
            cases.append({"programText": program_text, "inputs": [str(x) for x in inp]})
            try:
                py = run_source(src, inp)
                ref = interpret_source(src, inp)
                assert py == ref, f"interp != python-vm for {src!r} {inp}"
                expected.append(("ok", [str(x) for x in py]))
            except Trap:
                with pytest.raises(Trap):
                    interpret_source(src, inp)
                expected.append(("trap", None))

    js = _run_js(cases)
    assert len(js) == len(expected)
    for (kind, val), got, case in zip(expected, js, cases):
        if kind == "trap":
            assert got.get("trap") is True, f"expected TRAP on js, got {got} for inputs {case['inputs']}"
        else:
            assert got.get("ok") == val, f"js {got} != python {val} for inputs {case['inputs']}"


@pytest.mark.skipif(not _HAS_NODE and not _REQUIRED, reason="node not installed")
def test_cecl_output_hash_matches_on_js_vm_too():
    """The external anchor, on the JS side: the compiled CECL program reproduces the
    hand-authored receipt's output hash under the JavaScript VM as well."""
    receipt = json.loads(CONF.read_text())
    inputs = receipt["params"]["inputs"]
    src = ("#steps 100000\ninput v[13];\nlet n=v[0]; let acc=0; let i=0;\n"
           "while i<n { let base=i*3+1; let el=mulfx(v[base],v[base+1],32);"
           " acc=acc+mulfx(el,v[base+2],32); i=i+1; }\noutput acc;")
    prog = compile_source(src)
    js = _run_js([{"programText": json.dumps(prog), "inputs": [str(x) for x in inputs]}])[0]
    assert "ok" in js, f"js run failed: {js}"
    got = [int(x) for x in js["ok"]]
    assert output_sha256(got) == receipt["output"]["sha256"]
    assert got == run_source(src, inputs)
