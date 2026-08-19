"""The common path -- verifying a replay receipt -- must not load numpy.

WHY THIS EXISTS

A stranger's whole interaction with this package is usually one command:
verify one receipt. The great majority of receipts are `obsign/replay/1`, a
pure-int64 deterministic VM that never constructs an array. numpy is needed only
to re-execute the `tau_field_fixed` PDE kernel.

Importing numpy eagerly charged every one of those verifications ~50 ms of
array-library start-up for a library the replay path never calls. `kernel.py`
now imports numpy on first use, so the replay path pays nothing. This is a
start-up optimisation with NO effect on any verdict -- a tau receipt still loads
numpy and reproduces bit-for-bit -- so the only way it can regress is silently:
someone re-adds a module-level `import numpy` and the speed quietly evaporates
while every test still passes.

That is precisely what a gate is for. These run in a subprocess because this
test process has usually already imported numpy for other tests; `sys.modules`
is process-global and would mask the regression.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
ECL = REPO / "examples" / "ecl_receipt.json"


def _numpy_loaded_after(program: str) -> bool:
    """Run PROGRAM in a clean interpreter; return whether numpy ended up imported."""
    full = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        + program
        + "\nprint('NUMPY_LOADED' if 'numpy' in sys.modules else 'NUMPY_ABSENT')\n"
    )
    proc = subprocess.run([sys.executable, "-c", full],
                          capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith(("NUMPY_LOADED", "NUMPY_ABSENT")), proc.stdout
    return proc.stdout.strip().endswith("NUMPY_LOADED")


def test_importing_the_package_does_not_load_numpy():
    assert not _numpy_loaded_after("import obsign_verify"), (
        "importing obsign_verify pulled numpy -- a module-level `import numpy` "
        "crept back in, taxing every verification with array-library start-up")


def test_verifying_a_replay_receipt_does_not_load_numpy():
    program = (
        "from obsign_verify import load_receipt, verify\n"
        f"r = load_receipt(open({str(ECL)!r}).read())\n"
        "res = verify(r)\n"
        "assert r['kernel'] == 'obsign/replay/1', r['kernel']\n"
        "assert res['verified'] is True, res['notes']\n"
    )
    assert not _numpy_loaded_after(program), (
        "verifying a REPLAY receipt loaded numpy -- the replay path is pure int64 "
        "and must not depend on numpy; a kernel import leaked onto the hot path")


def test_a_tau_receipt_DOES_load_numpy_and_still_reproduces():
    """The counterweight: proving numpy is absent is only meaningful if the tau
    path still loads it and produces the identical hash. Otherwise the fastest way
    to pass the tests above is to break tau verification entirely."""
    program = (
        "import json\n"
        "from obsign_verify import data_path\n"
        "from obsign_verify.kernel import build_fixed_inputs, evolve, array_sha256\n"
        "v = json.loads(data_path('conformance_vectors.json').read_text())[0]\n"
        "out = evolve(build_fixed_inputs(v['params']))\n"
        "h = array_sha256(out)\n"
        "assert h.startswith('a50bef430f745b12'), h\n"
    )
    assert _numpy_loaded_after(program), (
        "the tau path did NOT load numpy -- either numpy vanished or tau "
        "verification is no longer exercising the kernel")
