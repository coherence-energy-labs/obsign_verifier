"""Three CLIs, one argv. A mistyped switch may not become a filename.

`obsign-verify`, `obsign-verify` (npm) and `obsign-verify-rs` are handed the same
command lines by the same operators and the same CI jobs. Every place they disagree
about what an argument MEANS is a place a run does something other than what was asked
-- and unlike a receipt-level split, this one has no cryptography behind it to catch it.

WHAT WAS MEASURED, before this file existed:

  --totally-bogus R      py exit 2 (usage)  |  npm exit 1  |  rust exit 1
  --strict-livenes R     py exit 0 (!)      |  npm exit 1  |  rust exit 1
  --help                 py exit 0 (usage)  |  npm exit 0  |  rust exit 1 ("cannot read")
  --json R               py exit 0 (JSON)   |  npm exit 0  |  rust exit 1 ("cannot read")

Three separate defects, one shape:

1. THE CATCH-ALL. npm and Rust pushed every unrecognised argument onto the FILE list,
   so a mistyped flag became a path, failed to open, and was reported as a refused
   RECEIPT. It fails closed -- the only reason this is a defect and not a breach -- but
   the diagnosis is wrong in the direction that matters: the strictness the operator
   asked for was never applied, and the run says "a file failed", which in a
   multi-receipt run reads as one bad receipt among many.

2. ARGPARSE ABBREVIATION. The reference accepted `--strict-livenes` as an unambiguous
   prefix, so the same argv meant two different things. An abbreviation is unambiguous
   only until the next flag is added: a later `--strict-mode` would silently repoint
   every script writing `--strict`, with no diagnostic on either side of the change.
   `allow_abbrev=False`.

3. MISSING SURFACE. The Rust CLI had neither `--help` nor `--json`. A tool whose help
   is an error is one a first-time user concludes is broken, and a tool with no machine
   output cannot be scripted -- which for the third implementation of a verifier means
   nobody scripts the third implementation.

Both directions in every row: a REAL flag must still work, or this file would pass with
three CLIs that reject everything.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import rustbin
from obsign_verify import data_path

REPO = Path(__file__).resolve().parent.parent
RECEIPT = data_path("conformance") / "producer_signed_replay.json"

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_needs_node = pytest.mark.skipif(
    not _HAS_NODE and "node" not in _REQUIRED,
    reason="node not available (set OBSIGN_REQUIRE=node to make this leg mandatory)")


def _python(argv):
    return [sys.executable, "-m", "obsign_verify.cli", *argv]


def _npm(argv):
    return ["node", str(REPO / "js" / "bin" / "obsign-verify.js"), *argv]


def _rust(argv):
    return [str(rustbin.rust_binary_or_skip()), *argv]


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          timeout=600, check=False, cwd=str(REPO))


#: (argv, expected exit code). Exit code is the whole interface -- a note on stdout is
#: documentation, and documentation is not a control.
CASES = [
    pytest.param(["--totally-bogus", str(RECEIPT)], 2, id="unknown-flag"),
    pytest.param(["--strict-livenes", str(RECEIPT)], 2, id="mistyped-real-flag"),
    pytest.param(["--stric", str(RECEIPT)], 2, id="prefix-of-a-real-flag"),
    pytest.param(["--help"], 0, id="help"),
    pytest.param([str(RECEIPT)], 0, id="honest-receipt"),
    pytest.param(["--json", str(RECEIPT)], 0, id="json"),
    pytest.param(["--strict-liveness", str(RECEIPT)], 0, id="real-flag-still-works"),
    pytest.param(["--chain", str(RECEIPT)], 0, id="chain"),
    pytest.param(["--expect-program"], 2, id="flag-with-no-value"),
]


@pytest.mark.parametrize("argv,want", CASES)
def test_the_reference_cli(argv, want):
    proc = _run(_python(argv))
    assert proc.returncode == want, f"{argv}\n{proc.stdout}\n{proc.stderr}"


@_needs_node
@pytest.mark.parametrize("argv,want", CASES)
def test_the_npm_cli_agrees(argv, want):
    proc = _run(_npm(argv))
    assert proc.returncode == want, f"{argv}\n{proc.stdout}\n{proc.stderr}"


@pytest.mark.parametrize("argv,want", CASES)
def test_the_rust_cli_agrees(argv, want):
    proc = _run(_rust(argv))
    assert proc.returncode == want, f"{argv}\n{proc.stdout}\n{proc.stderr}"


def test_a_mistyped_switch_is_never_reported_as_a_bad_receipt():
    """The DIAGNOSIS, not just the exit code.

    Failing closed is not enough. `[REFUSED] --strict-livenes / cannot read` tells the
    operator a receipt was rejected, when what happened is that the flag they asked for
    was silently dropped. Those two facts lead to opposite next actions.
    """
    for build in (_python, _npm, _rust):
        try:
            cmd = build(["--strict-livenes", str(RECEIPT)])
        except Exception:                       # pragma: no cover - skip propagates
            raise
        proc = _run(cmd)
        blob = (proc.stdout + proc.stderr).lower()
        assert "cannot read" not in blob and "not a receipt" not in blob, (
            f"{cmd[0]} reports a mistyped SWITCH as an unreadable RECEIPT:\n{blob}")
        assert ("unrecognized" in blob or "unrecognised" in blob), (
            f"{cmd[0]} does not say which argument it did not understand:\n{blob}")


@_needs_node
def test_all_three_emit_parseable_json_with_the_fields_a_reader_acts_on():
    """`--json` is the scripted interface, and the Rust CLI simply did not have one.

    The three need not be byte-identical -- the reference prints an indented object --
    but a caller must be able to parse each and find the same rungs, or the third
    implementation is unusable from anything but a terminal.
    """
    want = {"verified", "integrity", "reproduced", "unsupported", "approved_program",
            "signature", "notes"}
    for build in (_python, _npm, _rust):
        proc = _run(build(["--json", str(RECEIPT)]))
        assert proc.returncode == 0, proc.stderr
        doc = json.loads(proc.stdout)
        rows = doc if isinstance(doc, list) else [doc]
        assert rows, f"{build.__name__} emitted no rows"
        missing = want - set(rows[0])
        assert not missing, f"{build.__name__} --json omits {sorted(missing)}"
        assert rows[0]["verified"] is True, rows[0]
