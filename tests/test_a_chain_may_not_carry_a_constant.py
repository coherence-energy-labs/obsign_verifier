"""A chain that verifies must not be carrying a hardcoded number.

`verify()` refuses a receipt whose output ignores every declared input -- "a constant
dressed as a computation". An output WINDOW is a vector, and that verdict is about
the whole vector, so the refusal is defeated by one extra cell:

    input a, b;  output 424242, a + b;

Cell 1 echoes the inputs, so every input is "live", the receipt verifies, and the
notes say nothing is wrong. A docs/GRAPHS.md link then takes `src_offset 0,
length 1` -- the CONSTANT -- into its parent, and `obsign-verify --chain` printed

    [VERIFIED] af08ea050413abe9..
    [VERIFIED] d338e56cdce809c3..  links OK
    CHAIN VERIFIED - every node re-derived, every link binds        (exit 0)

over a supply chain whose whole payload is a number the author typed in. Every
individual rule held: both nodes re-derive, the link's `output_sha256` matches the
child's re-derived output, the parent really did consume those values. The chain was
still false.

THE FIX IS THE SAME RULE, APPLIED TO THE SLICE THAT TRAVELS. The probe now records
which output CELLS moved, and a link whose entire source slice never moved under any
perturbation is refused. Cells the probe could not decide stay "indeterminate" and
never refuse, exactly as an indeterminate node verdict does not -- and a cell may
only be called dead after the perturbation ladder has been run to the end, because
the per-input pass stops at the first perturbation that moves ANYTHING and that
proves nothing about a cell it did not happen to disturb.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

from obsign_verify import mint
from obsign_verify.graph import verify_graph
from obsign_verify.replayc import compile_source
from obsign_verify.verify import verify

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_needs_node = pytest.mark.skipif(
    not _HAS_NODE and "node" not in _REQUIRED,
    reason="node not available (set OBSIGN_REQUIRE=node to make this leg mandatory)")

#: cell 0 is the "answer" and is hardcoded; cell 1 is a decoy that echoes the inputs
#: purely so the liveness rung has something to see.
_DECOY = "input a, b; output 424242, a + b;"
#: the honest shape: the cell the parent consumes is the computed one
_HONEST = "input a, b; output a * b, a + b;"


def _chain(child_src: str, src_offset: int):
    child = mint.replay_receipt(compile_source(child_src), [5, 7])
    link, values = mint.link(child, dst_offset=0, src_offset=src_offset, length=1)
    parent_inputs = mint.compose_inputs(2, [(link, values)], base=[0, 3])
    parent = mint.replay_receipt(compile_source("input x, y; output x * y;"),
                                 parent_inputs, links=[link])
    return child, parent


def test_the_decoy_cell_does_not_hide_a_constant_from_the_node_verdict():
    """Precondition, and the reason the whole-window verdict cannot carry this: the
    child really does verify, and really is reported live on both its inputs."""
    child, _ = _chain(_DECOY, src_offset=0)
    res = verify(child)
    assert res["verified"] is True
    assert res["input_liveness"] == "live"
    assert res["input_liveness_by_input"] == ["live", "live"]
    # ...and the per-cell answer is where the constant becomes visible.
    assert res["output_liveness_by_cell"] == ["dead", "live"], res


def test_a_link_that_carries_a_constant_is_refused():
    """THE EXPLOIT. Every node verifies, every link binds value-for-value, and the
    number travelling the chain is a literal."""
    child, parent = _chain(_DECOY, src_offset=0)
    g = verify_graph([child, parent])
    assert g["complete"] is True, "not an incompleteness: every node was supplied"
    assert all(n["verified"] for n in g["nodes"].values()), "both nodes re-derive"
    assert g["graph_verified"] is False, (
        "a chain whose payload is a hardcoded constant reported CHAIN VERIFIED")
    notes = [n for node in g["nodes"].values() for n in node["notes"]]
    assert any("never moved" in n for n in notes), notes


def test_the_same_chain_over_the_computed_cell_still_verifies():
    """The fix must cost an honest chain nothing."""
    child, parent = _chain(_HONEST, src_offset=0)
    g = verify_graph([child, parent])
    assert g["graph_verified"] is True, g


def test_linking_the_live_cell_of_the_decoy_program_still_verifies():
    """Only the CONSTANT slice is refused, not the whole receipt: the decoy program's
    cell 1 is genuinely a function of its inputs and may be consumed."""
    child, parent = _chain(_DECOY, src_offset=1)
    g = verify_graph([child, parent])
    assert g["graph_verified"] is True, g


def test_a_cell_is_only_called_dead_after_the_whole_ladder_has_run():
    """The soundness condition on the fix. The per-input pass stops at the first
    perturbation that moves anything, so a cell that only responds to a LARGER
    perturbation would be falsely reported dead if the sweep stopped there -- and a
    parent linking it would be falsely accused."""
    # cell 0 responds only to a perturbation of ~a/2 or more; cell 1 to any.
    src = "input a, b; output a / 100000000 + b * 0, a + b;"
    child = mint.replay_receipt(compile_source(src), [743_215_600_000, 7])
    res = verify(child)
    assert res["output_liveness_by_cell"][0] == "live", (
        "a coarse-grained cell was called dead because the sweep stopped at the "
        "first perturbation that moved a different cell", res)


def test_the_chain_cli_refuses_and_says_why(tmp_path):
    child, parent = _chain(_DECOY, src_offset=0)
    paths = []
    for name, receipt in (("child", child), ("parent", parent)):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(receipt), encoding="utf-8")
        paths.append(str(p))
    proc = subprocess.run([sys.executable, "-m", "obsign_verify.cli", "--chain", *paths],
                          capture_output=True, text=True, timeout=600, check=False)
    assert proc.returncode == 1, proc.stdout
    assert "CHAIN REFUSED" in proc.stdout, proc.stdout
    assert "never moved" in proc.stdout, proc.stdout


@_needs_node
def test_javascript_refuses_the_same_chain(tmp_path):
    child, parent = _chain(_DECOY, src_offset=0)
    graph = tmp_path / "graph.json"
    graph.write_text(json.dumps([child, parent]), encoding="utf-8")
    runner = tmp_path / "run.mjs"
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    runner.write_text(
        "import { readFileSync } from 'node:fs';\n"
        "import { createRequire } from 'node:module';\n"
        "const require = createRequire(import.meta.url);\n"
        f"const {{ verifyGraph }} = require({os.path.join(repo, 'js/src/graph.js')!r});\n"
        f"const {{ loadReceipt }} = require({os.path.join(repo, 'js/src/canonical.js')!r});\n"
        "const raw = JSON.parse(readFileSync(process.argv[2], 'utf8'));\n"
        "const g = verifyGraph(raw.map((r) => loadReceipt(JSON.stringify(r))));\n"
        "console.log(JSON.stringify({ graph_verified: g.graph_verified,\n"
        "  notes: Object.values(g.nodes).flatMap((n) => n.notes) }));\n",
        encoding="utf-8")
    proc = subprocess.run(["node", str(runner), str(graph)],
                          capture_output=True, text=True, timeout=600, check=False)
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["graph_verified"] is False, out
    assert any("never moved" in n for n in out["notes"]), out
