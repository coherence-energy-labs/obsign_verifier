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

import rustbin

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
        f"a coarse-grained cell was called dead because the sweep stopped at the "
        f"first perturbation that moved a different cell: {res}")


def test_the_chain_cli_refuses_and_says_why(tmp_path):
    child, parent = _chain(_DECOY, src_offset=0)
    paths = []
    for name, receipt in (("child", child), ("parent", parent)):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(receipt), encoding="utf-8")
        paths.append(str(p))
    argv = [sys.executable, "-m", "obsign_verify.cli", "--chain", *paths]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=600,
                          check=False)
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


# --------------------------------------------------------------------------------
# THE RULE WAS TWO-VALUED AND THE CELL VERDICT IS THREE-VALUED
#
# Everything above tests the `dead` half. `dead` means the sweep RAN and the cell
# never moved; a cell the probe ran out of budget on is `indeterminate`, and
# `indeterminate` never refused. So the rule was switchable off by the party it
# constrains: the same child program, with ONE constant changed -- a spin loop long
# enough to cut the cell sweep short -- moved its laundered cell from `dead` to
# `indeterminate`, and a chain carrying the literal 424242 went from REFUSED to
# `graph_verified: true`. Cost decided it, not evidence.
#
# Measured before the fix, on programs differing in exactly that one constant:
#
#     spin=0       cells=['dead', 'live']            links_ok=False  graph=False
#     spin=20000   cells=['indeterminate', 'live']   links_ok=True   graph=TRUE
#
# The verdict is now three-valued, matching the cell verdict it reads:
#
#     any cell live  -> the link binds something that demonstrably moved
#     else any indeterminate (or the slice is not covered) -> INCOMPLETE
#     else all dead  -> FORGED
#
# `incomplete` is the verdict this graph already uses for "a child was not supplied":
# out of green without calling the producer a forger, which is the right answer for an
# honest receipt that is merely expensive to sweep. Under --strict-liveness there is
# no benefit of the doubt.

#: The smallest spin measured to cut the sweep short (0.10 s per verify). The tests
#: assert that precondition rather than trusting this number.
_SPIN = 20_000
_N_IN, _IN_BASE = 8, 16


def _costly_child_program(spin: int, constant_cell: bool) -> dict:
    """out[1] = sum(inputs), always live. out[0] is a literal, or a copy of the sum.

    `spin` is consts[3] and nothing else, so the cheap and costly variants of each
    program differ in exactly one number: the only thing that can explain a verdict
    change between them is the probe budget.
    """
    tail = [["LOADC", 0, 0]] if constant_cell else [["MOV", 0, 1]]
    return {
        "spec": "obsign/replay/1", "mem": 64, "steps": 8_000_000,
        "consts": [424242, 0, 1, spin, _IN_BASE, _N_IN],
        "input": {"offset": _IN_BASE, "length": _N_IN},
        "output": {"offset": 0, "length": 2},
        "code": [
            ["LOADC", 1, 1],      # 0  mem[1] = 0     accumulator -> cell 1
            ["LOADC", 2, 4],      # 1  mem[2] = 16    input pointer
            ["LOADC", 3, 1],      # 2  mem[3] = 0     counter
            ["LOADC", 4, 2],      # 3  mem[4] = 1
            ["LOADC", 5, 5],      # 4  mem[5] = 8
            ["LOAD", 6, 2],       # 5
            ["ADD", 1, 1, 6],     # 6
            ["ADD", 2, 2, 4],     # 7
            ["ADD", 3, 3, 4],     # 8
            ["LT", 7, 3, 5],      # 9
            ["JMPNZ", 7, 5],      # 10
            ["LOADC", 8, 3],      # 11 mem[8] = spin
            ["JMPZ", 8, 15],      # 12
            ["SUB", 8, 8, 4],     # 13
            ["JMP", 12],          # 14
            *tail,                # 15 cell 0: the literal, or the live sum
            ["HALT"],             # 16
        ],
    }


def _costly_chain(spin: int, constant_cell: bool):
    """A two-node chain whose parent consumes the child's output CELL 0."""
    prog = _costly_child_program(spin, constant_cell)
    child = mint.replay_receipt(prog, list(range(3, 3 + _N_IN)))
    link, values = mint.link(child, dst_offset=0, src_offset=0, length=1)
    parent_inputs = mint.compose_inputs(1, [(link, values)], base=[0])
    parent = mint.replay_receipt(compile_source("input x; output x + x;"),
                                 parent_inputs, links=[link])
    return child, parent


def test_the_budget_is_what_separates_dead_from_indeterminate():
    """The precondition the exploit rests on, asserted rather than assumed.

    Two programs differing in ONE constant must produce two different cell verdicts
    for the same laundered cell. If that stops holding, every test below is testing
    something other than what its name says.
    """
    cheap, _ = _costly_chain(0, constant_cell=True)
    costly, _ = _costly_chain(_SPIN, constant_cell=True)
    assert verify(cheap)["output_liveness_by_cell"] == ["dead", "live"]
    assert verify(costly)["output_liveness_by_cell"] == ["indeterminate", "live"], (
        f"spin={_SPIN} no longer exhausts the cell sweep, so the exploit this file "
        f"guards against is no longer constructible this way -- raise _SPIN")
    # ...and both receipts still VERIFY standalone. The chain is the only rung that
    # can tell them apart.
    assert verify(cheap)["verified"] is True
    assert verify(costly)["verified"] is True


def test_an_expensive_child_may_not_launder_a_constant():
    """THE EXPLOIT. `indeterminate` is not `live`, and a chain must not claim it is."""
    child, parent = _costly_chain(_SPIN, constant_cell=True)
    g = verify_graph([child, parent])
    assert g["complete"] is True, "every node was supplied; this is not an absence"
    assert all(n["verified"] for n in g["nodes"].values()), "both nodes re-derive"
    assert g["graph_verified"] is False, (
        "a chain carrying a literal reported CHAIN VERIFIED because the child was "
        "expensive to probe")
    notes = [n for node in g["nodes"].values() for n in node["notes"]]
    assert any("was not shown to depend on" in n for n in notes), notes


def test_an_unproven_slice_is_incomplete_and_a_constant_slice_is_forged():
    """The two refusals are spelled differently, in both directions.

    "I could not check this" and "this is false" are different facts, and this graph
    already distinguishes them for a missing child. Collapsing them here would either
    accuse an honest expensive producer of forgery, or let a real one hide behind the
    excuse -- so the distinction has to survive into the reported verdict, not only
    into the exit code.
    """
    cheap_child, cheap_parent = _costly_chain(0, constant_cell=True)
    costly_child, costly_parent = _costly_chain(_SPIN, constant_cell=True)
    forged_g = verify_graph([cheap_child, cheap_parent])
    unproven_g = verify_graph([costly_child, costly_parent])

    def links_of(g):
        return {n["links_ok"] for n in g["nodes"].values() if n["links_ok"] is not None}

    assert links_of(forged_g) == {False}, forged_g
    assert links_of(unproven_g) == {"incomplete"}, unproven_g
    assert forged_g["graph_verified"] is False and unproven_g["graph_verified"] is False


def test_an_expensive_HONEST_chain_is_still_accepted():
    """The other direction, and the reason `incomplete` is not simply `False`.

    A verifier that refuses everything is not a fix. The costly program whose linked
    cell is genuinely the sum of its inputs must still pass -- that cell moves on the
    first perturbation, so it reads `live` however early the sweep is cut off.
    """
    child, parent = _costly_chain(_SPIN, constant_cell=False)
    assert verify(child)["output_liveness_by_cell"][0] == "live"
    g = verify_graph([child, parent])
    assert g["graph_verified"] is True, g


def test_strict_liveness_reaches_the_chain_at_all():
    """`verify_graph(receipts)` took no flag, so `--chain --strict-liveness` parsed the
    switch, printed nothing different, and accepted exactly what `--chain` accepted.

    An auditor who sets a strictness that is never applied is worse off than one who
    knows the switch does not exist. This is the anti-inertness check: the flag must
    change a verdict on SOME input, and that input is a node whose whole liveness is
    `indeterminate` -- accepted by default, by design, and refusable on demand.
    """
    prog = _costly_child_program(_SPIN, constant_cell=True)
    # No decoy: nothing reaches the output window, so with the sweep cut short every
    # input reads `indeterminate` rather than `dead`.
    prog = dict(prog, output={"offset": 0, "length": 1})
    lone = mint.replay_receipt(prog, list(range(3, 3 + _N_IN)))
    assert verify(lone)["input_liveness"] == "indeterminate", verify(lone)

    assert verify_graph([lone])["graph_verified"] is True, (
        "the default must not refuse an honest receipt for being expensive to probe")
    strict = verify_graph([lone], strict_liveness=True)
    assert strict["graph_verified"] is False, (
        "--strict-liveness accepted a chain node that was never shown to depend on "
        "any declared input -- the switch is inert on the chain path")


def test_strict_liveness_does_not_refuse_a_live_chain():
    """...and it is not merely a refuse-everything switch."""
    child, parent = _costly_chain(_SPIN, constant_cell=False)
    assert verify_graph([child, parent], strict_liveness=True)["graph_verified"] is True


# --------------------------------------------------------------------------------
# ...AND EVERY SHIPPED CLI MUST REACH THAT VERDICT
#
# The rule above lived in three places and was tested in two. `js/src/graph.js` had it;
# `rust/src/graph.rs` did not have it AT ALL (`grep -c liveness rust/src/graph.rs` was
# 0), so on a chain the reference refuses with exit 1 the Rust CLI returned exit 0 --
# a forger's choice of verifier on the one rung a supply chain exists to establish.
# It survived because this file's legs were Python and JavaScript, and the JavaScript
# leg drives the LIBRARY.
#
# And the npm CLI had no `--chain` at all. `verifyGraph` shipped in the package; only
# the binary could not reach it. Verifying the same files one at a time exits 0 and
# prints VERIFIED for each, because a link naming a receipt the standalone ladder was
# never handed is not examined -- so the missing subcommand did not fail loudly, it
# agreed with the forgery.
#
# One test, three binaries, both directions.

_CHAIN_CLI_CASES = [
    ("laundered-constant", 0, True, 1),        # the slice is provably a constant
    ("laundered-indeterminate", _SPIN, True, 1),  # the slice was never decided
    ("honest-cheap", 0, False, 0),
    ("honest-costly", _SPIN, False, 0),
]


def _chain_files(tmp_path, tag, spin, constant_cell):
    child, parent = _costly_chain(spin, constant_cell)
    paths = []
    for name, receipt in ((f"{tag}_child", child), (f"{tag}_parent", parent)):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(receipt), encoding="utf-8")
        paths.append(str(p))
    return paths


@pytest.mark.parametrize("tag,spin,constant_cell,want", _CHAIN_CLI_CASES,
                         ids=[c[0] for c in _CHAIN_CLI_CASES])
def test_the_reference_cli_reaches_the_chain_verdict(tmp_path, tag, spin,
                                                     constant_cell, want):
    paths = _chain_files(tmp_path, tag, spin, constant_cell)
    proc = subprocess.run([sys.executable, "-m", "obsign_verify.cli", "--chain", *paths],
                          capture_output=True, text=True, encoding="utf-8",
                          timeout=600, check=False)
    assert proc.returncode == want, proc.stdout


@_needs_node
@pytest.mark.parametrize("tag,spin,constant_cell,want", _CHAIN_CLI_CASES,
                         ids=[c[0] for c in _CHAIN_CLI_CASES])
def test_the_npm_cli_has_a_chain_subcommand_and_agrees(tmp_path, tag, spin,
                                                       constant_cell, want):
    """`obsign-verify --chain` from the published package, not the library behind it.

    The failure this guards is not "--chain errors": it is that WITHOUT --chain the
    same files verify one at a time and exit 0, so the absent subcommand agreed with
    the forgery instead of refusing to answer.
    """
    cli = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "js", "bin", "obsign-verify.js")
    paths = _chain_files(tmp_path, tag, spin, constant_cell)
    proc = subprocess.run(["node", cli, "--chain", *paths], capture_output=True,
                          text=True, encoding="utf-8", timeout=600, check=False)
    assert proc.returncode == want, proc.stdout + proc.stderr
    if want:
        assert "CHAIN" in proc.stdout and "VERIFIED - every node" not in proc.stdout, \
            proc.stdout


@pytest.mark.parametrize("tag,spin,constant_cell,want", _CHAIN_CLI_CASES,
                         ids=[c[0] for c in _CHAIN_CLI_CASES])
def test_the_rust_cli_reaches_the_same_chain_verdict(tmp_path, tag, spin,
                                                     constant_cell, want):
    """The leg that was missing. Built here, so a binary predating the source it is
    meant to be testing cannot pass by being old."""
    exe = rustbin.rust_binary_or_skip()
    paths = _chain_files(tmp_path, tag, spin, constant_cell)
    proc = subprocess.run([str(exe), "--chain", *paths], capture_output=True,
                          text=True, encoding="utf-8", timeout=600, check=False)
    assert proc.returncode == want, proc.stdout + proc.stderr


def test_verifying_the_nodes_one_at_a_time_is_not_a_chain_check(tmp_path):
    """Why the missing subcommand was worse than an error.

    Both receipts in the laundering chain verify STANDALONE -- that is the whole point
    of the attack -- so a user handed a chain and a CLI without `--chain` gets exit 0
    and two VERIFIED lines. The gap this closes is silent by construction.
    """
    paths = _chain_files(tmp_path, "solo", 0, True)
    solo = subprocess.run([sys.executable, "-m", "obsign_verify.cli", *paths],
                          capture_output=True, text=True, encoding="utf-8",
                          timeout=600, check=False)
    assert solo.returncode == 0, solo.stdout
    chained = subprocess.run(
        [sys.executable, "-m", "obsign_verify.cli", "--chain", *paths],
        capture_output=True, text=True, encoding="utf-8", timeout=600, check=False)
    assert chained.returncode == 1, chained.stdout
