"""A hostile GRAPH must be refused, not allowed to kill the verifier.

`verify_graph`'s own docstring says it "Never raises on hostile input -- an
exception is not a refusal, on a graph exactly as on a single receipt". It does
raise. The link walk is a recursive depth-first search with no depth bound and no
guard around it, so the depth of the recursion is the length of the chain the
attacker supplies:

    RecursionError: maximum recursion depth exceeded    (Python, ~2,000 nodes)
    RangeError: Maximum call stack size exceeded        (Node, ~20,000 nodes)

Neither is a verdict. `obsign-verify --chain` calls `verify_graph` with no
try/except, so a stranger handed a stack of small receipts gets a traceback and an
exit code that means "crashed", not "refused"; a service that embeds the function
gets an unhandled exception. The receipts need not verify, need not be integral and
need not even name a real child -- only the `receipt_sha256` fields have to chain,
and those are public math anyone can compute.

`rust/src/graph.rs` already walks with an explicit stack, and says why: "a stack
overflow is a crash rather than a refusal". Python and JavaScript are the outliers.

The same walk has a second, cheaper crash: it reads `ln["receipt_sha256"]` raw and
asks `child in nodes` without ever checking that the value is a string. A link whose
target is a JSON array or object is unhashable, so ONE ~250-byte receipt raises
`TypeError: unhashable type: 'list'` out of the same function. `_well_formed_link`
exists and rejects exactly this -- but only `check_links` calls it; the reachability
walk and the `referenced` set comprehension do not. JavaScript keys its node table
with a Map and shrugs, so this is a Python-only refusal-to-refuse.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from obsign_verify.canonical import canonical_sha256, claim_of
from obsign_verify.graph import verify_graph

REPO = Path(__file__).resolve().parent.parent
_HAS_NODE = shutil.which("node") is not None
_REQUIRED = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_needs_node = pytest.mark.skipif(
    not _HAS_NODE and "node" not in _REQUIRED,
    reason="node not available (set OBSIGN_REQUIRE=node to make this leg mandatory)")


def _chain(n: int) -> list[dict]:
    """N receipts in a line, each linking to the next, built leaf-first so every
    link names a digest that really is in the set. Root first, so the walk enters
    at the deep end."""
    nodes: list[dict] = []
    child: str | None = None
    for k in range(n):
        claim: dict = {"spec": "obsign/receipt/v1", "kernel": "chain/depth", "n": k}
        if child is not None:
            claim["params"] = {"links": [{"receipt_sha256": child,
                                          "output_sha256": "0" * 64,
                                          "src_offset": 0, "length": 1,
                                          "dst_offset": 0}]}
        digest = canonical_sha256(claim_of(claim))
        nodes.append(dict(claim, receipt_sha256=digest))
        child = digest
    nodes.reverse()
    return nodes


def test_a_deep_chain_is_refused_rather_than_crashing_the_verifier():
    """THE EXPLOIT. Well past CPython's default recursion limit, and every node is
    about 200 bytes."""
    depth = sys.getrecursionlimit() * 3
    graph = _chain(depth)
    result = verify_graph(graph)          # must not raise
    assert result["graph_verified"] is False, result["notes"]
    assert len(result["nodes"]) == depth


def test_the_chain_cli_exits_with_a_verdict_not_a_traceback(tmp_path):
    """The interface is the exit code. A traceback is neither 0 nor 1 on purpose.

    THE DEPTH IS THE POINT, SO THE DEPTH IS NOT REDUCED. Naming ~3,000 absolute paths
    in argv is past Windows' 8,191-character command line, and the CLI then died with
    `[WinError 206] The filename or extension is too long` -- a refusal to RUN, which
    is not a verdict either, and which would have read as "the deep-chain guard fails
    on Windows" when the guard was never reached. Lowering the depth would have made
    the test pass by no longer exercising the property it exists for.

    `--chain-list FILE` delivers the same argument list through a channel with no
    length limit, and exists in all three CLIs for exactly this reason.
    """
    listing = tmp_path / "chain.txt"
    names = []
    for i, receipt in enumerate(_chain(sys.getrecursionlimit() * 3)):
        p = tmp_path / f"r{i:05d}.json"
        p.write_text(json.dumps(receipt), encoding="utf-8")
        names.append(p.name)
    listing.write_text("\n".join(names), encoding="utf-8")
    assert len(names) > 2000, "precondition: the chain is deep enough to overflow argv"

    proc = subprocess.run([sys.executable, "-m", "obsign_verify.cli", "--chain",
                           "--quiet", "--chain-list", listing.name],
                          cwd=tmp_path, capture_output=True, text=True,
                          encoding="utf-8", timeout=1800, check=False)
    assert proc.returncode == 1, (proc.returncode, proc.stdout[-2000:],
                                  proc.stderr[-2000:])
    assert "Traceback" not in proc.stderr, proc.stderr[-2000:]


def test_the_chain_list_option_reads_the_same_receipts_argv_would(tmp_path):
    """`--chain-list` must be the argument list, not a second, laxer door.

    A transport that quietly dropped receipts would make the test above pass by
    verifying a SHORTER chain -- the exact failure the option exists to prevent. So a
    chain small enough for argv is run BOTH ways and the two reports are compared
    node for node.
    """
    receipts = _chain(6)
    names = []
    for i, receipt in enumerate(receipts):
        p = tmp_path / f"n{i:03d}.json"
        p.write_text(json.dumps(receipt), encoding="utf-8")
        names.append(p.name)
    (tmp_path / "list.txt").write_text(
        "# a comment and a blank line must be ignored\n\n" + "\n".join(names) + "\n",
        encoding="utf-8")

    def run(argv):
        return subprocess.run([sys.executable, "-m", "obsign_verify.cli", "--chain",
                               "--json", *argv], cwd=tmp_path, capture_output=True,
                              text=True, encoding="utf-8", timeout=600, check=False)

    direct = run(names)
    listed = run(["--chain-list", "list.txt"])
    assert direct.returncode == listed.returncode, (direct.stderr, listed.stderr)
    assert json.loads(direct.stdout) == json.loads(listed.stdout), (
        "--chain-list produced a different graph than the same paths in argv")
    assert len(json.loads(listed.stdout)["nodes"]) == len(receipts)


def test_a_shallow_chain_still_walks_and_still_reports_the_cycle_rules():
    """The fix must not cost the walk its ordering or its verdicts."""
    graph = _chain(5)
    result = verify_graph(graph)
    assert len(result["order"]) == 5
    # children-first: the leaf (no links) finishes before the root that names it
    assert result["order"][-1] == graph[0]["receipt_sha256"]
    assert result["graph_verified"] is False


@_needs_node
def test_javascript_also_refuses_rather_than_overflowing(tmp_path):
    depth = 20000
    graph = tmp_path / "graph.json"
    graph.write_text(json.dumps(_chain(depth)), encoding="utf-8")
    runner = tmp_path / "run.mjs"
    runner.write_text(
        "import { readFileSync } from 'node:fs';\n"
        "import { createRequire } from 'node:module';\n"
        "const require = createRequire(import.meta.url);\n"
        f"const {{ verifyGraph }} = require({str(REPO / 'js' / 'src' / 'graph.js')!r});\n"
        f"const {{ loadReceipt }} = require({str(REPO / 'js' / 'src' / 'canonical.js')!r});\n"
        "const raw = JSON.parse(readFileSync(process.argv[2], 'utf8'));\n"
        "const rs = raw.map((r) => loadReceipt(JSON.stringify(r)));\n"
        "const g = verifyGraph(rs);\n"
        "console.log(JSON.stringify({ graph_verified: g.graph_verified,"
        " nodes: Object.keys(g.nodes).length }));\n",
        encoding="utf-8")
    proc = subprocess.run(["node", str(runner), str(graph)],
                          capture_output=True, text=True, timeout=1800, check=False)
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out == {"graph_verified": False, "nodes": depth}, out


@pytest.mark.parametrize("target", [[], {}, {"a": 1}, 7, None, True],
                         ids=["list", "object", "object-with-member", "int", "null",
                              "bool"])
def test_a_link_target_that_is_not_a_digest_is_refused_not_raised(target):
    """THE CHEAPER EXPLOIT. One receipt, no chain, no depth: the reachability walk
    asks `child in nodes` on whatever the JSON carried, and an unhashable value takes
    the verifier down instead of being refused as malformed."""
    claim = {"spec": "obsign/receipt/v1", "kernel": "obsign/replay/1",
             "params": {"links": [{"receipt_sha256": target, "output_sha256": "0" * 64,
                                   "src_offset": 0, "length": 1, "dst_offset": 0}]}}
    receipt = dict(claim, receipt_sha256=canonical_sha256(claim_of(claim)))
    result = verify_graph([receipt])          # must not raise
    assert result["graph_verified"] is False
    node = result["nodes"][receipt["receipt_sha256"]]
    assert node["links_ok"] is False, node
    assert any("receipt_sha256" in n for n in node["notes"]), node["notes"]
