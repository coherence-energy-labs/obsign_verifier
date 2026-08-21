"""Randomised chain fuzzing: honest graphs verify, corrupted graphs never do.

The hand-written battery attacks the chain rule where I expect it to be attacked.
This attacks it where I don't: random layered DAGs -- random small programs, random
fan-in, random slice offsets, multi-output children -- minted honestly through the
public API, then hit with ONE random corruption from a menu. The properties held:

  1. every honestly minted graph is graph_verified (no false refusals), and
  2. no corrupted graph is graph_verified (no false chains), with the verdict
     landing in the right CLASS: incomplete when the corruption orphans a link,
     refused when it forges one.

Seeded, so a failure prints what reproduces it. The generator only builds DAGs --
which is not a fuzzer limitation but the format's own theorem: links name claim
hashes, so cycles are unconstructible (see test_graph.py's impossibility tests).
"""
from __future__ import annotations

import random

import pytest

from obsign_verify import mint
from obsign_verify.canonical import canonical_sha256, claim_of
from obsign_verify.graph import verify_graph
from obsign_verify.replayc import compile_source

#: small program templates by (n_inputs, n_outputs) -- all input-live
_PROGS = {}


def _prog(n_in: int, n_out: int) -> dict:
    key = (n_in, n_out)
    if key not in _PROGS:
        ins = ", ".join(f"x{i}" for i in range(n_in))
        outs = []
        for j in range(n_out):
            terms = " + ".join(f"x{i} * {((i + j) % 5) + 1}" for i in range(n_in))
            outs.append(f"({terms} + {j})")
        _PROGS[key] = compile_source(f"input {ins}; output {', '.join(outs)};")
    return _PROGS[key]


def _build_random_dag(rng: random.Random):
    """Layered DAG: each node consumes random slices of earlier nodes' outputs."""
    receipts = []
    outputs_meta = []                       # (receipt, n_outputs)
    n_nodes = rng.randint(2, 6)
    for k in range(n_nodes):
        n_out = rng.randint(1, 3)
        max_links = min(k, rng.randint(0, 2))
        links, base_positions = [], []
        n_in = rng.randint(max(1, max_links), max_links + 2)
        # choose distinct destination slots for each link (length-1 slices keep the
        # generator simple; multi-length slices are covered by the hand battery)
        dst_slots = rng.sample(range(n_in), k=max_links) if max_links else []
        linked = []
        for d in dst_slots:
            child, child_outs = outputs_meta[rng.randrange(len(outputs_meta))]
            src = rng.randrange(child_outs)
            block, values = mint.link(child, dst_offset=d, src_offset=src, length=1)
            linked.append((block, values))
            links.append(block)
        base = [rng.randint(-1000, 1000) for _ in range(n_in)]
        inputs = mint.compose_inputs(n_in, linked, base=base)
        r = mint.replay_receipt(_prog(n_in, n_out), inputs, links=links)
        receipts.append(r)
        outputs_meta.append((r, n_out))
    return receipts


def _corrupt(rng: random.Random, receipts: list) -> str:
    """Apply ONE random corruption; return which class of verdict it must cause."""
    kind = rng.choice(["tamper_leaf", "forge_values", "wrong_outhash", "withhold"])
    linked_parents = [r for r in receipts if (r.get("params") or {}).get("links")]
    if kind == "withhold" or not linked_parents:
        # withhold a receipt something links to (fall back if nothing has links)
        targets = {ln["receipt_sha256"] for r in linked_parents
                   for ln in r["params"]["links"]}
        victims = [r for r in receipts if r["receipt_sha256"] in targets]
        if victims:
            receipts.remove(rng.choice(victims))
            return "incomplete"
        receipts.pop(rng.randrange(len(receipts)))
        return "any"                        # nothing linked it: removal may stay green
    parent = rng.choice(linked_parents)
    # forging a node CHANGES ITS DIGEST, which also orphans every link pointing AT it
    # -- the immutability theorem applying to the attacker's own edit. So a forgery on
    # a node others reference is refused AND disconnects its consumers; only a forgery
    # on an unreferenced root is a "pure" refusal with the graph still complete.
    referenced = {ln["receipt_sha256"] for r in linked_parents for ln in r["params"]["links"]}
    parent_is_referenced = parent["receipt_sha256"] in referenced
    if kind == "tamper_leaf":
        # tamper the CHILD of one of parent's links (and reseal: internally true,
        # but its digest moves, orphaning the link)
        digest = rng.choice(parent["params"]["links"])["receipt_sha256"]
        child = next(r for r in receipts if r["receipt_sha256"] == digest)
        child["params"]["inputs"][0] += 1
        # keep it internally consistent: recompute output + hash by re-minting
        fixed = mint.replay_receipt(child["params"]["program"], child["params"]["inputs"],
                                    links=child["params"].get("links", ()))
        receipts[receipts.index(child)] = fixed
        return "incomplete"
    if kind == "forge_values":
        ln = rng.choice(parent["params"]["links"])
        forged_inputs = list(parent["params"]["inputs"])
        forged_inputs[ln["dst_offset"]] += 7
        forged = mint.replay_receipt(parent["params"]["program"], forged_inputs,
                                     links=parent["params"]["links"])
        receipts[receipts.index(parent)] = forged
        return "refused_and_orphaned" if parent_is_referenced else "refused"
    ln = rng.choice(parent["params"]["links"])
    ln["output_sha256"] = "f" * 64
    parent["receipt_sha256"] = canonical_sha256(claim_of(parent))
    return "refused_and_orphaned" if parent_is_referenced else "refused"


@pytest.mark.parametrize("batch", range(8))
def test_random_honest_dags_verify_and_corruptions_never_do(batch):
    for k in range(6):
        seed = batch * 6 + k
        rng = random.Random(seed * 6151 + 11)
        receipts = _build_random_dag(rng)

        g = verify_graph(list(receipts))
        assert g["graph_verified"] is True, (
            f"seed={seed}: an HONESTLY minted graph failed: {g['notes']} "
            f"{[n['notes'] for n in g['nodes'].values()]}")

        expect = _corrupt(rng, receipts)
        g2 = verify_graph(receipts)
        if expect == "any":
            continue                        # removed an unreferenced node: no claim
        assert g2["graph_verified"] is False, f"seed={seed}: corruption survived ({expect})"
        if expect == "incomplete":
            assert g2["complete"] is False, f"seed={seed}: expected an orphaned link"
        if expect == "refused":
            assert g2["complete"] is True, f"seed={seed}: forgery must be REFUSED, not incomplete"
        if expect == "refused_and_orphaned":
            # the forgery is refused AND, because the forged node's digest moved,
            # every consumer's link is orphaned -- the immutability theorem
            assert g2["complete"] is False, f"seed={seed}: consumers should be orphaned"


def test_multi_output_child_feeds_two_parents_and_two_slices():
    """One child, three outputs; one parent takes outputs [0..2), another takes
    output [2..3) -- fan-out and multi-length slices in one honest graph."""
    child = mint.replay_receipt(_prog(2, 3), [10, 20])
    la, va = mint.link(child, dst_offset=0, src_offset=0, length=2)
    pa = mint.replay_receipt(_prog(2, 1), mint.compose_inputs(2, [(la, va)]), links=[la])
    lb, vb = mint.link(child, dst_offset=1, src_offset=2, length=1)
    pb = mint.replay_receipt(_prog(2, 1), mint.compose_inputs(2, [(lb, vb)], base=[5, 0]),
                             links=[lb])
    g = verify_graph([child, pa, pb])
    assert g["graph_verified"] is True, g
    assert len(g["roots"]) == 2


# ------------------------------------------------------------------ cross-language
import os
import shutil
import subprocess
import tempfile
import json as _json
from pathlib import Path as _Path

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = "node" in {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_JS_RUNNER = _Path(__file__).resolve().parent / "graph_js_runner.mjs"


@pytest.mark.skipif(not _HAS_NODE and not _REQUIRED, reason="node not installed")
def test_fuzzed_graphs_reach_identical_verdicts_in_python_and_javascript():
    """The strongest net over the graph rule: fuzzer-generated DAGs -- honest and
    then corrupted -- must produce the SAME verdict object in both implementations,
    field for field: graph_verified, complete, the missing set, the roots, and every
    node's (verified, links_ok) pair, 'incomplete' string included. Receipts cross
    as canonical text, so integers never round through a double."""
    cases, py_verdicts = [], {}

    def record(name: str, receipts: list) -> None:
        texts = [_json.dumps(r, sort_keys=True, separators=(",", ":")) for r in receipts]
        cases.append((name, texts))
        g = verify_graph([_json.loads(t) for t in texts])
        py_verdicts[name] = {
            "graph_verified": g["graph_verified"],
            "complete": g["complete"],
            "missing": g["missing"],
            "roots": sorted(g["roots"]),
            "nodes": {d: {"verified": n["verified"], "links_ok": n["links_ok"],
                          "envelopes": n["envelopes"]}
                      for d, n in g["nodes"].items()},
        }

    for seed in range(25):
        rng = random.Random(seed * 7333 + 5)
        receipts = _build_random_dag(rng)

        for phase in ("honest", "corrupt"):
            if phase == "corrupt":
                _corrupt(rng, receipts)
            record(f"s{seed}-{phase}", receipts)

    # ---- duplicate ENVELOPES around one claim. `signature` and `env` are outside the
    # claim, so these index to the SAME digest as the receipt they wrap: one claim,
    # two documents. Crossed with arrival order, because the defect this covers was
    # exactly an order-sensitive verdict -- and a divergence here would mean the two
    # implementations disagree about which of two supplied receipts got examined.
    base = _build_random_dag(random.Random(99))
    twin = dict(base[0], env={"platform": "aarch64"})
    hostile = dict(base[0], signature={
        "spec": "obsign/signature/v2", "alg": "ed25519", "signer": "nobody",
        "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "sig": "00" * 64, "binds": [], "binds_sha256": None})
    for label, extra in (("honest", twin), ("forged", hostile)):
        record(f"dup-{label}-first", [extra] + base)
        record(f"dup-{label}-last", base + [extra])
        assert py_verdicts[f"dup-{label}-first"] == py_verdicts[f"dup-{label}-last"], (
            f"dup-{label}: the Python verdict moved with arrival order")

    fd, name = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    tmp = _Path(name)
    try:
        tmp.write_text(_json.dumps(cases), encoding="utf-8")
        proc = subprocess.run(["node", str(_JS_RUNNER), str(tmp)],
                              encoding="utf-8",
                              capture_output=True, text=True, timeout=300, check=False)
    finally:
        tmp.unlink(missing_ok=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    js_verdicts = _json.loads(proc.stdout.strip().splitlines()[-1])

    assert set(js_verdicts) == set(py_verdicts)
    for name in py_verdicts:
        assert js_verdicts[name] == py_verdicts[name], (
            f"{name}: JS and Python graph verdicts DIVERGE\n"
            f"py: {py_verdicts[name]}\njs: {js_verdicts[name]}")
