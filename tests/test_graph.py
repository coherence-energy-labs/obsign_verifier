"""Receipt graphs: the chain rule enforced, attacked, and held.

docs/GRAPHS.md is the contract. These tests hold both directions of it: every attack
a hostile author would try against a chain is refused with the right verdict, and
every honest configuration -- including the shipped conformance chain -- verifies.
The impossibility results matter as much as the refusals: cycles and self-links are
not merely rejected, they are demonstrated UNCONSTRUCTIBLE, because a link names a
hash that would have to include itself. Tampering does not corrupt a chain; it
visibly disconnects it.
"""
from __future__ import annotations

import copy
import json
import pathlib

import pytest

from obsign_verify import mint
from obsign_verify.canonical import canonical_sha256, claim_of
from obsign_verify.graph import verify_graph
from obsign_verify.replay import Trap
from obsign_verify.replayc import compile_source

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHAIN = ROOT / "src/obsign_verify/data/conformance/chain"

DESK_SRC = """#steps 100000
input v[7];
let acc = 0;
for i in 0..v[0] {
  let b = i*3 + 1;
  acc = acc + mulfx(mulfx(v[b], v[b+1], 32), v[b+2], 32);
}
output acc;"""
ROOT_SRC = "input a, b, c; output a + b + c;"
ONE32 = 1 << 32
BOOKS = [
    [2, int(0.02 * ONE32), int(0.45 * ONE32), 1_000_000_00,
     int(0.01 * ONE32), int(0.40 * ONE32), 2_000_000_00],
    [2, int(0.03 * ONE32), int(0.50 * ONE32), 500_000_00,
     int(0.05 * ONE32), int(0.60 * ONE32), 250_000_00],
    [2, int(0.01 * ONE32), int(0.35 * ONE32), 3_000_000_00,
     int(0.02 * ONE32), int(0.55 * ONE32), 1_500_000_00],
]


def build_chain():
    desk_prog = compile_source(DESK_SRC)
    root_prog = compile_source(ROOT_SRC)
    desks = [mint.replay_receipt(desk_prog, b) for b in BOOKS]
    linked = [mint.link(d, dst_offset=i) for i, d in enumerate(desks)]
    root = mint.replay_receipt(root_prog, mint.compose_inputs(3, linked),
                               links=[l for l, _ in linked])
    return desks, root


def reseal(receipt: dict) -> dict:
    receipt["receipt_sha256"] = canonical_sha256(claim_of(receipt))
    return receipt


# ------------------------------------------------------------------ honest chains
def test_the_shipped_conformance_chain_verifies():
    receipts = [json.loads(p.read_text()) for p in sorted(CHAIN.glob("*.json"))]
    assert len(receipts) == 4, "the conformance chain must ship 3 desks + 1 root"
    g = verify_graph(receipts)
    assert g["graph_verified"] is True, g
    assert g["complete"] is True and not g["missing"]
    assert len(g["roots"]) == 1
    assert all(n["verified"] for n in g["nodes"].values())


def test_a_freshly_minted_chain_verifies_and_orders_children_first():
    desks, root = build_chain()
    g = verify_graph(desks + [root])
    assert g["graph_verified"] is True
    root_digest = root["receipt_sha256"]
    assert g["order"][-1] == root_digest or root_digest in g["order"]
    for d in desks:                                # every desk finishes before the root
        assert g["order"].index(d["receipt_sha256"]) < g["order"].index(root_digest)


def test_receipt_order_and_duplicates_do_not_matter():
    desks, root = build_chain()
    g = verify_graph([root] + desks[::-1] + [desks[0]])   # shuffled + duplicated
    assert g["graph_verified"] is True
    assert len(g["nodes"]) == 4                            # byte-identical dupe deduped


def test_a_linked_receipt_still_verifies_standalone_under_plain_verify():
    """Compatibility: links are additive. A pre-graph verifier sees an ordinary
    receipt and verifies it on the standalone ladder."""
    from obsign_verify import verify
    _, root = build_chain()
    res = verify(root)
    assert res["verified"] is True, res["notes"]


def test_deep_chain_verifies_transitively():
    """leaf -> mid -> root: three levels, each consuming the level below."""
    leaf_prog = compile_source("input a, b; output a * b;")
    mid_prog = compile_source("input x; output x + 7;")
    top_prog = compile_source("input y; output y * 2;")
    leaf = mint.replay_receipt(leaf_prog, [6, 7])
    l1, v1 = mint.link(leaf, dst_offset=0)
    mid = mint.replay_receipt(mid_prog, mint.compose_inputs(1, [(l1, v1)]), links=[l1])
    l2, v2 = mint.link(mid, dst_offset=0)
    top = mint.replay_receipt(top_prog, mint.compose_inputs(1, [(l2, v2)]), links=[l2])
    g = verify_graph([leaf, mid, top])
    assert g["graph_verified"] is True
    assert top["params"]["inputs"] == [49] and v2 == [49]


# ------------------------------------------------------------------ attacks
def test_tampering_a_leaf_disconnects_the_chain():
    """Editing a leaf changes its digest, so the root's link points at a document
    that no longer exists: the graph reports INCOMPLETE (link target missing) and the
    tampered node fails standalone. History is immutable the way git history is."""
    desks, root = build_chain()
    desks[0]["params"]["inputs"][3] += 1               # cook the book
    g = verify_graph(desks + [root])
    assert g["graph_verified"] is False
    assert g["complete"] is False and g["missing"], "the orphaned link must be reported"
    tampered_digest = canonical_sha256(claim_of(desks[0]))
    assert g["nodes"][tampered_digest]["verified"] is False   # integrity broke too


def test_a_resealed_tampered_leaf_still_cannot_reconnect():
    """Resealing the tampered leaf's hash makes it internally consistent again -- but
    its digest is now different, so the root still points at the missing original.
    The attacker cannot have both: same digest, different content."""
    desks, root = build_chain()
    desks[0]["params"]["inputs"][3] += 1
    reseal(desks[0])                                    # now integrity-valid again
    g = verify_graph(desks + [root])
    tampered_digest = desks[0]["receipt_sha256"]
    assert g["nodes"][tampered_digest]["verified"] is True    # internally true...
    assert g["complete"] is False                             # ...but the chain is broken
    assert g["graph_verified"] is False


def test_a_parent_that_lies_about_its_inputs_is_caught_by_value():
    """The honest split verdict: the root verifies standalone (its sum is correctly
    computed over its DECLARED inputs) but links_ok is False, because those inputs are
    not what the children produced."""
    desks, _ = build_chain()
    root_prog = compile_source(ROOT_SRC)
    linked = [mint.link(d, dst_offset=i) for i, d in enumerate(desks)]
    forged_inputs = mint.compose_inputs(3, linked)
    forged_inputs[1] += 100_00                          # skim $100 into desk B's number
    forged = mint.replay_receipt(root_prog, forged_inputs, links=[l for l, _ in linked])
    g = verify_graph(desks + [forged])
    node = g["nodes"][forged["receipt_sha256"]]
    assert node["verified"] is True                     # internally consistent
    assert node["links_ok"] is False                    # provenance is a lie
    assert any("did NOT consume" in n for n in node["notes"])
    assert g["graph_verified"] is False


def test_a_wrong_output_sha256_in_a_link_is_refused():
    desks, root = build_chain()
    root["params"]["links"][0]["output_sha256"] = "0" * 64
    reseal(root)
    g = verify_graph(desks + [root])
    node = g["nodes"][root["receipt_sha256"]]
    assert node["links_ok"] is False
    assert any("output_sha256" in n for n in node["notes"])


def test_missing_child_is_incomplete_not_forged():
    desks, root = build_chain()
    g = verify_graph([desks[0], desks[2], root])        # desk B withheld
    node = g["nodes"][root["receipt_sha256"]]
    assert node["verified"] is True
    assert node["links_ok"] == "incomplete"
    assert g["complete"] is False
    assert desks[1]["receipt_sha256"] in g["missing"]
    assert g["graph_verified"] is False
    assert any("incomplete, not forged" in n for n in node["notes"])


def test_overlapping_link_destinations_are_refused():
    desks, _ = build_chain()
    root_prog = compile_source(ROOT_SRC)
    l0, v0 = mint.link(desks[0], dst_offset=0)
    l1, _v1 = mint.link(desks[1], dst_offset=0)         # same destination: overlap
    inputs = mint.compose_inputs(3, [(l0, v0)])
    bad = mint.replay_receipt(root_prog, inputs, links=[l0, l1])
    g = verify_graph(desks[:2] + [bad])
    node = g["nodes"][bad["receipt_sha256"]]
    assert node["links_ok"] is False
    assert any("overlap" in n for n in node["notes"])


def test_out_of_range_link_source_is_refused():
    desks, root = build_chain()
    root["params"]["links"][0]["src_offset"] = 5        # desk output has length 1
    reseal(root)
    g = verify_graph(desks + [root])
    node = g["nodes"][root["receipt_sha256"]]
    assert node["links_ok"] is False
    assert any("outside the child's output" in n for n in node["notes"])


def test_malformed_link_blocks_are_refused_not_crashed():
    desks, root = build_chain()
    root["params"]["links"][0] = {"receipt_sha256": "zz"}
    reseal(root)
    g = verify_graph(desks + [root])
    node = g["nodes"][root["receipt_sha256"]]
    assert node["links_ok"] is False
    assert g["graph_verified"] is False


def test_hostile_garbage_in_the_receipt_list_never_raises():
    desks, root = build_chain()
    g = verify_graph([None, 42, "receipt", {"spec": 1}, desks[0], root])
    assert g["graph_verified"] is False                 # garbage was supplied; not green
    assert isinstance(g["nodes"], dict)


# ------------------------------------------------------------------ impossibility results
def test_cycles_are_unconstructible_a_link_cannot_name_its_own_future_hash():
    """To make A -> B -> A, B's link must carry A's final digest -- but A's final
    digest is computed over A's links, which must already carry B's final digest,
    which is computed over B's link to A's final digest. SHA-256 offers no such fixed
    point. The nearest an attacker can get is guessing: the guessed digest simply is
    not any supplied receipt, and the graph reports it missing."""
    prog = compile_source("input a; output a + 1;")
    a = mint.replay_receipt(prog, [1])
    guessed = "ab" * 32
    b_params_link = {"receipt_sha256": guessed, "output_sha256": "cd" * 32,
                     "src_offset": 0, "length": 1, "dst_offset": 0}
    b = mint.replay_receipt(prog, [2], links=[b_params_link])
    # try to close the loop: rewrite a to link b, resealing -- a's digest CHANGES,
    # so b's guessed digest still names nothing
    a["params"]["links"] = [{"receipt_sha256": b["receipt_sha256"],
                             "output_sha256": b["output"]["sha256"],
                             "src_offset": 0, "length": 1, "dst_offset": 0}]
    reseal(a)
    assert a["receipt_sha256"] != guessed, "closing the loop would need a hash fixed point"
    g = verify_graph([a, b])
    assert g["graph_verified"] is False
    assert g["complete"] is False and guessed in g["missing"]


def test_self_links_are_unconstructible_for_the_same_reason():
    prog = compile_source("input a; output a + 1;")
    r = mint.replay_receipt(prog, [1])
    r["params"]["links"] = [{"receipt_sha256": r["receipt_sha256"],   # its OLD digest
                             "output_sha256": r["output"]["sha256"],
                             "src_offset": 0, "length": 1, "dst_offset": 0}]
    reseal(r)                                            # adding the link moved the digest
    assert r["params"]["links"][0]["receipt_sha256"] != r["receipt_sha256"]
    g = verify_graph([r])
    assert g["graph_verified"] is False and g["complete"] is False


# ------------------------------------------------------------------ minting hygiene
def test_mint_refuses_to_link_an_unverifiable_child():
    prog = compile_source("input a; output a + 1;")
    child = mint.replay_receipt(prog, [1])
    child["output"]["sha256"] = "0" * 64                 # break it
    with pytest.raises(Trap, match="does not verify standalone"):
        mint.link(child, dst_offset=0)


def test_mint_refuses_malformed_links_and_overlaps():
    prog = compile_source("input a; output a + 1;")
    with pytest.raises(Trap, match="missing"):
        mint.replay_receipt(prog, [1], links=[{"receipt_sha256": "x" * 64}])
    child = mint.replay_receipt(prog, [1])
    l0, v0 = mint.link(child, dst_offset=0)
    with pytest.raises(Trap, match="overlap"):
        mint.compose_inputs(1, [(l0, v0), (l0, v0)])


def test_minted_receipts_are_deterministic():
    desks1, root1 = build_chain()
    desks2, root2 = build_chain()
    assert [d["receipt_sha256"] for d in desks1] == [d["receipt_sha256"] for d in desks2]
    assert root1 == root2


# ------------------------------------------------------------------ the CLI
def test_cli_chain_mode_verdicts_and_exit_codes(capsys):
    from obsign_verify import cli
    chain_files = sorted(str(p) for p in CHAIN.glob("*.json"))
    assert cli.main(["--chain", *chain_files]) == 0
    assert "CHAIN VERIFIED" in capsys.readouterr().out
    assert cli.main(["--chain", chain_files[0], str(CHAIN / "firm_root.json")]) == 1
    assert "CHAIN INCOMPLETE" in capsys.readouterr().out
