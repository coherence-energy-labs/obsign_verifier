"""Verify a GRAPH of receipts -- a supply chain of computation, leaf to root.

docs/GRAPHS.md is the contract; this file only implements it. One receipt proves one
computation. A set of receipts whose `params.links` bind each parent's input slices
to other receipts' re-derived output slices proves a pipeline -- and this function is
what makes that claim checkable by a stranger: every node re-executed, every link
compared value-for-value against a fresh re-derivation of the child, nothing taken
from a stated hash that a recomputation could establish instead.

VERDICTS STAY SPLIT AND HONEST. A node can be `verified` (internally true) while its
`links_ok` is False (it lied about where its inputs came from). A missing child makes
the graph `incomplete` -- reported with the digest, and spelled differently from
FORGED in both directions, because "I could not check this" and "this is false" are
different facts. `graph_verified` is the conjunction: every supplied node verifies,
every link binds, nothing referenced is missing, no cycles, no digest collisions.

A NODE IS A CLAIM; A RECEIPT IS AN ENVELOPE AROUND ONE. `signature`, `case`, `env`
and `receipt_sha256` are all outside the claim, so two documents can index to the
same node -- one genuine, one re-enveloped by whoever handed you the set. Every
supplied envelope runs the ladder and the node's verdict is their conjunction, so a
hostile copy is a supplied failure rather than an accident of list order.
"""
from __future__ import annotations

from typing import Any

from . import replay as replaymod
from .canonical import canonical_bytes, canonical_sha256, claim_of
from .verify import verify

_LINK_FIELDS = ("receipt_sha256", "output_sha256", "src_offset", "length", "dst_offset")


def _links_of(receipt: dict) -> list:
    params = receipt.get("params")
    if not isinstance(params, dict):
        return []
    links = params.get("links")
    return links if isinstance(links, list) else []


def _well_formed_link(ln: Any) -> str | None:
    """None if LN has the spec'd shape, else the reason it does not."""
    if not isinstance(ln, dict):
        return "link is not an object"
    for f in _LINK_FIELDS:
        if f not in ln:
            return f"link is missing {f!r}"
    for f in ("receipt_sha256", "output_sha256"):
        if not isinstance(ln[f], str) or len(ln[f]) != 64:
            return f"link.{f} must be a 64-hex digest"
    for f in ("src_offset", "length", "dst_offset"):
        v = ln[f]
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            return f"link.{f} must be a non-negative integer"
    if ln["length"] == 0:
        return "link.length must be > 0"
    return None


def _envelope_key(receipt: dict, index: int) -> bytes:
    """What tells two receipts carrying the SAME claim apart.

    `signature`, `case`, `env`, `receipt_sha256` and `_`-prefixed helpers all live
    outside the claim, so re-enveloping a receipt leaves the claim digest this graph
    indexes by exactly where it was. Canonicalising the whole document is what
    distinguishes the copies. A document that will not canonicalise gets a key unique
    to its position, so it counts as its own envelope instead of being merged into
    another receipt's verdict.
    """
    try:
        return canonical_bytes(receipt)
    except (ValueError, TypeError):
        return f"<uncanonicalisable envelope #{index}>".encode("utf-8")


def _placeholder(key: str, note: str) -> dict:
    """A supplied item that never became a receipt. Still ONE document, so it carries
    one envelope under a key unique to it -- it must never merge with anything."""
    return {"receipt": None, "verified": False, "links_ok": None, "notes": [note],
            "envelopes": {key.encode("utf-8"): None}}


def verify_graph(receipts: list) -> dict:
    """Verify RECEIPTS individually and transitively. Never raises on hostile input --
    an exception is not a refusal, on a graph exactly as on a single receipt."""
    graph_notes: list[str] = []
    nodes: dict[str, dict] = {}          # digest -> {"receipt", "envelopes", "verified", ...}
    canon_bytes: dict[str, bytes] = {}   # digest -> canonical claim bytes (collision check)

    # ---- index by RECOMPUTED claim hash: a link names content, not a self-description
    for i, r in enumerate(receipts):
        if not isinstance(r, dict):
            graph_notes.append(f"receipts[{i}] is not an object; ignored as a node "
                               f"(and the graph cannot be green with it supplied)")
            nodes[f"<non-object #{i}>"] = _placeholder(f"<non-object #{i}>",
                                                       "not a JSON object")
            continue
        try:
            digest = canonical_sha256(claim_of(r))
            cbytes = canonical_bytes(claim_of(r))
        except (ValueError, TypeError) as exc:
            nodes[f"<uncanonicalisable #{i}>"] = _placeholder(
                f"<uncanonicalisable #{i}>",
                f"claim is not canonicalisable ({type(exc).__name__}: {exc})")
            continue
        if digest in nodes:
            if canon_bytes[digest] != cbytes:
                # two different claims, one hash: that is a SHA-256 collision
                graph_notes.append(f"COLLISION: two different claims share digest "
                                   f"{digest[:16]}.. -- refusing the whole graph")
                nodes[digest]["notes"].append("digest collision")
                nodes[digest]["links_ok"] = False
                continue
            # Same claim, a DIFFERENT document. Dropping it here ran the standalone
            # ladder on whichever copy arrived first and never examined the other, so
            # a forged re-envelope supplied second was invisible and the same set of
            # receipts came out green or red depending on list order.
            nodes[digest]["envelopes"].setdefault(_envelope_key(r, i), r)
            continue
        nodes[digest] = {"receipt": r, "verified": None, "links_ok": None, "notes": [],
                         "envelopes": {_envelope_key(r, i): r}}
        canon_bytes[digest] = cbytes

    for digest, node in nodes.items():
        if len(node["envelopes"]) > 1:
            graph_notes.append(
                f"DUPLICATE ENVELOPE: claim {digest[:16]}.. was supplied as "
                f"{len(node['envelopes'])} documents differing outside the claim "
                f"(signature/case/env/receipt_sha256); each is verified and this "
                f"node's verdict is their conjunction")

    # ---- every supplied node runs the FULL standalone ladder
    for digest, node in nodes.items():
        if node["receipt"] is None:
            continue
        # EVERY envelope, in canonical order rather than arrival order, so the notes
        # read identically however the list was shuffled. docs/GRAPHS.md rule 1 is
        # "every node verifies standalone", and a receipt deduped away never ran the
        # ladder at all -- so the node's verdict is the conjunction over the documents
        # actually supplied, and one hostile copy cannot hide behind an honest one.
        results = [verify(node["envelopes"][k]) for k in sorted(node["envelopes"])]
        node["verified"] = all(bool(res.get("verified")) for res in results)
        node["standalone"] = results[0]
        for res in results:
            if not res.get("verified"):
                node["notes"].append("does not verify standalone: "
                                     + "; ".join(res.get("notes", [])[:2]))

    # ---- re-derive outputs once per node that anything links to
    _out_cache: dict[str, list | None] = {}

    def outputs_of(digest: str) -> list | None:
        if digest not in _out_cache:
            r = nodes[digest]["receipt"]
            params = r.get("params") if isinstance(r, dict) else None
            try:
                _out_cache[digest] = replaymod.run(params["program"], list(params["inputs"]))
            except Exception:
                _out_cache[digest] = None    # standalone verify already recorded why
        return _out_cache[digest]

    # ---- walk the links: cycles, missing children, value binding
    missing: set[str] = set()
    WHITE, GREY, BLACK = 0, 1, 2
    color = {d: WHITE for d in nodes}
    order: list[str] = []                    # children-first finish order

    def check_links(digest: str) -> None:
        node = nodes[digest]
        r = node["receipt"]
        if r is None:
            return
        links = _links_of(r)
        if not links:
            return
        node["links_ok"] = True              # until a link says otherwise
        if r.get("kernel") != replaymod.SPEC:
            node["links_ok"] = False
            node["notes"].append("links on a non-replay parent are not supported "
                                 "in graphs v1 (docs/GRAPHS.md)")
            return
        parent_inputs = (r.get("params") or {}).get("inputs")
        taken: set[int] = set()
        for ln in links:
            why = _well_formed_link(ln)
            if why:
                node["links_ok"] = False
                node["notes"].append(why)
                continue
            child_digest = ln["receipt_sha256"]
            if child_digest not in nodes:
                missing.add(child_digest)
                if node["links_ok"] is True:
                    node["links_ok"] = "incomplete"
                node["notes"].append(f"link target {child_digest[:16]}.. was not "
                                     f"supplied -- the graph is incomplete, not forged")
                continue
            child = nodes[child_digest]
            if child["receipt"] is not None and child["receipt"].get("kernel") != replaymod.SPEC:
                node["links_ok"] = False
                node["notes"].append(f"link target {child_digest[:16]}.. is not an "
                                     f"obsign/replay/1 receipt (unsupported in v1)")
                continue
            d, ln_len, s = ln["dst_offset"], ln["length"], ln["src_offset"]
            if not isinstance(parent_inputs, list) or d + ln_len > len(parent_inputs):
                node["links_ok"] = False
                node["notes"].append(f"link destination {d}..{d + ln_len} is outside "
                                     f"this receipt's inputs")
                continue
            overlap = taken.intersection(range(d, d + ln_len))
            if overlap:
                node["links_ok"] = False
                node["notes"].append(f"link destinations overlap at input {min(overlap)}")
                continue
            taken.update(range(d, d + ln_len))
            child_out = outputs_of(child_digest)
            if child_out is None:
                node["links_ok"] = False
                node["notes"].append(f"link target {child_digest[:16]}.. cannot be "
                                     f"re-executed, so the link cannot bind")
                continue
            if s + ln_len > len(child_out):
                node["links_ok"] = False
                node["notes"].append(f"link source {s}..{s + ln_len} is outside the "
                                     f"child's output (length {len(child_out)})")
                continue
            if replaymod.output_sha256(child_out) != ln["output_sha256"]:
                node["links_ok"] = False
                node["notes"].append(f"link.output_sha256 does not match the child's "
                                     f"re-derived output")
                continue
            if parent_inputs[d:d + ln_len] != child_out[s:s + ln_len]:
                node["links_ok"] = False
                node["notes"].append(
                    f"inputs[{d}..{d + ln_len}) do not equal the child's re-derived "
                    f"output[{s}..{s + ln_len}) -- this receipt did NOT consume what "
                    f"{child_digest[:16]}.. produced")
                continue
            # THE SLICE THAT TRAVELS MUST BE THE PART THAT DEPENDS ON THE INPUTS.
            #
            # verify() refuses a node whose whole output ignores every declared input.
            # An output window is a VECTOR, so that check is passed by appending one
            # decoy cell -- `output 424242, a + b;` -- and then linking only cell 0:
            # every input is live, the node verifies, and a hardcoded constant travels
            # the chain under "CHAIN VERIFIED - every node re-derived, every link
            # binds". The same rule, applied to the slice the link actually carries,
            # closes it. Cells the child's probe could not decide are "indeterminate"
            # and never refuse, exactly as an indeterminate node verdict does not.
            cells = (child.get("standalone") or {}).get("output_liveness_by_cell") or []
            slice_states = cells[s:s + ln_len]
            if slice_states and all(st == "dead" for st in slice_states):
                node["links_ok"] = False
                node["notes"].append(
                    f"link source output[{s}..{s + ln_len}) of {child_digest[:16]}.. "
                    f"never moved under ANY perturbation of that receipt's inputs: the "
                    f"values this link carries are constants, so the chain proves "
                    f"nothing about them however well every node re-derives")

    def _named_child(ln) -> str | None:
        """The digest a link names, or None if it does not name one.

        `nodes` is a dict, so `child in nodes` needs a HASHABLE child -- and a link is
        attacker-supplied JSON, where `receipt_sha256` can be an array or an object.
        One 250-byte receipt carrying `"receipt_sha256": []` raised
        `TypeError: unhashable type: 'list'` straight out of this function, which
        promises never to raise. `_well_formed_link` already refuses that shape, but
        only `check_links` consulted it; the reachability walk read the raw value.
        """
        if not isinstance(ln, dict):
            return None
        child = ln.get("receipt_sha256")
        return child if isinstance(child, str) else None

    def dfs(start: str) -> None:
        """Iterative depth-first walk.

        This was recursive, so its depth was the length of the chain WHOEVER HANDED
        YOU THE SET chose: about 2,000 linked receipts of 200 bytes each raised
        RecursionError, and `obsign-verify --chain` turned that into a traceback and
        an exit code that means "crashed" rather than "refused". rust/src/graph.rs
        already walks with an explicit stack, and says why: "a stack overflow is a
        crash rather than a refusal". The visit order, the finish order and the cycle
        rule are unchanged -- only the stack moved from the interpreter's to ours.
        """
        color[start] = GREY
        stack: list[tuple[str, int]] = [(start, 0)]
        while stack:
            digest, i = stack.pop()
            r = nodes[digest]["receipt"]
            links = _links_of(r) if isinstance(r, dict) else []
            if i >= len(links):
                color[digest] = BLACK
                order.append(digest)
                continue
            stack.append((digest, i + 1))
            child = _named_child(links[i])
            if child in nodes:
                if color[child] == GREY:
                    graph_notes.append(f"CYCLE through {child[:16]}.. -- a receipt "
                                       f"cannot depend on its own consequence; refused")
                    nodes[digest]["links_ok"] = False
                    nodes[child]["links_ok"] = False
                elif color[child] == WHITE:
                    color[child] = GREY
                    stack.append((child, 0))

    for digest in nodes:
        check_links(digest)
    for digest in nodes:
        if color[digest] == WHITE:
            dfs(digest)

    # ---- roots: nodes nothing supplied links to (for display; not a verdict input)
    referenced = {child
                  for n in nodes.values() if isinstance(n["receipt"], dict)
                  for ln in _links_of(n["receipt"])
                  if (child := _named_child(ln)) is not None}
    roots = [d for d in nodes if d not in referenced]

    complete = not missing
    all_nodes_ok = all(n["verified"] is True for n in nodes.values())
    all_links_ok = all(n["links_ok"] in (None, True) for n in nodes.values())
    no_graph_faults = not any("COLLISION" in g or "CYCLE" in g for g in graph_notes)
    graph_verified = bool(nodes) and complete and all_nodes_ok and all_links_ok and no_graph_faults

    return {
        "graph_verified": graph_verified,
        "complete": complete,
        "missing": sorted(missing),
        "roots": roots,
        "order": order,                      # children-first where acyclic
        "nodes": {d: {"verified": n["verified"], "links_ok": n["links_ok"],
                      "envelopes": len(n["envelopes"]), "notes": n["notes"]}
                  for d, n in nodes.items()},
        "notes": graph_notes,
    }
