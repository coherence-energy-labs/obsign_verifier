"""Assemble replay receipts -- the last missing piece of the open loop.

The compiler let a stranger AUTHOR a computation without the producer's toolchain;
this lets them put it in a receipt without hand-rolling claim assembly (which three
of this repo's own tests were doing, identically, by copy). Everything here is public
math over public formats: run the program, hash the output, hash the claim. Nothing
here signs anything -- a signature is an identity's act, it belongs to whoever holds a
key, and an unsigned receipt is honestly reported as unsigned by the verifier rather
than dressed up otherwise.

The graph entry points build the `links` blocks docs/GRAPHS.md specifies:

    child = mint.replay_receipt(child_prog, raw_inputs)
    link, values = mint.link(child, dst_offset=1)          # child's output -> parent input 1
    parent_inputs = mint.compose_inputs(4, [(link, values)], base=[3, 0, 0, 0])
    parent = mint.replay_receipt(parent_prog, parent_inputs, links=[link])

`link()` re-verifies the child before lending its values: minting a chain on top of a
receipt that does not itself verify would build a supply chain on sand, so it refuses.
"""
from __future__ import annotations

from typing import Sequence

from .canonical import canonical_sha256, claim_of
from .replay import SPEC as REPLAY_SPEC
from .replay import Trap, output_sha256, program_sha256, run

RECEIPT_SPEC = "obsign/receipt/v1"


def replay_receipt(program: dict, inputs: Sequence[int], *,
                   links: Sequence[dict] = (), note: str | None = None) -> dict:
    """Run PROGRAM on INPUTS and assemble the unsigned receipt attesting the result.

    The program is validated and EXECUTED here -- minting means attesting what
    actually happened, so a program that traps refuses to mint (the Trap propagates
    with its reason). LINKS, if given, are stored verbatim in the claim; their
    truthfulness is the graph verifier's business (verify_graph re-derives both
    sides), but their SHAPE is checked now, because a malformed link is a bug worth
    refusing at mint time rather than shipping.
    """
    out = run(program, list(inputs))          # validates + executes; Trap propagates
    params: dict = {
        "program": program,
        "program_sha256": program_sha256(program),
        "inputs": list(inputs),
    }
    if links:
        for i, ln in enumerate(links):
            _check_link_shape(ln, i, n_inputs=len(inputs))
        params["links"] = [dict(ln) for ln in links]
    if note is not None:
        params["note"] = note
    claim = {
        "spec": RECEIPT_SPEC,
        "kernel": REPLAY_SPEC,
        "params": params,
        "output": {"sha256": output_sha256(out), "length": len(out), "dtype": "int64"},
    }
    return dict(claim, receipt_sha256=canonical_sha256(claim_of(claim)))


def link(child_receipt: dict, *, dst_offset: int, src_offset: int = 0,
         length: int | None = None) -> tuple[dict, list[int]]:
    """A link block binding a parent's input slice to CHILD_RECEIPT's output slice,
    plus the actual VALUES the parent must carry there.

    The child is fully re-verified first (the standalone ladder): a chain minted on
    an unverifiable child is refused here, at authoring time, with the child's own
    notes -- not discovered later by whoever received the graph.
    """
    from .verify import verify   # local import: mint must not force verify's imports
    res = verify(child_receipt)
    if not res.get("verified"):
        raise Trap("link refused: the child receipt does not verify standalone -- "
                   + "; ".join(res.get("notes", [])[:3]))
    params = child_receipt["params"]
    values = run(params["program"], list(params["inputs"]))
    if length is None:
        length = len(values) - src_offset
    if src_offset < 0 or length <= 0 or src_offset + length > len(values):
        raise Trap(f"link source range {src_offset}..{src_offset + length} is outside "
                   f"the child's output (length {len(values)})")
    block = {
        "receipt_sha256": child_receipt["receipt_sha256"],
        "output_sha256": output_sha256(values),
        "src_offset": src_offset,
        "length": length,
        "dst_offset": dst_offset,
    }
    return block, list(values[src_offset:src_offset + length])


def compose_inputs(n: int, linked: Sequence[tuple[dict, Sequence[int]]],
                   *, base: Sequence[int] | None = None) -> list[int]:
    """An input vector of length N with each link's values placed at its dst_offset.

    BASE fills the unlinked positions (zeros if omitted). Overlapping links are
    refused here exactly as the graph verifier refuses them -- authoring should fail
    where verification would.
    """
    inputs = list(base) if base is not None else [0] * n
    if len(inputs) != n:
        raise Trap(f"base has {len(inputs)} values, expected {n}")
    taken: set[int] = set()
    for block, values in linked:
        d, ln = block["dst_offset"], block["length"]
        if len(values) != ln:
            raise Trap(f"link carries {len(values)} values but declares length {ln}")
        if d < 0 or d + ln > n:
            raise Trap(f"link destination {d}..{d + ln} is outside inputs (length {n})")
        overlap = taken.intersection(range(d, d + ln))
        if overlap:
            raise Trap(f"link destinations overlap at input {min(overlap)}")
        taken.update(range(d, d + ln))
        inputs[d:d + ln] = list(values)
    return inputs


def _check_link_shape(ln: dict, i: int, *, n_inputs: int) -> None:
    if not isinstance(ln, dict):
        raise Trap(f"links[{i}] is not an object")
    for field in ("receipt_sha256", "output_sha256", "src_offset", "length", "dst_offset"):
        if field not in ln:
            raise Trap(f"links[{i}] is missing {field!r}")
    for field in ("receipt_sha256", "output_sha256"):
        v = ln[field]
        if not isinstance(v, str) or len(v) != 64:
            raise Trap(f"links[{i}].{field} must be a 64-hex digest")
    for field in ("src_offset", "length", "dst_offset"):
        v = ln[field]
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise Trap(f"links[{i}].{field} must be a non-negative integer")
    if ln["length"] == 0:
        raise Trap(f"links[{i}].length must be > 0")
    if ln["dst_offset"] + ln["length"] > n_inputs:
        raise Trap(f"links[{i}] destination {ln['dst_offset']}.."
                   f"{ln['dst_offset'] + ln['length']} is outside inputs ({n_inputs})")
