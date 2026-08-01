#!/usr/bin/env python3
"""Publish our own receipts, checkable with our own tool.

PROGRAM.md §4.3 item 6: *"Dogfood publicly: publish our own receipt stream beside
the computed org banner. One afternoon; un-counterfeitable."*

The point is not that we can produce receipts -- of course we can, we wrote the
format. The point is that **we publish claims about ourselves in a form a stranger
can refuse.** A vendor asserting their own product works is marketing. A vendor
handing you the command that would expose them if it did not is something else.

What the stream contains: one receipt per conformance vector, carrying the
parameters, the input fingerprint, and the output hash. Anyone can run

    obsign-verify stream/*.json

and either get the same bytes or catch us.

DELIBERATELY UNSIGNED. A signature would add *who*, and who is not in question here
-- these are our own published numbers on our own page. Adding one would also invite
the reader to check the signature and stop, which is the habit this whole product
exists to break. Integrity and re-derivation are the claim.

    python tools/dogfood.py                 # write the stream
    python tools/dogfood.py --check         # verify the stream as a stranger would
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from obsign_verify import __version__, verify                    # noqa: E402
from obsign_verify.canonical import canonical_sha256, load_receipt  # noqa: E402
from obsign_verify.kernel import array_sha256, build_fixed_inputs, evolve  # noqa: E402

VECTORS = ROOT / "vectors" / "conformance_vectors.json"
STREAM = ROOT / "stream"


def build_receipt(case: dict) -> dict:
    inp = build_fixed_inputs(case["params"])
    out = evolve(inp)
    claim = {
        "spec": "obsign/receipt/v1",
        "producer": f"obsign-verify/{__version__} (dogfood)",
        "kernel": "tau_field_fixed",
        "params": case["params"],
        "input": {"sha256": array_sha256(inp["S"])},
        "output": {"sha256": array_sha256(out),
                   "shape": list(out.shape),
                   "dtype": str(out.dtype)},
        "run": {"case": case["name"], "steps": int(case["params"]["steps"])},
    }
    receipt = dict(claim, receipt_sha256=canonical_sha256(claim))
    # `env` is OUTSIDE the claim by spec, so recording it cannot change the hash.
    # That is the property being demonstrated: the same receipt re-derives on a
    # different OS, and the env block proves we are not hiding where it ran.
    receipt["env"] = {"python": platform.python_version(),
                      "platform": platform.platform(),
                      "numpy": __import__("numpy").__version__}
    return receipt


def write_stream() -> int:
    cases = json.loads(VECTORS.read_text(encoding="utf-8"))
    STREAM.mkdir(exist_ok=True)
    index = []
    for case in cases:
        receipt = build_receipt(case)
        path = STREAM / f"{case['name']}.json"
        # newline="" so the published bytes are what we hashed, on every platform.
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="")
        index.append({"file": path.name,
                      "receipt_sha256": receipt["receipt_sha256"],
                      "output_sha256": receipt["output"]["sha256"]})
        # Cross-check against the conformance vector: the stream must agree with the
        # artifact an independent implementation is judged against, or we are
        # publishing a number that our own conformance suite would reject.
        if receipt["output"]["sha256"] != case["output_sha256"]:
            print(f"REFUSING to publish {case['name']}: output disagrees with the "
                  f"conformance vector", file=sys.stderr)
            return 1

    (STREAM / "index.json").write_text(
        json.dumps({"spec": "obsign/stream/v1", "receipts": index}, indent=2) + "\n",
        encoding="utf-8", newline="")
    print(f"wrote {len(index)} receipt(s) to {STREAM.relative_to(ROOT)}/")
    print("verify them exactly as a stranger would:  obsign-verify stream/*.json")
    return 0


def check_stream() -> int:
    """Run the published stream through the public verifier.

    Fails closed on an empty stream: an assertion over zero receipts passes for any
    input, and a dogfood page that verified nothing would be the worst possible
    artifact for this product to ship.
    """
    receipts = sorted(p for p in STREAM.glob("*.json") if p.name != "index.json")
    if not receipts:
        print("no receipts in the stream -- this check would be vacuous", file=sys.stderr)
        return 1
    bad = 0
    for path in receipts:
        res = verify(load_receipt(path.read_text(encoding="utf-8")))
        mark = "ok " if res["verified"] else "!! "
        print(f"  {mark}{path.name}")
        for note in res["notes"]:
            print(f"       {note}")
        bad += 0 if res["verified"] else 1
    print(f"\n{len(receipts) - bad}/{len(receipts)} published receipt(s) re-derived here.")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="verify the published stream instead of writing it")
    args = ap.parse_args()
    return check_stream() if args.check else write_stream()


if __name__ == "__main__":
    raise SystemExit(main())
