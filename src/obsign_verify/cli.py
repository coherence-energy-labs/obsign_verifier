"""`obsign-verify receipt.json` -- the one command PG-1 is about.

Exit code is the interface: 0 means every named receipt verified, 1 means at least
one did not. A script wrapping this must be able to branch on that alone.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .canonical import load_receipt
from .verify import verify


def _report(path: Path, res: dict, quiet: bool) -> None:
    if quiet:
        return
    mark = "VERIFIED" if res["verified"] else "REFUSED"
    print(f"  [{mark:^8}] {path.name}")
    print(f"      integrity   {'ok' if res['integrity'] else 'FAIL'}")
    print(f"      re-derived  {'ok' if res['reproduced'] else 'FAIL'}")
    sig = res.get("signature") or {}
    if not sig.get("present"):
        print("      signature   absent (integrity and re-derivation still hold)")
    else:
        who = sig.get("attributed_signer")
        # Never print a signer name the signature did not cover. A v1 signature's
        # name can be rewritten by anyone with a text editor and no key.
        ident = (f"attributed to {who!r}" if sig.get("identity_bound")
                 else f"NOT identity-bound (file claims {sig.get('claimed_signer')!r})")
        print(f"      signature   {'ok' if sig.get('valid') else 'FAIL'} - {ident}")
    for note in res["notes"]:
        print(f"      - {note}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="obsign-verify",
        description="Re-derive an Obsign receipt's claim on your own machine.")
    ap.add_argument("receipts", nargs="+", type=Path)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--version", action="version", version=f"obsign-verify {__version__}")
    args = ap.parse_args(argv)

    report, failures = [], 0
    for path in args.receipts:
        try:
            receipt = load_receipt(path.read_text(encoding="utf-8"))
        except Exception as exc:
            failures += 1
            report.append({"file": str(path), "verified": False,
                           "notes": [f"unreadable: {type(exc).__name__}: {exc}"]})
            if not args.quiet:
                print(f"  [ REFUSED ] {path.name}: unreadable ({exc})")
            continue
        res = verify(receipt)
        failures += 0 if res["verified"] else 1
        report.append({"file": str(path), **res})
        _report(path, res, args.quiet)

    if args.json:
        print(json.dumps(report, indent=2))
    elif not args.quiet:
        total = len(report)
        print(f"\n{total - failures}/{total} receipt(s) verified on THIS machine.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
