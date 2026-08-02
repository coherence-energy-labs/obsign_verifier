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


def _self_check(quiet: bool) -> int:
    """Run the challenge that ships INSIDE the package.

    A stranger who `pip install`ed has no `challenge/` directory to point at, so the
    README's "run the forgeries" instruction was unfollowable for exactly the people
    it was written for. This needs no files of their own and no arguments.

    Exit 0 means every bundle got the verdict it declares -- the honest ones
    verified, and every forgery refused. Refusing the forgeries is the job, so a
    clean run is NOT "9 verified".
    """
    from . import data_path
    bundles = sorted(data_path("challenge", "bundles").glob("*/receipt.json"))
    if not bundles:
        print("no bundles shipped with this package -- the install is incomplete",
              file=sys.stderr)
        return 1

    wrong = 0
    for path in bundles:
        receipt = load_receipt(path.read_text(encoding="utf-8"))
        declared = receipt.get("_challenge", {}).get("expect_verified")
        got = verify(receipt)["verified"]
        ok = got is declared
        wrong += not ok
        if not quiet:
            print(f"  {'ok  ' if ok else '!!  '}{path.parent.name:<36}"
                  f"{'VERIFIED' if got else 'REFUSED':<9}"
                  f"(expected {'VERIFIED' if declared else 'REFUSED'})")
    if not quiet:
        n = len(bundles)
        print()
        print(f"{n - wrong}/{n} bundles behaved as declared."
              + ("" if wrong else "  Every forgery was refused, including the resealed"
                                  " one whose signature is intact and whose claim is false."))
    return 1 if wrong else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="obsign-verify",
        description="Re-derive an Obsign receipt's claim on your own machine.")
    ap.add_argument("receipts", nargs="*", type=Path)
    ap.add_argument("--self-check", action="store_true",
                    help="verify the bundled challenge: 2 honest receipts and 7 "
                         "forgeries that must be refused. Needs no files of your own.")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--expect-program", metavar="SHA256", default=None,
                    help="require the receipt's replay program to be this exact "
                         "program (its program_sha256). Turns 'did this re-derive?' "
                         "into 'did this re-derive from the program my validator "
                         "approved?'")
    ap.add_argument("--version", action="version", version=f"obsign-verify {__version__}")
    args = ap.parse_args(argv)

    if args.self_check:
        return _self_check(args.quiet)
    if not args.receipts:
        ap.error("give one or more receipt files, or --self-check")

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

        # PROGRAM PINNING -- the answer to the sharpest attack on the replay rung.
        #
        # Re-derivation proves the output follows FROM THE PROGRAM. It cannot prove
        # the program computes what its name claims: a two-instruction program that
        # returns a hardcoded constant re-derives perfectly, and this verifier says
        # VERIFIED, correctly, because it did.
        #
        # That is not a hole to paper over, it is the boundary of what replay means,
        # and it maps onto how model validation already works. A validator reads the
        # program ONCE -- for the worked example that is 27 readable instructions --
        # approves it, and records its digest. From then on the question stops being
        # "did this re-derive?" and becomes "did this re-derive FROM THE PROGRAM I
        # APPROVED?", which is the question an auditor was asking all along.
        if args.expect_program:
            actual = ((receipt.get("params") or {}).get("program_sha256")
                      if isinstance(receipt.get("params"), dict) else None)
            if actual != args.expect_program:
                res = dict(res, verified=False,
                           notes=list(res["notes"]) + [
                               f"program is not the approved one: expected "
                               f"{args.expect_program[:16]}.., receipt carries "
                               f"{str(actual)[:16]}.."])

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
