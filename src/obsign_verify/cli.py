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
    # A HEADLINE THAT HIDES AN UNPROVEN RUNG IS THE DEFECT, NOT THE VERDICT.
    #
    # `verified` deliberately still accepts an `indeterminate` liveness probe -- a
    # verifier must not accuse an honest receipt of forgery because it was expensive
    # to probe. But the reader who scans one line and stops must not come away
    # believing the inputs were shown to reach the output when the probe ran out of
    # budget before proving anything either way. The tag is the difference between
    # "verified" and "verified, and here is what that word does not cover".
    live = res.get("input_liveness")
    tag = ""
    if res["verified"] and live == "indeterminate":
        tag = "  (inputs unproven)"
    elif res.get("unsupported"):
        tag = "  (unsupported format - NOT verified)"
    print(f"  [{mark:^8}] {path.name}{tag}")
    print(f"      integrity   {'ok' if res['integrity'] else 'FAIL'}")
    # Three-valued: None is "nothing was attempted" (an unrecognised format, a kernel
    # this verifier cannot run), which must not be printed as FAIL -- that reads as an
    # accusation, and this tool never accuses a receipt of being forged for being
    # unreadable. Matches js/bin/obsign-verify.js word for word.
    print(f"      re-derived  {'not attempted' if res['reproduced'] is None else ('ok' if res['reproduced'] else 'FAIL')}")
    if live and live != "n/a":
        # "guarded" was missing, so a receipt REFUSED for it printed a bare word with
        # no FAIL beside it -- the one line a reader scans to see which rung failed.
        shown = {"live": "ok - the output depends on the declared inputs",
                 "dead": "FAIL - the output ignores every declared input",
                 "guarded": "FAIL - the program trapped on every perturbation, so "
                            "nothing was shown to reach the output",
                 "indeterminate": "UNPROVEN (probe budget reached) - semantic "
                                  "validity not established"}.get(live, live)
        print(f"      inputs      {shown}")
    if res.get("approved_program") is not None:
        print(f"      program     {'ok - matches the approved digest' if res['approved_program'] else 'FAIL - not the approved program'}")
    sig = res.get("signature") or {}
    if not sig.get("present"):
        print("      signature   absent (integrity and re-derivation still hold)")
    elif sig.get("unsupported"):
        # "I did not read it" is a THIRD answer, and printing it as FAIL would say the
        # signature was checked and found wanting.
        print("      signature   UNSUPPORTED spec - nothing was checked")
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

    # THE BOUNDARY CROSSING, ON THE INSTALLED ARTIFACT. The receipts below were signed
    # by the PRODUCER, not by this package. Through 0.2.1 this verifier refused every
    # one of them (it checked a different message than the producer signed) while its
    # own test suite stayed green, because the suite only ever verified signatures it
    # had made itself. A stranger running `--self-check` on the wheel they installed
    # is the one place that cannot be fooled by a test that talks to itself.
    corpus = sorted(data_path("conformance").glob("*.json"))
    if not corpus:
        print("no producer-signed conformance receipts shipped with this package -- "
              "the install is incomplete", file=sys.stderr)
        return 1

    # Signature checking is an optional extra BY DESIGN (integrity and re-derivation
    # need no crypto library). Without it, every signed receipt is REFUSED -- "I cannot
    # check this" never resolves to a pass -- which is correct behaviour, not a broken
    # install. So the corpus is not counted as failed here; it is reported, by name, as
    # NOT EXERCISED, and the exit code says nothing about signatures. A skip that is
    # named is a skip; a skip that is silent is a pass nobody earned.
    try:
        import cryptography  # noqa: F401
        can_sign = True
    except ImportError:
        can_sign = False

    sig_wrong = 0
    for path in corpus:
        receipt = load_receipt(path.read_text(encoding="utf-8"))
        res = verify(receipt)
        sig = res["signature"]
        ok = res["verified"] and sig["valid"] and sig["identity_bound"]
        if can_sign:
            sig_wrong += not ok
        if not quiet:
            if not can_sign:
                print(f"  --  {path.stem:<36}{'NOT CHECKED':<13}"
                      f"(cryptography not installed; the receipt is REFUSED, not passed)")
            else:
                print(f"  {'ok  ' if ok else '!!  '}{path.stem:<36}"
                      f"{'SIGNER BOUND' if ok else 'REFUSED':<13}"
                      f"({sig['attributed_signer'] if ok else sig['detail']})")

    # ...and the forgery the public verifier once accepted: strip `binds`, rewrite
    # the examiner on a cryptographically valid receipt. Must be refused, and must
    # attribute nobody. A check nobody has watched block the attack is unverified.
    # (Without cryptography it is refused for the wrong reason -- so it only counts
    # as evidence when the signature could actually have been accepted.)
    base = load_receipt(data_path("conformance", "producer_signed_replay.json")
                        .read_text(encoding="utf-8"))
    base["signature"].pop("binds", None)
    base["case"]["examiner"] = "Dr. J. Smith, FBI Digital Forensics"
    forged = verify(base)
    refused = (not forged["verified"] and not forged["signature"]["valid"]
               and forged["signature"]["attributed_signer"] is None)
    sig_wrong += not refused
    if not quiet:
        n = len(corpus)
        print(f"  {'ok  ' if refused else '!!  '}{'binds stripped, examiner rewritten':<36}"
              f"{'REFUSED' if refused else 'ACCEPTED':<13}"
              f"({'attributed nobody' if refused else 'FORGERY ACCEPTED'})")
        print()
        if not can_sign:
            print(f"0/{n} producer-signed receipt(s) exercised: signature checking is NOT "
                  f"installed. Signed receipts are refused, never passed. To verify "
                  f"signatures: pip install 'obsign-verify[sig]'")
        else:
            accepted = n - (sig_wrong - (not refused))
            print(f"{accepted}/{n} producer-signed receipt(s) accepted with the signer bound"
                  + ("" if sig_wrong else "; the binds-stripping forgery was refused."))

    return 1 if (wrong or sig_wrong) else 0


def _chain(args) -> int:
    """Verify the receipts as a graph and report node-by-node, then the chain verdict."""
    from .graph import verify_graph

    receipts, unreadable = [], []
    for path in args.receipts:
        try:
            receipts.append(load_receipt(path.read_text(encoding="utf-8")))
        except Exception as exc:
            unreadable.append(f"{path.name}: {type(exc).__name__}: {exc}")
    g = verify_graph(receipts, strict_liveness=args.strict_liveness)

    if args.json:
        print(json.dumps({**g, "unreadable": unreadable}, indent=2))
    elif not args.quiet:
        for digest in g["order"] or list(g["nodes"]):
            n = g["nodes"][digest]
            mark = "VERIFIED" if n["verified"] else " REFUSED"
            link = ("" if n["links_ok"] is None
                    else "  links OK" if n["links_ok"] is True
                    else "  links INCOMPLETE" if n["links_ok"] == "incomplete"
                    else "  links REFUSED")
            print(f"  [{mark}] {digest[:16]}..{link}")
            for note in n["notes"]:
                print(f"             - {note}")
        for u in unreadable:
            print(f"  [ REFUSED ] {u}")
        for note in g["notes"]:
            print(f"  ! {note}")
        for m in g["missing"]:
            print(f"  ? missing: {m[:16]}.. (referenced but not supplied)")
        verdict = ("CHAIN VERIFIED - every node re-derived, every link binds"
                   if g["graph_verified"] and not unreadable
                   else "CHAIN INCOMPLETE - supply the missing receipts"
                   if not g["complete"]
                   else "CHAIN REFUSED")
        print(f"\n{verdict} ({len(g['nodes'])} node(s), {len(g['roots'])} root(s))")
    return 0 if (g["graph_verified"] and not unreadable) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="obsign-verify",
        description="Re-derive an Obsign receipt's claim on your own machine.",
        # NO ABBREVIATIONS. argparse accepts any unambiguous PREFIX by default, so
        # `--strict-livenes` (one letter short) silently meant `--strict-liveness`
        # here while the npm and Rust CLIs rejected the same argv -- three tools
        # disagreeing about what a command line means. Worse than the split: an
        # abbreviation is only unambiguous until the next flag is added, so adding a
        # `--strict-mode` later would silently repoint every script that had been
        # writing `--strict`, with no diagnostic on either side of the change. A
        # verifier must not GUESS which security switch the operator meant.
        allow_abbrev=False)
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
    ap.add_argument("--strict-liveness", action="store_true",
                    help="refuse a receipt whose input-liveness probe ended "
                         "'indeterminate'. The default accepts it -- a verifier must "
                         "not accuse an honest receipt of forgery for being expensive "
                         "to probe -- but an audited program should not rest on a "
                         "probe that ran out of budget.")
    ap.add_argument("--chain-list", metavar="FILE", default=None, type=Path,
                    help="read receipt paths from FILE, one per line, instead of "
                         "(or as well as) naming them in argv. A chain of thousands "
                         "of nodes is past the command-line length limit on Windows "
                         "(8191 characters), which is a refusal to RUN rather than a "
                         "verdict -- and the deep-chain property is exactly the one "
                         "that needs thousands of nodes to exercise.")
    ap.add_argument("--chain", action="store_true",
                    help="verify the given receipts as a GRAPH: every node "
                         "re-derived, every params.links binding checked value-for-"
                         "value against the child's re-derived output "
                         "(docs/GRAPHS.md). Exit 0 only if the whole chain holds.")
    ap.add_argument("--version", action="version", version=f"obsign-verify {__version__}")
    args = ap.parse_args(argv)

    if args.self_check:
        return _self_check(args.quiet)

    # A LIST FILE IS THE SAME ARGUMENT LIST, DELIVERED THROUGH A CHANNEL WITH NO LIMIT.
    # Blank lines and `#` comments are dropped so a generated list stays readable.
    if args.chain_list is not None:
        try:
            listed = args.chain_list.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            ap.error(f"cannot read --chain-list {args.chain_list}: {exc}")
        args.receipts = list(args.receipts) + [
            Path(line.strip()) for line in listed
            if line.strip() and not line.lstrip().startswith("#")]

    if not args.receipts:
        ap.error("give one or more receipt files, --chain-list FILE, or --self-check")

    if args.chain:
        return _chain(args)

    report, failures = [], 0
    for path in args.receipts:
        try:
            receipt = load_receipt(path.read_text(encoding="utf-8"))
        except Exception as exc:
            failures += 1
            report.append({"file": str(path), "verified": False,
                           "notes": [f"unreadable: {type(exc).__name__}: {exc}"]})
            if not (args.quiet or args.json):
                print(f"  [ REFUSED ] {path.name}: unreadable ({exc})")
            continue
        # PROGRAM PINNING -- the answer to the sharpest attack on the replay rung --
        # is now a LIBRARY argument, not CLI post-processing.
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
        #
        # Living in three CLIs meant every LIBRARY caller -- every service that
        # imports the package instead of shelling out -- silently got the weaker
        # question, with no field in the result to tell them so. `verify()` takes it
        # now and reports `approved_program`.
        res = verify(receipt, expect_program=args.expect_program,
                     strict_liveness=args.strict_liveness)

        failures += 0 if res["verified"] else 1
        report.append({"file": str(path), **res})
        #  MEANS MACHINE-READABLE, AND A MACHINE READS ALL OF STDOUT.
        # This called _report unconditionally, so  printed the full human
        # report and THEN the JSON array:  died on
        # "Expecting value: line 1 column 4". The npm CLI has always suppressed the
        # prose under --json; the flag whose entire purpose is to be parsed was the
        # one that could not be.
        _report(path, res, args.quiet or args.json)

    if args.json:
        print(json.dumps(report, indent=2))
    elif not args.quiet:
        total = len(report)
        print(f"\n{total - failures}/{total} receipt(s) verified on THIS machine.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
