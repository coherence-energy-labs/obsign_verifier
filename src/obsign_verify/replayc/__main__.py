"""Command line for the replay compiler.

  python -m obsign_verify.replayc build  prog.rl [-o prog.json]   compile to a program
  python -m obsign_verify.replayc run    prog.rl -i "1,2,3"        compile and execute
  python -m obsign_verify.replayc check  prog.rl                   parse + type-check only
  python -m obsign_verify.replayc disasm prog.json|receipt.json    show the bytecode

`run` prints each output value and the output SHA-256 -- the exact digest a receipt
records -- so a program can be developed and its result pinned without leaving the
standard library.
"""
from __future__ import annotations

import argparse
import json
import sys

from ..replay import SPEC, Trap, output_sha256, run
from . import compile_source, disassemble, ir_sha256, parse_program
from .codegen import CodegenError, generate
from .disasm import disassemble_receipt_program
from .frontend import ParseError
from .typer import TypeError_


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as f:
        return f.read()


def _parse_inputs(s: str | None) -> list[int]:
    if not s:
        return []
    return [int(x, 0) for x in s.replace(",", " ").split()]


def _compile_or_die(path: str) -> dict:
    try:
        return compile_source(_read(path))
    except (ParseError, TypeError_, CodegenError) as e:
        print(f"{path}: {e}", file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="obsign_verify.replayc",
                                 description="compile a small language to an obsign/replay/1 program")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="compile source to a replay program (JSON)")
    b.add_argument("source")
    b.add_argument("-o", "--out", help="write the program JSON here (default: stdout)")

    r = sub.add_parser("run", help="compile and execute on the VM")
    r.add_argument("source")
    r.add_argument("-i", "--inputs", help="comma/space separated int64 inputs (0x ok)")

    c = sub.add_parser("check", help="parse and type-check only")
    c.add_argument("source")

    d = sub.add_parser("disasm", help="disassemble a program or a receipt")
    d.add_argument("program")

    args = ap.parse_args(argv)

    if args.cmd == "build":
        prog = _compile_or_die(args.source)
        text = json.dumps(prog, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"wrote {args.out}  (ir_sha256 {ir_sha256(prog)[:16]}.., "
                  f"{prog['mem']} cells, {len(prog['code'])} instrs)")
        else:
            print(text)
        return 0

    if args.cmd == "run":
        prog = _compile_or_die(args.source)
        inputs = _parse_inputs(args.inputs)
        try:
            out = run(prog, inputs)
        except Trap as e:
            print(f"TRAP: {e}", file=sys.stderr)
            return 1
        for v in out:
            print(v)
        print(f"output_sha256 {output_sha256(out)}", file=sys.stderr)
        return 0

    if args.cmd == "check":
        try:
            parse_program(_read(args.source))
            generate(parse_program(_read(args.source)))   # also prove it lowers
        except (ParseError, TypeError_, CodegenError) as e:
            print(f"{args.source}: {e}", file=sys.stderr)
            return 2
        print(f"{args.source}: ok")
        return 0

    if args.cmd == "disasm":
        doc = json.loads(_read(args.program))
        if isinstance(doc, dict) and doc.get("spec") == SPEC:
            print(disassemble(doc))
        else:
            print(disassemble_receipt_program(doc))
        return 0

    return 0  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
