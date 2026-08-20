"""Disassemble a replay program to readable, auditable text.

Bytecode is what actually travels in a receipt, so bytecode is what a careful reader
audits -- not the source, which the producer could have changed before compiling. This
renders a program as labelled assembly: each instruction on its own line, jump targets
shown as `L<n>:` labels, the const pool and the input/output windows spelled out. It is
faithful to the JSON, adds nothing, and hides nothing.
"""
from __future__ import annotations

from .. import replay


def disassemble(prog: dict) -> str:
    code = prog["code"]
    consts = prog.get("consts", [])

    # jump targets get labels
    targets = set()
    for ins in code:
        if ins and ins[0] in ("JMP", "JMPZ", "JMPNZ") and isinstance(ins[-1], int):
            targets.add(ins[-1])
    label = {pc: f"L{i}" for i, pc in enumerate(sorted(targets))}

    lines = []
    lines.append(f"; spec   {prog.get('spec')}")
    lines.append(f"; mem    {prog.get('mem')} cells   steps<= {prog.get('steps')}")
    io = prog.get("input", {})
    oo = prog.get("output", {})
    lines.append(f"; input  @{io.get('offset')} x{io.get('length')}   "
                 f"output @{oo.get('offset')} x{oo.get('length')}")
    if consts:
        shown = ", ".join(f"[{i}]={c}" for i, c in enumerate(consts))
        lines.append(f"; consts {shown}")
    lines.append("")

    for pc, ins in enumerate(code):
        lead = f"{label[pc]}:" if pc in label else ""
        op = ins[0]
        args = ins[1:]
        if op in ("JMP", "JMPZ", "JMPNZ") and isinstance(args[-1], int) and args[-1] in label:
            shown_args = [str(a) for a in args[:-1]] + [label[args[-1]]]
        else:
            shown_args = [str(a) for a in args]
        body = f"{op:6}" + " ".join(shown_args)
        lines.append(f"{lead:>6} {pc:4}  {body}".rstrip())
    return "\n".join(lines)


def disassemble_receipt_program(receipt: dict) -> str:
    """Convenience: pull the program out of a receipt's params and disassemble it."""
    params = receipt.get("params") or {}
    prog = params.get("program")
    if not isinstance(prog, dict) or prog.get("spec") != replay.SPEC:
        raise ValueError("receipt carries no obsign/replay/1 program in params.program")
    return disassemble(prog)
