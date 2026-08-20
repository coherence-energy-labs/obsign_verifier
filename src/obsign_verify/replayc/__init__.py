"""replayc -- an open compiler from a small language (RL) to `obsign/replay/1`.

WHY THIS SHIPS IN THE VERIFIER

The replay VM exists so a computation can travel inside a receipt and be re-run by a
stranger with nothing but the standard library -- breaking the circularity where
"verification" needs the producer's private toolchain. But authoring a replay program
was still hand-written int64 assembly. This closes the loop from the other side: an
OPEN compiler, standard-library-only, in the SAME public package as the verifier, so a
stranger can write their own computation, compile it, mint a receipt, and hand it to
someone who verifies it with the identical package -- no private compiler anywhere in
the chain.

HOW IT EARNS TRUST

A wrong compiler is worse than none: it would mint receipts that faithfully reproduce
the WRONG number. So correctness is not asserted, it is differentially established.
`interpret_source` evaluates the source by a tree-walk that shares nothing with codegen
but the int64 number model; `run_source` compiles and runs the result on the actual VM.
The test suite proves the two agree across adversarial int64 edges, fuzzed programs and
inputs, and -- the external anchor -- by regenerating a real, hand-authored receipt's
program to the identical output hash.

PUBLIC API
  compile_source(text)             -> replay program dict (validated)
  run_source(text, inputs)         -> output list, via the VM (what a receipt records)
  interpret_source(text, inputs)   -> output list, via the reference interpreter
  ir_sha256(program)               -> the program's canonical digest (== program_sha256)
  disassemble(program)             -> readable assembly, for auditing bytecode
"""
from __future__ import annotations

from ..replay import output_sha256, program_sha256, run
from . import codegen, frontend, interp, typer
from .codegen import CodegenError
from .disasm import disassemble
from .frontend import ParseError
from .nodes import Program
from .scales import ScaleError
from .typer import TypeError_ as TypeError

__all__ = [
    "compile_source", "run_source", "interpret_source", "ir_sha256",
    "disassemble", "output_sha256", "parse_program",
    "ParseError", "TypeError", "CodegenError", "ScaleError",
]


def parse_program(text: str) -> Program:
    """Source -> resolved, checked AST. Raises ParseError, ResolveError, TypeError or
    ScaleError with a source position. This is the LAST shared step between the two
    paths: everything after it is either compile-side (inline -> fold -> generate) or
    oracle-side (direct evaluation, with native function calls), never both. Sharing
    the static checks is safe because they only ever REJECT -- a check cannot make the
    two paths compute different numbers, only refuse the same program."""
    from .resolve import resolve
    from .scales import check_scales
    ast = resolve(frontend.parse(text))
    typer.check(ast)
    check_scales(ast)
    return ast


def compile_source(text: str) -> dict:
    """Source -> a validated `obsign/replay/1` program dict.

    The pipeline is parse -> resolve -> check -> INLINE -> FOLD -> generate. Inlining,
    folding and code generation run only here; interpret_source evaluates the checked
    tree directly, executing calls natively in a fresh frame. The differential suite
    compares the two, so a bug in any compile-side pass shows up as a divergence
    instead of being shared by both sides."""
    from .fold import fold_program
    from .inline import inline_program
    return codegen.generate(fold_program(inline_program(parse_program(text))))


def run_source(text: str, inputs: list[int]) -> list[int]:
    """Compile the source and run it on the VM -- the numbers a receipt would record."""
    return run(compile_source(text), list(inputs))


def interpret_source(text: str, inputs: list[int], step_budget: int = 50_000_000) -> list[int]:
    """Evaluate the source directly with the reference interpreter (the oracle)."""
    return interp.interpret(parse_program(text), list(inputs), step_budget)


def ir_sha256(program: dict) -> str:
    """The program's canonical digest -- the same digest the receipt names as
    `program_sha256`, so a compiled program's identity is checkable independently."""
    return program_sha256(program)
