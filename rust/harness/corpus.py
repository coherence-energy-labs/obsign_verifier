"""The corpus the three implementations are held to.

Kept beside the Rust crate rather than in `tests/` because it is the Rust port's
evidence: a third implementation is worth nothing on its own say-so, and this is the
material that turns "it agrees" into a measurement. `tests/test_cross_language_
differential.py` imports it and runs every case through Python, JavaScript and Rust.

The corpus has four layers, in increasing order of how much they can surprise you:

  1. what is COMMITTED -- the shipped chain, the challenge bundles, the producer-signed
     receipts, the worked example. These must verify identically forever.
  2. what is ADVERSARIAL BY HAND -- the wire-format edges (depth, digits, duplicate
     members, lone surrogates, oversized strings) and the receipts that were built to
     probe a specific suspected divergence. Every one of these was written because
     reading the three implementations suggested they might disagree.
  3. what is RANDOM -- seeded programs, inputs on the int64 edges, receipts mutated at
     random. Random cases find what nobody thought to suspect.
  4. what is DERIVED -- for every receipt in layers 1-3 that carries a replay program,
     the raw (program, inputs) pair is also run through the bare VM, so a divergence in
     the machine is separated from a divergence in the ladder around it.
"""
from __future__ import annotations

import json
import random
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "src"))

from obsign_verify.canonical import (MAX_DEPTH, MAX_INT_DIGITS,  # noqa: E402
                                     MAX_MEMBERS_PER_OBJECT, canonical_sha256, claim_of)
from obsign_verify.replay import output_sha256, program_sha256, run  # noqa: E402

DATA = REPO / "src" / "obsign_verify" / "data"

# A minimal program that actually depends on its input, used as the honest control in
# hand-built cases: out = in0 + 1.
LIVE_PROG = {
    "spec": "obsign/replay/1", "mem": 4, "steps": 100, "consts": [1],
    "input": {"offset": 0, "length": 1}, "output": {"offset": 2, "length": 1},
    "code": [["LOADC", 1, 0], ["ADD", 2, 0, 1], ["HALT"]],
}


def seal(receipt: dict) -> str:
    """Mint: recompute `receipt_sha256` over the claim and emit the document text."""
    r = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    r["receipt_sha256"] = canonical_sha256(claim_of(r))
    return json.dumps(r)


def replay_receipt(program=None, inputs=None, **over) -> dict:
    program = LIVE_PROG if program is None else program
    inputs = [41] if inputs is None else inputs
    try:
        out = run(program, list(inputs))
        digest, length = output_sha256(out), len(out)
    except Exception:
        digest, length = "0" * 64, 1
    r = {
        "spec": "obsign/receipt/v1", "kernel": "obsign/replay/1",
        "params": {"program": program, "program_sha256": program_sha256(program),
                   "inputs": list(inputs)},
        "output": {"dtype": "int64", "length": length, "sha256": digest},
    }
    r.update(over)
    return r


# --------------------------------------------------------------------------- layer 1

def committed_receipts() -> list[tuple[str, str]]:
    """Every receipt this repository ships, as raw text."""
    cases = []
    for path in sorted(DATA.rglob("*.json")):
        text = path.read_text(encoding="utf-8")
        if not text.lstrip().startswith("{"):
            continue                      # conformance_vectors.json is a list, not a receipt
        cases.append((f"committed:{path.relative_to(DATA)}", text))
    example = REPO / "examples" / "ecl_receipt.json"
    if example.exists():
        cases.append(("committed:examples/ecl_receipt.json", example.read_text(encoding="utf-8")))
    for path in sorted((REPO / "stream").glob("*.json")):
        text = path.read_text(encoding="utf-8")
        if text.lstrip().startswith("{"):
            cases.append((f"committed:stream/{path.name}", text))
    return cases


# --------------------------------------------------------------------------- layer 2

def wire_format_edges() -> list[tuple[str, str]]:
    """Documents that sit exactly on a stated limit, or one step past it.

    A limit is only shared if both sides round it the same way, and "one past" is where
    an off-by-one lives. The lone-surrogate and oversized-string cases are here because
    reading the two parsers suggested only ONE of them enforces those rules.
    """
    big = "1" * MAX_INT_DIGITS
    return [
        ("edge:honest", '{"spec":"obsign/receipt/v1","n":1,"f":1.5}'),
        ("edge:duplicate-members", '{"a":1,"a":2}'),
        ("edge:duplicate-nested", '{"p":{"x":1,"x":2}}'),
        ("edge:int-at-limit", '{"a":' + big + "}"),
        ("edge:int-past-limit", '{"a":' + big + "1}"),
        ("edge:int-past-limit-negative", '{"a":-' + big + "1}"),
        ("edge:depth-at-limit", '{"a":' * (MAX_DEPTH - 1) + "1" + "}" * (MAX_DEPTH - 1)),
        ("edge:depth-scalar-32", '{"a":' * MAX_DEPTH + "1" + "}" * MAX_DEPTH),
        ("edge:depth-scalar-33", '{"a":' * (MAX_DEPTH + 1) + "1" + "}" * (MAX_DEPTH + 1)),
        # 33 containers where the innermost is EMPTY: CPython's depth rule counts the
        # depth a VALUE sits at, so an empty container has no member to reject.
        ("edge:depth-33-empty-innermost", '{"a":' * MAX_DEPTH + "{}" + "}" * MAX_DEPTH),
        ("edge:depth-32-empty-innermost", '{"a":' * (MAX_DEPTH - 1) + "{}" + "}" * (MAX_DEPTH - 1)),
        ("edge:array-depth-33", "[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1)),
        ("edge:members-at-limit",
         "{" + ",".join(f'"k{i}":1' for i in range(MAX_MEMBERS_PER_OBJECT)) + "}"),
        ("edge:members-past-limit",
         "{" + ",".join(f'"k{i}":1' for i in range(MAX_MEMBERS_PER_OBJECT + 1)) + "}"),
        ("edge:nan", '{"a":NaN}'),
        ("edge:infinity-literal", '{"a":1e400}'),
        ("edge:negative-infinity-literal", '{"a":-1e400}'),
        ("edge:infinity-token", '{"a":Infinity}'),
        ("edge:minus-zero-int", '{"a":-0}'),
        ("edge:minus-zero-float", '{"a":-0.0}'),
        ("edge:exponent-no-point", '{"a":1e2}'),
        ("edge:leading-zero", '{"a":01}'),
        ("edge:bare-decimal-point", '{"a":.5}'),
        ("edge:trailing-decimal-point", '{"a":1.}'),
        ("edge:plus-sign", '{"a":+1}'),
        ("edge:trailing-comma", '{"a":1,}'),
        ("edge:trailing-data", '{"a":1} {"b":2}'),
        ("edge:top-level-array", "[1,2,3]"),
        ("edge:raw-control-char-in-string", '{"a":"x\x01y"}'),
        ("edge:lone-high-surrogate", '{"a":"\\ud800"}'),
        ("edge:lone-low-surrogate", '{"a":"\\udc00"}'),
        ("edge:valid-surrogate-pair", '{"a":"\\ud83d\\ude00"}'),
        ("edge:raw-astral-character", '{"a":"\U0001f600"}'),
        ("edge:string-at-limit", '{"a":"' + "x" * 65536 + '"}'),
        ("edge:string-past-limit", '{"a":"' + "x" * 65537 + '"}'),
        ("edge:key-past-limit", '{"' + "k" * 65537 + '":1}'),
        ("edge:utf8-bom", "﻿" + '{"a":1}'),
        ("edge:empty-object", "{}"),
        ("edge:unicode-keys-sort", '{"\\ue000":1,"\\ud83d\\ude00":2,"a":3}'),
    ]


def suspected_divergences() -> list[tuple[str, str]]:
    """Receipts built to test one specific suspicion each.

    Every case here came from reading the three implementations side by side and
    noticing a place where they could not all be doing the same thing. They are named
    for the mechanism rather than for the outcome, because the outcome is the finding.
    """
    cases = []

    # `output.length` is a STRUCTURAL scalar. `True == 1` in Python.
    r = replay_receipt()
    r["output"] = dict(r["output"], length=True)
    cases.append(("suspect:output-length-is-json-true", seal(r)))
    r = replay_receipt()
    r["output"] = dict(r["output"], length=1.0)
    cases.append(("suspect:output-length-is-json-float", seal(r)))
    r = replay_receipt()
    r["output"] = dict(r["output"], length="1")
    cases.append(("suspect:output-length-is-string", seal(r)))

    # A whole-valued FLOAT inside the program. Canonical JSON keeps `1.0` and `1`
    # distinct, so any implementation that re-types by value computes a different
    # program digest.
    p = dict(LIVE_PROG, note_f=1.0)
    cases.append(("suspect:program-carries-whole-float", seal(replay_receipt(program=p))))
    p = dict(LIVE_PROG, note_f=1.5)
    cases.append(("suspect:program-carries-fractional-float", seal(replay_receipt(program=p))))

    # A program whose members are reachable only through a `__proto__` member.
    r = replay_receipt()
    r["params"] = {"program": {"__proto__": LIVE_PROG}, "inputs": [41]}
    cases.append(("suspect:program-behind-__proto__", seal(r)))
    r = replay_receipt()
    r["params"] = {"program": dict(LIVE_PROG, __proto__={"mem": 1}), "inputs": [41]}
    cases.append(("suspect:program-with-extra-__proto__-member", seal(r)))

    # Structural scalars written as booleans or floats, which docs/COMPAT.md says every
    # implementation must now refuse.
    for field, value, label in [("mem", True, "true"), ("mem", 4.0, "float"),
                                ("steps", True, "true"), ("steps", 100.0, "float")]:
        p = dict(LIVE_PROG)
        p[field] = value
        cases.append((f"suspect:program-{field}-is-{label}", seal(replay_receipt(program=p))))
    p = dict(LIVE_PROG, consts=[1.0])
    cases.append(("suspect:const-is-float", seal(replay_receipt(program=p))))
    p = dict(LIVE_PROG, consts=[True])
    cases.append(("suspect:const-is-true", seal(replay_receipt(program=p))))
    p = dict(LIVE_PROG, code=[["LOADC", 1, 0], ["ADD", 2.0, 0, 1], ["HALT"]])
    cases.append(("suspect:operand-is-float", seal(replay_receipt(program=p))))
    p = dict(LIVE_PROG, code=[["LOADC", 1, 0], ["ADD", True, 0, 1], ["HALT"]])
    cases.append(("suspect:operand-is-true", seal(replay_receipt(program=p))))

    # Inputs that are not int64s.
    for label, val in [("float", 41.0), ("true", True), ("string", "41"),
                       ("above-int64", 2**63), ("below-int64", -(2**63) - 1)]:
        cases.append((f"suspect:input-is-{label}",
                      seal(replay_receipt(inputs=[val]))))

    # A constant program: re-derives perfectly and proves nothing about its inputs.
    const_prog = {"spec": "obsign/replay/1", "mem": 4, "steps": 100, "consts": [424242],
                  "input": {"offset": 0, "length": 1}, "output": {"offset": 2, "length": 1},
                  "code": [["LOADC", 2, 0], ["HALT"]]}
    cases.append(("suspect:constant-program-dead-inputs",
                  seal(replay_receipt(program=const_prog))))

    # A constant behind an equality guard: every perturbation TRAPS, which is a refusal
    # to run rather than evidence about the output.
    guarded = {"spec": "obsign/replay/1", "mem": 8, "steps": 200,
               "consts": [41, 424242, 0, 1],
               "input": {"offset": 0, "length": 1}, "output": {"offset": 5, "length": 1},
               "code": [["LOADC", 1, 0], ["EQ", 2, 0, 1], ["LOADC", 3, 3],
                        ["DIV", 4, 3, 2], ["LOADC", 5, 1], ["HALT"]]}
    cases.append(("suspect:guarded-constant", seal(replay_receipt(program=guarded))))

    # int64 extremes through MULFX, where an implementation that multiplies before
    # widening loses exactly the bits the shift exists to discard.
    wide = {"spec": "obsign/replay/1", "mem": 6, "steps": 100,
            "consts": [2**62, 3], "input": {"offset": 0, "length": 1},
            "output": {"offset": 4, "length": 1},
            "code": [["LOADC", 1, 0], ["MULFX", 4, 0, 1, 32], ["HALT"]]}
    for v in (2**63 - 1, -(2**63), 2**62, -1, 0):
        cases.append((f"suspect:mulfx-wide-{v}", seal(replay_receipt(program=wide, inputs=[v]))))

    # Unknown kernels and unknown program specs: "unsupported" is a third answer.
    cases.append(("suspect:unknown-kernel",
                  seal(replay_receipt(kernel="obsign/replay/2"))))
    p = dict(LIVE_PROG, spec="obsign/replay/2")
    cases.append(("suspect:unknown-program-spec", seal(replay_receipt(program=p))))

    # An `env`-only change must not move the claim hash.
    r = replay_receipt(env={"platform": "somewhere else", "n": 1e-06})
    cases.append(("suspect:env-only-change", seal(r)))
    return cases


def signed_cases() -> list[tuple[str, str]]:
    """Signature-envelope cases, minted here with a throwaway key.

    Skipped silently if `cryptography` is absent; the signed CONFORMANCE receipts in
    layer 1 still exercise the v2 path with the producer's real key.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return []
    from obsign_verify.signature import SIG_DOMAIN_V2

    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw).hex()

    def base():
        r = replay_receipt(case={"case_id": "2026-CR-0041", "examiner": "A. Chen"})
        r["receipt_sha256"] = canonical_sha256(claim_of(r))
        return r

    def sign_v2(r, *, binds_sha256, binds=None, signer="A. Chen", spec="obsign/signature/v2",
                alg="ed25519", corrupt=False):
        covered = {"spec": spec, "alg": alg, "public_key": pk,
                   "receipt_sha256": r["receipt_sha256"], "signer": signer,
                   "binds_sha256": binds_sha256}
        sig = sk.sign(SIG_DOMAIN_V2 + canonical_sha256(covered).encode("ascii")).hex()
        if corrupt:
            sig = ("f" if sig[0] != "f" else "0") + sig[1:]
        block = {"spec": spec, "alg": alg, "public_key": pk, "signer": signer,
                 "binds_sha256": binds_sha256, "sig": sig}
        if binds is not None:
            block["binds"] = binds
        out = dict(r)
        out["signature"] = block
        return json.dumps(out)

    cases = []
    r = base()
    bh = canonical_sha256({"case": r["case"]})
    cases.append(("sig:v2-honest-binds-case", sign_v2(r, binds_sha256=bh, binds=["case"])))
    cases.append(("sig:v2-binds-stripped", sign_v2(r, binds_sha256=bh)))
    cases.append(("sig:v2-binds-empty-list", sign_v2(r, binds_sha256=bh, binds=[])))
    cases.append(("sig:v2-corrupt-signature",
                  sign_v2(r, binds_sha256=bh, binds=["case"], corrupt=True)))
    cases.append(("sig:v2-binds-nothing", sign_v2(r, binds_sha256=None)))
    # A `binds_sha256` that is not a string is not a digest. If an implementation reads
    # a non-string as "absent", an empty `binds` list reproduces it and the check that
    # exists to stop `case.examiner` being rewritten never runs.
    cases.append(("sig:v2-binds_sha256-is-number", sign_v2(r, binds_sha256=0)))
    cases.append(("sig:v2-binds_sha256-is-true", sign_v2(r, binds_sha256=True)))
    cases.append(("sig:v2-binds-is-not-a-list", sign_v2(r, binds_sha256=bh, binds="case")))
    cases.append(("sig:v2-binds-has-non-string", sign_v2(r, binds_sha256=bh, binds=[1])))
    cases.append(("sig:v2-alg-uppercase", sign_v2(r, binds_sha256=bh, binds=["case"], alg="ED25519")))
    cases.append(("sig:v2-unknown-sig-spec",
                  sign_v2(r, binds_sha256=bh, binds=["case"], spec="obsign/signature/v3")))
    cases.append(("sig:v2-signer-is-null", sign_v2(r, binds_sha256=bh, binds=["case"], signer=None)))

    # v1 signs the bare receipt hash: verifies, and attributes NOBODY.
    v1 = dict(base())
    v1["signature"] = {"spec": "obsign/signature/v1", "alg": "ed25519", "public_key": pk,
                       "signer": "A. Chen",
                       "sig": sk.sign(v1["receipt_sha256"].encode("ascii")).hex()}
    cases.append(("sig:v1-legacy", json.dumps(v1)))

    # `sig` of the wrong TYPE beside a real `signature` member: a fallback between
    # spellings that reads a number as "absent" verifies a block the reference refuses.
    r2 = base()
    covered = {"spec": "obsign/signature/v2", "alg": "ed25519", "public_key": pk,
               "receipt_sha256": r2["receipt_sha256"], "signer": "A. Chen",
               "binds_sha256": None}
    real = sk.sign(SIG_DOMAIN_V2 + canonical_sha256(covered).encode("ascii")).hex()
    for label, bad in [("number", 5), ("true", True), ("empty-string", ""), ("null", None)]:
        r3 = dict(r2)
        r3["signature"] = {"spec": "obsign/signature/v2", "alg": "ed25519", "public_key": pk,
                           "signer": "A. Chen", "binds_sha256": None,
                           "sig": bad, "signature": real}
        cases.append((f"sig:sig-member-is-{label}", json.dumps(r3)))

    # A signature over a claim that no longer hashes: there is no claim left to attribute.
    r4 = json.loads(sign_v2(base(), binds_sha256=bh, binds=["case"]))
    r4["params"] = dict(r4["params"], inputs=[42])
    cases.append(("sig:claim-tampered-after-signing", json.dumps(r4)))
    return cases


# --------------------------------------------------------------------------- layer 3

_I64 = (0, 1, -1, 2, -2, 7, 255, 256, 2**31, -(2**31), 2**32, 2**53, 2**53 + 1,
        2**62, 2**63 - 1, -(2**63), -(2**63) + 1, 3037000499, -3037000499)

_OPS_2 = ["ADD", "SUB", "MUL", "DIV", "MOD", "MIN", "MAX", "AND", "OR", "XOR",
          "SHL", "SHR", "EQ", "NE", "LT", "LE", "GT", "GE"]
_OPS_1 = ["MOV", "NEG", "ABS", "NOT", "LOAD"]


def random_program(rng: random.Random, mem: int = 16) -> dict:
    """A random but structurally valid program.

    Structural validity is the point: an invalid program is refused by all three
    trivially, while a valid one that TRAPS somewhere -- a division by zero, a shift of
    64, an address off the end, a budget that runs out -- is where the three machines
    can actually disagree. The contract is trap-for-trap, not merely value-for-value.
    """
    consts = [rng.choice(_I64) for _ in range(rng.randint(1, 4))]
    n = rng.randint(1, 14)
    code = []
    for _ in range(n):
        kind = rng.random()
        if kind < 0.42:
            code.append([rng.choice(_OPS_2), rng.randrange(mem), rng.randrange(mem),
                         rng.randrange(mem)])
        elif kind < 0.62:
            code.append([rng.choice(_OPS_1), rng.randrange(mem), rng.randrange(mem)])
        elif kind < 0.72:
            code.append(["LOADC", rng.randrange(mem), rng.randrange(len(consts))])
        elif kind < 0.80:
            code.append(["MULFX", rng.randrange(mem), rng.randrange(mem), rng.randrange(mem),
                         rng.choice([0, 1, 16, 31, 32, 62, 63])])
        elif kind < 0.86:
            code.append(["SEL", rng.randrange(mem), rng.randrange(mem), rng.randrange(mem),
                         rng.randrange(mem)])
        elif kind < 0.90:
            code.append(["STORE", rng.randrange(mem), rng.randrange(mem)])
        elif kind < 0.96:
            code.append([rng.choice(["JMPZ", "JMPNZ"]), rng.randrange(mem), rng.randrange(n)])
        else:
            code.append(["JMP", rng.randrange(n)])
    code.append(["HALT"])
    in_len = rng.randint(1, 3)
    return {"spec": "obsign/replay/1", "mem": mem,
            "steps": rng.choice([1, 2, 8, 64, 500, 500, 500, 2000]),
            "consts": consts,
            "input": {"offset": 0, "length": in_len},
            "output": {"offset": rng.randrange(mem - 1), "length": rng.randint(1, 2)},
            "code": code}


def random_vm_cases(seed: int = 20260820, count: int = 900) -> list[tuple[str, dict]]:
    """(program, inputs) pairs for the bare machine. Seeded: every failure reproduces."""
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        prog = random_program(rng)
        n = prog["input"]["length"]
        inputs = [rng.choice(_I64) if rng.random() < 0.7 else rng.randint(-(2**63), 2**63 - 1)
                  for _ in range(n)]
        cases.append((f"rand-vm:{i}", {"program": json.dumps(prog),
                                       "inputs": [str(v) for v in inputs]}))
    return cases


# ------------------------------------------------------- layer 3b: the arithmetic grid

#: The int64 values where implementations disagree if they are going to: the range
#: ends, the sign boundary, the 2^53 line where a double stops being exact, and
#: 3037000499 (the largest x with x*x inside int64).
EDGE = [0, 1, -1, 2, -2, 3, -3, 7, -7, 255, 256, 65535, 2**31 - 1, -(2**31),
        2**32, 2**53 - 1, 2**53, 2**53 + 1, 2**62, 2**63 - 1, -(2**63), -(2**63) + 1,
        3037000499, -3037000499, 4294967296]

_BINARY = ["ADD", "SUB", "MUL", "DIV", "MOD", "MIN", "MAX", "AND", "OR", "XOR",
           "SHL", "SHR", "EQ", "NE", "LT", "LE", "GT", "GE"]
_UNARY = ["MOV", "NEG", "ABS", "NOT"]


def _grid_program(op: str, pairs: list[tuple[int, int]], frac: int | None = None) -> dict:
    """One program per operator, computing it over EVERY pair at once.

    Batching is what makes an exhaustive grid affordable across three processes: 600
    operand pairs become one program and one output vector to compare, instead of 600
    subprocess round trips.
    """
    n = len(pairs)
    in_len = 2 * n
    mem = in_len + n + 1
    code = []
    for i in range(n):
        if frac is not None:
            code.append([op, in_len + i, 2 * i, 2 * i + 1, frac])
        else:
            code.append([op, in_len + i, 2 * i, 2 * i + 1])
    code.append(["HALT"])
    return {"spec": "obsign/replay/1", "mem": mem, "steps": n + 1, "consts": [0],
            "input": {"offset": 0, "length": in_len},
            "output": {"offset": in_len, "length": n},
            "code": code}


def arithmetic_grid_cases() -> list[tuple[str, dict]]:
    """Every binary operator over every pair of int64 edge values.

    This is the part a random generator reaches only by luck. Wrapping on overflow,
    truncation toward zero on a negative dividend, INT64_MIN / -1, an arithmetic right
    shift of a negative number, and MULFX's exact-128-bit product are each a place where
    a language's native behaviour differs from the format's -- and the three languages
    here have three different natives.
    """
    cases: list[tuple[str, dict]] = []
    all_pairs = [(a, b) for a in EDGE for b in EDGE]

    for op in _BINARY:
        pairs = all_pairs
        if op in ("DIV", "MOD"):
            pairs = [(a, b) for a, b in all_pairs if b != 0]     # zero divisors trap; below
        if op in ("SHL", "SHR"):
            pairs = [(a, b) for a in EDGE for b in range(0, 64)]  # out-of-range shifts trap
        prog = _grid_program(op, pairs)
        flat = [v for pair in pairs for v in pair]
        cases.append((f"grid:{op}", {"program": json.dumps(prog),
                                     "inputs": [str(v) for v in flat]}))

    # MULFX at the fractional scales that matter: none, the fixed-point default, and
    # the extremes where the 128-bit product is the only thing keeping the answer right.
    for frac in (0, 1, 16, 31, 32, 33, 62, 63):
        pairs = all_pairs
        prog = _grid_program("MULFX", pairs, frac=frac)
        flat = [v for pair in pairs for v in pair]
        cases.append((f"grid:MULFX-{frac}", {"program": json.dumps(prog),
                                             "inputs": [str(v) for v in flat]}))

    # Unary operators, over every edge value.
    for op in _UNARY:
        n = len(EDGE)
        code = [[op, n + i, i] for i in range(n)] + [["HALT"]]
        prog = {"spec": "obsign/replay/1", "mem": 2 * n + 1, "steps": n + 1, "consts": [0],
                "input": {"offset": 0, "length": n}, "output": {"offset": n, "length": n},
                "code": code}
        cases.append((f"grid:{op}", {"program": json.dumps(prog),
                                     "inputs": [str(v) for v in EDGE]}))

    # THE PARTIAL CASES, one program each so a trap cannot mask the rest. Every one of
    # these must trap in all three, because "every partial operation is a Trap" is the
    # totality property the whole machine rests on.
    def one(op, a, b, frac=None):
        code = [[op, 2, 0, 1, frac] if frac is not None else [op, 2, 0, 1], ["HALT"]]
        return {"spec": "obsign/replay/1", "mem": 4, "steps": 4, "consts": [0],
                "input": {"offset": 0, "length": 2}, "output": {"offset": 2, "length": 1},
                "code": code}

    partial = []
    for op in ("DIV", "MOD"):
        for a in (0, 1, -1, 2**63 - 1, -(2**63)):
            partial.append((f"trap:{op}-by-zero-{a}", one(op, a, 0), [a, 0]))
        # INT64_MIN / -1 overflows the range and WRAPS; it does not trap.
        partial.append((f"edge:{op}-int64min-by-minus-one", one(op, 0, 0),
                        [-(2**63), -1]))
    for op in ("SHL", "SHR"):
        for b in (-1, 64, 65, 2**31, -(2**63), 2**63 - 1):
            partial.append((f"trap:{op}-amount-{b}", one(op, 1, b), [1, b]))
        for b in (0, 63):
            partial.append((f"edge:{op}-amount-{b}", one(op, -(2**63), b), [-(2**63), b]))
    for addr in (-1, 4, 5, 2**62, -(2**63)):
        load = {"spec": "obsign/replay/1", "mem": 4, "steps": 4, "consts": [0],
                "input": {"offset": 0, "length": 1}, "output": {"offset": 2, "length": 1},
                "code": [["LOAD", 2, 0], ["HALT"]]}
        partial.append((f"trap:LOAD-address-{addr}", load, [addr]))
        store = dict(load, code=[["STORE", 0, 1], ["HALT"]])
        partial.append((f"trap:STORE-address-{addr}", store, [addr]))
    for name, prog, inputs in partial:
        cases.append((f"grid-{name}", {"program": json.dumps(prog),
                                       "inputs": [str(v) for v in inputs]}))
    return cases


def random_receipts(seed: int = 20260821, count: int = 220) -> list[tuple[str, str]]:
    """Random receipts, half of them mutated after sealing.

    A mutated receipt should fail integrity in every implementation; an unmutated one
    should reach the same verdict in every implementation. Both directions matter.
    """
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        prog = random_program(rng, mem=12)
        n = prog["input"]["length"]
        inputs = [rng.choice(_I64) for _ in range(n)]
        r = replay_receipt(program=prog, inputs=inputs)
        text = seal(r)
        if rng.random() < 0.45:
            doc = json.loads(text)
            what = rng.choice(["inputs", "output_hash", "length", "digest", "env", "steps"])
            if what == "inputs" and doc["params"]["inputs"]:
                j = rng.randrange(len(doc["params"]["inputs"]))
                doc["params"]["inputs"][j] = rng.choice(_I64)
            elif what == "output_hash":
                doc["output"]["sha256"] = "0" * 64
            elif what == "length":
                doc["output"]["length"] = rng.choice([0, 2, 99])
            elif what == "digest":
                doc["params"]["program_sha256"] = "b" * 64
            elif what == "env":
                doc["env"] = {"host": "elsewhere"}    # outside the claim: must NOT matter
            else:
                doc["params"]["program"]["steps"] = rng.choice([1, 2, 3])
            text = json.dumps(doc)
        cases.append((f"rand-receipt:{i}", text))
    return cases


def random_live_receipts(seed: int = 20260823, count: int = 90) -> list[tuple[str, str]]:
    """Honest receipts that actually VERIFY, so the green path is exercised too.

    The random generator above produces mostly refusals -- a random program usually
    ignores its inputs, which is `dead`, which is a refusal. Agreement on a refusal is
    much cheaper to achieve than agreement on a pass: three implementations that all
    crash agree perfectly. These fold every input into the answer with total operators
    only, so the program cannot trap and the first input always moves the output.
    """
    rng = random.Random(seed)
    total_ops = ["ADD", "SUB", "XOR", "MIN", "MAX"]
    cases = []
    for i in range(count):
        k = rng.randint(1, 4)
        code = [["MOV", 7, 0]]
        for j in range(1, k):
            code.append([rng.choice(total_ops), 7, 7, j])
        if k == 1:
            code.append(["ADD", 7, 7, 0])       # keep input 0 reaching the output
        code.append(["HALT"])
        prog = {"spec": "obsign/replay/1", "mem": 8, "steps": len(code) + 1,
                "consts": [1], "input": {"offset": 0, "length": k},
                "output": {"offset": 7, "length": 1}, "code": code}
        inputs = [rng.choice(_I64) for _ in range(k)]
        cases.append((f"live-receipt:{i}", seal(replay_receipt(program=prog, inputs=inputs))))
    return cases


def random_canonical_values(seed: int = 20260822, count: int = 600) -> list[tuple[str, str]]:
    """Documents whose canonical BYTES the three must agree on, character for character.

    Floats carry most of the risk: all three print the shortest decimal that round
    trips, and they disagree about presentation -- whole-numbered floats, the exponent
    thresholds, exponent padding -- in ways that change bytes and therefore hashes.
    """
    rng = random.Random(seed)
    cases: list[tuple[str, str]] = []

    fixed = [0.0, -0.0, 1.0, -1.0, 0.5, 1e15, 1e16, 1e17, 9.999999999999998e15,
             1e-4, 9.999e-5, 1e-5, 1e-6, 1e-7, 5e-324, 1.7976931348623157e308,
             2.2250738585072014e-308, 1/3, 2/3, 0.1, 0.2, 0.3, 1e21, 1e22,
             123456789012345.6, 1.5e-10, -3e-05, 1e-06, 5e-05]
    for i, f in enumerate(fixed):
        cases.append((f"float-fixed:{i}", json.dumps({"v": f})))

    for i in range(count):
        kind = rng.random()
        if kind < 0.5:
            bits = rng.getrandbits(64)
            f = struct.unpack("<d", struct.pack("<Q", bits))[0]
            if f != f or f in (float("inf"), float("-inf")):
                continue
            cases.append((f"float-random:{i}", json.dumps({"v": f})))
        elif kind < 0.7:
            f = rng.uniform(-1e6, 1e6) * (10 ** rng.randint(-20, 20))
            if f != f or f in (float("inf"), float("-inf")):
                continue
            cases.append((f"float-scaled:{i}", json.dumps({"v": f})))
        elif kind < 0.85:
            n = rng.randint(1, 6)
            doc = {f"k{j}": rng.choice(_I64) for j in range(n)}
            doc["nested"] = {"a": [rng.choice(_I64) for _ in range(3)],
                             "b": {"c": rng.random()}}
            cases.append((f"mixed:{i}", json.dumps(doc)))
        else:
            # Unicode keys and values, where key ORDER is by code point and every
            # non-ASCII character is escaped.
            chars = [chr(rng.choice([0x41, 0x7e, 0x7f, 0x80, 0xff, 0x100, 0x2028,
                                     0xd7ff, 0xe000, 0xfffd, 0x10000, 0x1f600, 0x10ffff]))
                     for _ in range(rng.randint(1, 4))]
            doc = {"".join(chars): "".join(reversed(chars)), "a": 1}
            cases.append((f"unicode:{i}", json.dumps(doc, ensure_ascii=False)))
    return cases


# --------------------------------------------------------------------------- layer 4

def vm_cases_from_receipts(receipt_cases: list[tuple[str, str]]) -> list[tuple[str, dict]]:
    """Pull every (program, inputs) pair out of a receipt corpus.

    Separating the machine from the ladder around it is what makes a disagreement
    diagnosable: if the bare VM agrees and the verdicts do not, the fault is in the
    ladder, and the other way round.
    """
    out = []
    for name, text in receipt_cases:
        try:
            doc = json.loads(text)
        except ValueError:
            continue
        params = doc.get("params")
        if not isinstance(params, dict):
            continue
        prog, inputs = params.get("program"), params.get("inputs")
        if not isinstance(prog, dict) or not isinstance(inputs, list):
            continue
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in inputs):
            continue
        if not all(-(2**63) <= v <= 2**63 - 1 for v in inputs):
            continue
        out.append((f"vm-of:{name}", {"program": json.dumps(prog),
                                      "inputs": [str(v) for v in inputs]}))
    return out


def graph_cases() -> list[tuple[str, list[str]]]:
    """Chains, and the ways a chain can be wrong.

    docs/GRAPHS.md's six rules each get at least one case, plus the two verdicts the
    rule insists stay distinguishable: a node that is internally true while its links
    lie, and a chain that is INCOMPLETE rather than forged.
    """
    chain = {p.stem: p.read_text(encoding="utf-8")
             for p in sorted((DATA / "conformance" / "chain").glob("*.json"))}
    if not chain:
        return []
    desks = [v for k, v in chain.items() if k != "firm_root"]
    root = chain["firm_root"]
    cases: list[tuple[str, list[str]]] = [
        ("graph:full-chain", desks + [root]),
        ("graph:shuffled", [root] + list(reversed(desks))),
        ("graph:root-only-incomplete", [root]),
        ("graph:leaves-only", desks),
        ("graph:empty", []),
        ("graph:duplicate-envelope", desks + [root, root]),
    ]

    # A re-enveloped copy: same claim, different document. Both must run the ladder.
    doc = json.loads(root)
    doc["env"] = {"note": "re-enveloped by whoever handed you the set"}
    cases.append(("graph:re-enveloped-root", desks + [root, json.dumps(doc)]))

    # A leaf edited after the fact: the digest moves, so the link is orphaned. The
    # chain DISCONNECTS, it does not silently corrupt.
    doc = json.loads(desks[0])
    doc["params"] = dict(doc["params"], inputs=list(doc["params"]["inputs"]))
    doc["params"]["inputs"][0] = doc["params"]["inputs"][0] + 1
    cases.append(("graph:leaf-edited", [json.dumps(doc)] + desks[1:] + [root]))

    # A parent that did NOT consume what the child produced.
    doc = json.loads(root)
    doc["params"] = dict(doc["params"], inputs=list(doc["params"]["inputs"]))
    doc["params"]["inputs"][0] = doc["params"]["inputs"][0] + 1
    doc["output"] = dict(doc["output"], sha256="0" * 64)
    cases.append(("graph:parent-input-does-not-match-child", desks + [json.dumps(doc)]))

    # Malformed link ranges REFUSE; they do not clamp.
    for label, patch in [
        ("negative-length", {"length": -1}),
        ("zero-length", {"length": 0}),
        ("dst-past-end", {"dst_offset": 99}),
        ("src-past-end", {"src_offset": 99}),
        ("length-float", {"length": 1.0}),
        ("length-true", {"length": True}),
        ("short-digest", {"receipt_sha256": "abc"}),
        ("wrong-output-hash", {"output_sha256": "0" * 64}),
        ("unknown-child", {"receipt_sha256": "e" * 64}),
    ]:
        doc = json.loads(root)
        doc["params"]["links"][0] = dict(doc["params"]["links"][0], **patch)
        cases.append((f"graph:link-{label}", desks + [json.dumps(doc)]))

    # Two links landing on the same destination slot.
    doc = json.loads(root)
    doc["params"]["links"][1] = dict(doc["params"]["links"][1],
                                     dst_offset=doc["params"]["links"][0]["dst_offset"])
    cases.append(("graph:overlapping-destinations", desks + [json.dumps(doc)]))

    # A self-link: cryptographically unmintable, and the verifier guards anyway.
    doc = json.loads(root)
    doc["params"]["links"] = [dict(doc["params"]["links"][0],
                                   receipt_sha256=canonical_sha256(claim_of(doc)))]
    cases.append(("graph:self-link", [json.dumps(doc)]))

    cases.append(("graph:not-an-object", ["[1,2,3]"]))
    return cases
