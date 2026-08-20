"""Python and JavaScript must agree on what LOADS, not merely on what hashes.

Two measured divergences motivated this file. A 5000-digit integer literal parsed
in the JS verifier as an unbounded BigInt and was refused by CPython, which caps
decimal integer conversion at 4300 digits. Two-thousand-level nesting parsed in
Node and raised RecursionError in Python. Either way a receipt exists that one
implementation reads and the other cannot -- the same class as the NaN and 1e400
splits already closed, and exactly the material an adversary looks for when the
whole product claim is "any implementation re-derives the same answer".

Duplicate object members are refused rather than resolved. Both parsers happened
to agree on last-value-wins, but that is a convention, not a guarantee: downstream
JSON readers -- other languages, security appliances, log pipelines -- do not all
share it, and a document whose meaning depends on which reader opens it has no
business being called canonical.

The limits are ~100x the largest shipped receipt (depth 5, 11 members, 35-element
arrays, 128-byte strings, 10-digit integers, 3 KB), so they bound hostile input
without coming near an honest one.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from obsign_verify.canonical import (MAX_DEPTH, MAX_INT_DIGITS, MAX_MEMBERS_PER_OBJECT,
                                     MAX_RECEIPT_BYTES, WireFormatError, load_receipt)

_HAS_NODE = shutil.which("node") is not None
_REQUIRED = "node" in {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}

#: (name, receipt text, must_load)
_CASES = [
    ("honest", '{"spec":"obsign/receipt/v1","n":1,"f":1.5}', True),
    ("duplicate-members", '{"a":1,"a":2}', False),
    ("duplicate-nested", '{"p":{"x":1,"x":2}}', False),
    ("huge-int", '{"a":' + "1" * (MAX_INT_DIGITS + 1) + "}", False),
    ("huge-int-negative", '{"a":-' + "1" * (MAX_INT_DIGITS + 1) + "}", False),
    ("int-at-limit", '{"a":' + "1" * MAX_INT_DIGITS + "}", True),
    ("deep-nesting", '{"a":' * (MAX_DEPTH + 2) + "1" + "}" * (MAX_DEPTH + 2), False),
    ("deep-nesting-array", "[" * (MAX_DEPTH + 2) + "]" * (MAX_DEPTH + 2), False),
    ("depth-at-limit", '{"a":' * (MAX_DEPTH - 1) + "1" + "}" * (MAX_DEPTH - 1), True),
    ("too-many-members",
     "{" + ",".join(f'"k{i}":1' for i in range(MAX_MEMBERS_PER_OBJECT + 1)) + "}", False),
    ("nan", '{"a":NaN}', False),
    ("infinity-literal", '{"a":1e400}', False),
]


@pytest.mark.parametrize("name,text,must_load", _CASES, ids=[c[0] for c in _CASES])
def test_python_loadability(name, text, must_load):
    if must_load:
        load_receipt(text)          # must not raise
    else:
        with pytest.raises(ValueError):   # WireFormatError is a ValueError
            load_receipt(text)


def test_an_oversized_receipt_is_refused_before_parsing():
    big = '{"a":"' + "x" * (MAX_RECEIPT_BYTES + 16) + '"}'
    with pytest.raises(WireFormatError):
        load_receipt(big)


def test_every_shipped_receipt_still_loads():
    """The limits must not touch anything honest. A bound that refuses the
    conformance corpus is a bound that was chosen wrong."""
    root = Path(__file__).resolve().parent.parent / "src" / "obsign_verify" / "data"
    files = list(root.rglob("*.json"))
    assert len(files) >= 10, f"expected the shipped corpus, found {len(files)}"
    for f in files:
        text = f.read_text(encoding="utf-8")
        try:
            json.loads(text)          # only receipts, not every vector file, are dicts
        except ValueError:
            continue
        if text.lstrip().startswith("{"):
            load_receipt(text)        # must not raise


@pytest.mark.skipif(not _HAS_NODE and not _REQUIRED, reason="node not installed")
def test_the_two_parsers_agree_on_every_case():
    """The point of the file: identical LOADABILITY, case for case."""
    assert _HAS_NODE, "OBSIGN_REQUIRE=node was set but node is not installed"
    runner = Path(__file__).resolve().parent / "wire_limits_runner.mjs"
    fd, name = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    tmp = Path(name)
    try:
        tmp.write_text(json.dumps([[c[0], c[1]] for c in _CASES]), encoding="utf-8")
        proc = subprocess.run(["node", str(runner), str(tmp)],
                              capture_output=True, text=True, timeout=120, check=False)
    finally:
        tmp.unlink(missing_ok=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    js = json.loads(proc.stdout.strip().splitlines()[-1])

    for name_, text, must_load in _CASES:
        try:
            load_receipt(text)
            py_loads = True
        except ValueError:
            py_loads = False
        assert py_loads == must_load, f"{name_}: Python loadability is not as declared"
        assert js[name_] == py_loads, (
            f"{name_}: LOADABILITY DIVERGES -- python={py_loads} javascript={js[name_]}. "
            f"A receipt one implementation reads and the other refuses is the split "
            f"this corpus exists to prevent.")
