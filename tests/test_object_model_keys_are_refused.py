"""A receipt is data; it must not depend on the reader's object model.

THE BREAK THIS PINS. `js/src/verify.js` built plain objects with `o[k] = v`. In
JavaScript `o["__proto__"] = x` is a SETTER, not an assignment: it reparents the
object. So a receipt whose program was

    "program": {"__proto__": { ...a complete, valid replay program... }}

produced an object with ZERO own members that answered .spec, .code and .steps
through the prototype chain. Measured, not theorised: the npm verifier reported
`verified: true, integrity: true, reproduced: true` on a receipt the reference
implementation refuses -- it executed and re-derived a program Python cannot read.

Worse, `programSha256` hashed the empty own-property set, so every such program
carried the SAME digest, sha256("{}") = 44136fa355b3678a..., which defeats
--expect-program pinning: a validator who approved one program would accept any
of them.

The browser verifier was already immune -- verify-core.js builds with
Object.create(null) and its comment describes this exact attack -- which is why
this is worth a test rather than a memo: the knowledge existed in one
implementation and not its sibling.

Fixed in two layers. plain() builds on a null prototype so no setter exists, and
every parser refuses these names outright, so all four implementations agree on
what LOADS rather than each sanitising differently.
"""
from __future__ import annotations

import json

import pytest

from obsign_verify import mint
from obsign_verify.canonical import load_receipt
from obsign_verify.replayc import compile_source

_HONEST = mint.replay_receipt(compile_source("input a, b; output a * 3 + b;"), [5, 7])


@pytest.mark.parametrize("key", ["__proto__", "constructor", "prototype"])
def test_object_model_keys_are_refused_at_load(key):
    txt = json.dumps({"spec": "obsign/receipt/v1", "params": {"x": {key: {"a": 1}}}})
    with pytest.raises(Exception, match="object-model slot"):
        load_receipt(txt)


def test_the_polluted_program_receipt_is_refused_rather_than_reproduced():
    """The end-to-end exploit: a program carried entirely on a prototype."""
    import copy
    forged = copy.deepcopy(_HONEST)
    # Build it structurally: a string replacement is at the mercy of key order and
    # separator choice, and a replacement that silently misses produces a test that
    # passes because it exercises nothing.
    forged["params"]["program"] = {"__PROTO__": forged["params"]["program"]}
    txt = json.dumps(forged).replace('"__PROTO__"', '"__proto__"')
    assert '"__proto__"' in txt, "the exploit did not get built; test is vacuous"
    with pytest.raises(Exception, match="object-model slot"):
        load_receipt(txt)


def test_an_honest_receipt_still_loads_and_verifies():
    """The refusal must not cost honest receipts anything."""
    from obsign_verify.verify import verify
    r = load_receipt(json.dumps(_HONEST))
    assert verify(r)["verified"] is True


def test_the_key_is_refused_at_any_depth():
    txt = json.dumps({"a": {"b": {"c": [{"__proto__": {"deep": True}}]}}})
    with pytest.raises(Exception, match="object-model slot"):
        load_receipt(txt)
