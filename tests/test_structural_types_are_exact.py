"""Fixed-kernel integer fields are INTERPRETED, never repaired.

`int(p["grid"])` accepted 3.9 as 3, "3" as 3, and True as 1 (bool subclasses int).
That is a verifier repairing a document instead of reading it. Canonical JSON
writes `3` and `3.0` differently and they hash differently, so the distinction is
on the wire and it matters: two receipts that differ only there are different
documents, and quietly collapsing them is how "verified" drifts between
implementations. The replay VM has always refused a float where an integer is
required -- this pins the fixed-kernel path to the same rule.
"""
from __future__ import annotations

import pytest

from obsign_verify.kernel import validate_params


def _params(**over):
    p = {"grid": 8, "steps": 2, "frac_bits": 24,
         "sources": [(0.5, 0.5, 1.0, 0.2)],
         "D": 0.1, "gamma": 0.1, "dt": 0.1}
    p.update(over)
    return p


def test_the_honest_shape_still_validates():
    validate_params(_params())          # must not raise


@pytest.mark.parametrize("field", ["grid", "steps", "frac_bits"])
@pytest.mark.parametrize("bad", [3.0, 3.9, "3", True, False, None, [], {}, "  3  "],
                         ids=["float-round", "float-frac", "str", "true", "false",
                              "null", "list", "dict", "str-padded"])
def test_a_non_integer_is_refused_not_coerced(field, bad):
    with pytest.raises(ValueError) as e:
        validate_params(_params(**{field: bad}))
    assert "malformed" in str(e.value).lower() or "integer" in str(e.value).lower(), e.value


def test_true_is_not_one():
    """The subtlest of the set: Python says isinstance(True, int), so `steps: true`
    used to be read as one step and validate cleanly."""
    with pytest.raises(ValueError):
        validate_params(_params(steps=True))
