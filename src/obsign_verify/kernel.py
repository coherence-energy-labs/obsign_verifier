"""The `tau_field_fixed` kernel, reimplemented here so this package stands alone.

WHY IT IS RE-IMPLEMENTED RATHER THAN IMPORTED

If this verifier imported the producer's engine, "it verifies" would mean "the
producer agrees with itself" -- which is not a claim worth making. Independence is
the point: a bug in the engine and a bug here cannot cancel, because they were
written separately against a published spec.

WHY THE RESULT IS THE SAME ON YOUR MACHINE AND OURS

The computation is integer fixed-point. Floating point is non-associative and
vendor-dependent, so the same float kernel on two chips can differ in the last
bits. int64 arithmetic is exact and identical on every machine that has it. The
only float in the whole path builds the initial source term, which is rounded to
int64 before any evolution -- so a last-ulp libm difference is absorbed by the
rounding rather than compounded over the steps.

    Honest residual risk, stated rather than hidden: a source value sitting exactly
    on a .5 rounding boundary could round differently under a different libm. Not
    observed across the platforms tested; not proven impossible.
"""

from __future__ import annotations

import hashlib

try:
    import numpy as np
except ImportError:                                          # pragma: no cover
    raise SystemExit("numpy is required: pip install numpy")


def build_fixed_inputs(p: dict) -> dict:
    """Deterministic integer inputs from parameters alone.

    Every substrate consumes this identically. Nothing external is read -- the
    receipt carries everything needed to rebuild the input, which is what makes
    offline verification possible.
    """
    frac_bits = int(p.get("frac_bits", 24))
    scale = 1 << frac_bits
    n = int(p["grid"])

    ys, xs = np.mgrid[0:n, 0:n] / (n - 1)
    s = np.zeros((n, n), dtype=np.float64)
    for cx, cy, strength, width in p["sources"]:
        s += strength * np.exp(-((xs - cx) ** 2 + (ys - cy) ** 2) / width)

    return {
        "n": n,
        "steps": int(p["steps"]),
        "SCALE": scale,
        "D": int(round(p["D"] * scale)),
        "G": int(round(p["gamma"] * scale)),
        "DT": int(round(p["dt"] * scale)),
        "lo": int(round(0.01 * scale)),
        "hi": int(round(10.0 * scale)),
        "S": np.round(s * scale).astype(np.int64),
    }


def evolve(inp: dict) -> np.ndarray:
    """Screened-diffusion field in pure int64.

    t <- t + DT*( D*laplacian(t) - G*t + S ), every product truncated back down by
    SCALE, Neumann (edge-replicating) boundaries, clipped to [lo, hi].

    `tdiv` truncates toward ZERO, not floor. On negative values the two differ, and
    an arithmetic shift would silently pick floor -- which is how a port drifts from
    the reference by one bit and then by everything.
    """
    scale = inp["SCALE"]
    n, steps = inp["n"], inp["steps"]
    D, G, DT, lo, hi = inp["D"], inp["G"], inp["DT"], inp["lo"], inp["hi"]
    S = inp["S"].astype(np.int64)
    t = np.full((n, n), scale, dtype=np.int64)

    def tdiv(a):
        return np.sign(a) * (np.abs(a) // scale)

    for _ in range(steps):
        up = np.empty_like(t); up[1:] = t[:-1]; up[0] = t[0]
        dn = np.empty_like(t); dn[:-1] = t[1:]; dn[-1] = t[-1]
        lf = np.empty_like(t); lf[:, 1:] = t[:, :-1]; lf[:, 0] = t[:, 0]
        rt = np.empty_like(t); rt[:, :-1] = t[:, 1:]; rt[:, -1] = t[:, -1]

        lap = up + dn + lf + rt - 4 * t
        inner = tdiv(D * lap) - tdiv(G * t) + S
        t = t + tdiv(DT * inner)
        np.clip(t, lo, hi, out=t)

    return np.ascontiguousarray(t)


def array_sha256(a) -> str:
    """SHA-256 over the contiguous bytes of the array, and ONLY those bytes.

    Shape and dtype are deliberately NOT mixed in; the spec records them as separate
    fields of the `output` block. Prefixing them is arguably a stronger binding but
    is not the published format, so it would disagree with every genuine receipt.
    The spec governs a verifier, not the verifier's opinion of the spec.

    Because shape/dtype ride outside this hash, the caller compares them against the
    re-executed result explicitly -- otherwise that metadata could be rewritten while
    the byte hash still agreed.
    """
    return hashlib.sha256(np.ascontiguousarray(a).tobytes()).hexdigest()


#: Kernels this verifier can re-execute. Anything else is UNVERIFIED by
#: re-derivation -- reported as such, never quietly treated as a pass.
SUPPORTED_KERNELS = ("tau_field_fixed",)
