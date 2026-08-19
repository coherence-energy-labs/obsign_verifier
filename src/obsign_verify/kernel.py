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


def _np():
    """numpy, imported on first use rather than at module import.

    Only tau_field_fixed needs numpy; a replay receipt (obsign/replay/1) is pure
    int64 and never touches it -- and replay is the common path a stranger runs.
    Importing numpy eagerly charged EVERY verification ~50 ms of array-library
    start-up, most of them for a receipt that never calls a single numpy function.
    numpy is cached in sys.modules after the first import, so the second call is a
    dict lookup; each kernel function binds the result once as a local, so the hot
    evolve() loop pays nothing per iteration. Semantics are unchanged: where numpy
    is present (every honest tau receipt) this returns the identical module."""
    try:
        import numpy as np
    except ImportError:                                      # pragma: no cover
        raise SystemExit("numpy is required for tau_field_fixed: pip install numpy")
    return np


# Verifier-side safety bounds on tau_field_fixed parameters. A receipt is a file an
# adversary hands you; without these, `grid` and `steps` are unbounded and the
# kernel will happily try to allocate 149 GiB (grid 100000) or loop for 28 hours
# (steps 1e9) -- a denial of service delivered through the file you were invited to
# check. These bound the WORK a receipt can make a verifier do; they only ever
# refuse, never change a hash, so a receipt within them verifies identically on
# every substrate and one outside them is simply not checkable here (which is
# honest). A producer who needs more must split the computation. Mirrors the
# replay VM's MAX_MEM / MAX_STEPS philosophy: bound each dimension, and the product.
MIN_GRID = 2
MAX_GRID = 4096
MAX_TAU_STEPS = 1_000_000
MAX_SOURCES = 1 << 16
MAX_FRAC_BITS = 60
MAX_CELL_STEPS = 1 << 30   # grid*grid*steps: ~1.07e9 cell-updates, seconds of work


def validate_params(p: dict) -> None:
    """Refuse a tau_field_fixed param block that would exhaust the verifier, BEFORE
    a single cell is allocated. Raises ValueError with a specific reason; verify()
    turns that into a refusal note rather than a crash."""
    if not isinstance(p, dict):
        raise ValueError("params must be an object")
    try:
        n = int(p["grid"])
        steps = int(p["steps"])
        frac_bits = int(p.get("frac_bits", 24))
        sources = p["sources"]
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"tau_field_fixed params are malformed: {e}")
    if not (MIN_GRID <= n <= MAX_GRID):
        raise ValueError(f"grid {n} outside [{MIN_GRID}, {MAX_GRID}]: refused before "
                         f"allocating (a grid this size is a memory denial of service, "
                         f"and grid<2 is a NaN that casts differently per CPU)")
    if not (0 <= steps <= MAX_TAU_STEPS):
        raise ValueError(f"steps {steps} outside [0, {MAX_TAU_STEPS}]: refused before "
                         f"looping (an unbounded step count is a time denial of service)")
    if not (0 <= frac_bits <= MAX_FRAC_BITS):
        raise ValueError(f"frac_bits {frac_bits} outside [0, {MAX_FRAC_BITS}]")
    if not isinstance(sources, (list, tuple)) or len(sources) > MAX_SOURCES:
        raise ValueError(f"sources must be a list of at most {MAX_SOURCES} entries")
    if n * n * max(steps, 1) > MAX_CELL_STEPS:
        raise ValueError(f"grid*grid*steps = {n * n * max(steps, 1)} exceeds "
                         f"{MAX_CELL_STEPS}: the total work this receipt asks the "
                         f"verifier to do is bounded, and this is over the bound")


def build_fixed_inputs(p: dict) -> dict:
    """Deterministic integer inputs from parameters alone.

    Every substrate consumes this identically. Nothing external is read -- the
    receipt carries everything needed to rebuild the input, which is what makes
    offline verification possible.
    """
    validate_params(p)
    np = _np()
    frac_bits = int(p.get("frac_bits", 24))
    scale = 1 << frac_bits
    n = int(p["grid"])

    # grid >= 2 is guaranteed by validate_params. It matters for correctness, not
    # just size: at n == 1 the coordinate grid is 0/(n-1) = 0/0 = NaN, and
    # np.round(NaN).astype(int64) is a PLATFORM-DEPENDENT cast -- INT64_MIN on
    # x86-64, 0 on aarch64. A receipt built at grid 1 would verify on one CPU and
    # refuse on another, inside a kernel whose entire promise is that int64 is
    # identical on every machine. So it is refused, not silently cast.
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

    `tdiv` truncates toward ZERO, not floor. On negative values the two differ.
    """
    np = _np()
    scale = inp["SCALE"]
    frac_bits = int(scale).bit_length() - 1   # scale is 2**frac_bits, exactly
    n, steps = inp["n"], inp["steps"]
    D, G, DT, lo, hi = inp["D"], inp["G"], inp["DT"], inp["lo"], inp["hi"]
    S = inp["S"].astype(np.int64)
    t = np.full((n, n), scale, dtype=np.int64)

    def tdiv(a):
        # Truncate toward ZERO by scale = 2**frac_bits, WITHOUT np.abs.
        #
        # The old form was `np.sign(a) * (np.abs(a) // scale)`, and np.abs(INT64_MIN)
        # OVERFLOWS to INT64_MIN (it has no positive int64), so the sign came out
        # wrong at exactly that one input: tdiv(INT64_MIN) returned +549755813888
        # instead of -549755813888. A correct native port (Rust `/`, which truncates
        # toward zero and does not overflow there) already disagreed with this -- so
        # numpy was the substrate breaking the "int64 is identical on every machine"
        # promise, not upholding it.
        #
        # A bare arithmetic shift `a >> frac_bits` is FLOOR division, which the
        # author rightly avoided for negatives. The fix is to bias negatives up by
        # (scale - 1) first: then the floor-shift lands on the toward-zero result.
        # `(a >> 63)` is all-ones (-1) for negative a and 0 otherwise, so the bias is
        # (scale - 1) exactly when a < 0. `a + bias` cannot overflow -- for a >= 0 the
        # bias is 0, and for a < 0 the sum is < scale-1 < 2**62 and > a. Verified
        # bit-identical to true truncation over every frac_bits and every int64 edge,
        # and identical to the old form everywhere EXCEPT INT64_MIN.
        bias = (a >> np.int64(63)) & np.int64(scale - 1)
        return (a + bias) >> np.int64(frac_bits)

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
    return hashlib.sha256(_np().ascontiguousarray(a).tobytes()).hexdigest()


#: Kernels this verifier can re-execute. Anything else is UNVERIFIED by
#: re-derivation -- reported as such, never quietly treated as a pass.
SUPPORTED_KERNELS = ("tau_field_fixed",)
