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
import math
import sys


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


# Verifier-side admissibility bounds on tau_field_fixed parameters. A receipt is a
# file an adversary hands you, and it must be bounded in two independent ways.
#
# THE WORK BOUNDS -- grid, steps, sources, grid*grid*steps. Without them the kernel
# will happily try to allocate 149 GiB (grid 100000) or loop for 28 hours
# (steps 1e9): a denial of service delivered through the file you were invited to
# check. Mirrors the replay VM's MAX_MEM / MAX_STEPS philosophy: bound each
# dimension, and the product.
#
# THE VALUE BOUNDS -- frac_bits, source tuples, coefficients. Bounding the work says
# nothing about the numbers, and int64 overflow is not an error in any substrate
# this kernel claims to be identical on: numpy wraps silently, `rustc -O` wraps
# silently, a debug-profile Rust build has overflow-checks on and PANICS, and C++
# signed overflow is undefined behaviour the optimiser may assume away. Three of
# those four are a wrong answer with no diagnostic and the fourth is a crash, so an
# overflowing receipt has no single correct output to be identical about -- which is
# precisely what fixed-point mode exists to guarantee. A verifier that re-executes
# such a receipt is not checking it, it is guessing along with it.
#
# EVERY CONSTANT HERE MUST EQUAL THE PRODUCER'S (obsign.fixedpoint). A verifier that
# admits a receipt the producer would never mint, or refuses one it would, has
# already diverged from it -- the disagreement just surfaces as "mints here, refused
# there" instead of as a hash mismatch. The producer's
# tests/test_fixedpoint_numeric_envelope.py runs both validators over one corpus and
# fails if a single verdict differs.
#
# Bounds only ever refuse. None of them changes a value, so a receipt inside the
# envelope verifies exactly as it did before, and one outside it is simply not
# checkable here -- which is honest. A producer who needs more must split the
# computation.
MIN_GRID = 2
MAX_GRID = 4096
MAX_TAU_STEPS = 1_000_000
MAX_SOURCES = 1 << 16
MAX_CELL_STEPS = 1 << 30   # grid*grid*steps: ~1.07e9 cell-updates, seconds of work

INT64_MAX = (1 << 63) - 1
INT64_MIN = -(1 << 63)

# frac_bits <= 57 because the clamps scale with it: hi = round(10.0 * 2**frac_bits),
# and the laplacian materialises `up+dn+lf+rt` and `4*t` as int64 temporaries, each
# bounded by 4*hi. At frac_bits 58 that is 1.15e19 > INT64_MAX. The margin is not
# theoretical: at frac_bits 60 the three substrates whose agreement is this kernel's
# entire claim returned three different things for one receipt -- numpy
# 1152921504606846976, torch a RuntimeError out of clamp, and the producer's Rust
# FFI -6917529027641081856, the wrapped clamp. Was 60, which admitted all of that.
MAX_FRAC_BITS = 57

# A source width is a divisor and an exponent denominator, so it must be strictly
# positive AND normal:
#   width == 0 -> at a centre landing exactly on a grid node the exponent is
#                 0/0 = NaN, and np.round(NaN).astype(int64) is a PLATFORM-DEPENDENT
#                 cast (INT64_MIN on x86-64, 0 on aarch64). That is the same defect
#                 MIN_GRID already refuses, reached through a different door.
#   width < 0  -> the exponent's sign flips, exp overflows to +inf, and the cast of
#                 inf is platform-dependent in the same way.
#   subnormal  -> CONSERVATIVE. Under flush-to-zero (a Rust or C++ build with
#                 fast-math, and some ARM NEON configurations) a subnormal divisor
#                 is treated as 0, so the coincident-node exponent is 0/0 = NaN on
#                 those machines and a finite 0 on an IEEE-strict one. Not observed
#                 on the platforms tested; refused because it cannot be ruled out,
#                 and no legitimate source term needs a width below 1e-308.
MIN_SOURCE_WIDTH = sys.float_info.min          # 2.2250738585072014e-308

# CONSERVATIVE. Keeps (coord - x)**2 finite in f64: 1e150**2 = 1e300 < DBL_MAX. An
# infinite squared distance is one subtraction from inf-inf = NaN and the
# platform-dependent cast behind it. The grid itself only spans [0, 1], so this
# refuses nothing a real source term needs; it is stated in terms of the arithmetic
# rather than the geometry so the reason survives a change of domain.
MAX_SOURCE_COORD = 1e150


def _finite(value, name: str) -> float:
    """A non-finite float reaches np.round(...).astype(np.int64), and that cast is
    platform-dependent -- the receipt would verify on one CPU and fail on another.

    Duck-typed rather than isinstance-checked against numpy's scalar types, so this
    stays true to the module's rule that nothing imports numpy until a tau receipt
    actually needs it -- and so the producer, which does have numpy in hand, reaches
    the identical verdict. A type one side accepted and the other refused would be a
    divergence in its own right. bool and str are excluded by hand: both survive
    float() and neither is a number a receipt may carry."""
    if isinstance(value, (bool, str, bytes, bytearray)):
        raise ValueError(f"{name} must be a real number, got {value!r}")
    try:
        v = float(value)
    except (TypeError, ValueError, OverflowError) as e:
        raise ValueError(f"{name} must be a real number, got {value!r}") from e
    if not math.isfinite(v):
        raise ValueError(f"{name} must be finite, got {v!r}")
    return v


def _scaled(value: float, scale: int, name: str) -> int:
    """The exact int64 the kernel will hold for a float coefficient. Computed here
    and handed back so build_fixed_inputs uses the value that was CHECKED -- a
    validator that recomputes what it validated is not a bound."""
    product = value * scale
    if not math.isfinite(product):
        raise ValueError(f"{name} {value!r} * 2**frac_bits overflows f64")
    scaled = int(round(product))
    if not (INT64_MIN <= scaled <= INT64_MAX):
        raise ValueError(f"{name} {value!r} scales to {scaled}, outside int64 "
                         f"[{INT64_MIN}, {INT64_MAX}]")
    return scaled


def _exact_int(params, key, default=None):
    """Read an integer field that must ALREADY be an integer.

    `int(p["grid"])` REPAIRS its input: 3.9 becomes 3, "3" becomes 3, and True
    becomes 1 because bool subclasses int in Python. A verifier interprets bytes;
    it does not repair them. Canonical JSON writes `3` and `3.0` differently and
    they hash differently, so a float here is a real wire distinction -- silently
    reading both as the same computation is how one implementation's "verified"
    quietly stops meaning what another's does. The replay VM already refuses a
    float where an integer is required; this is the fixed-kernel path catching up.
    """
    if key not in params:
        if default is None:
            raise ValueError(f"params are malformed: missing {key!r}")
        return default
    v = params[key]
    # bool first: isinstance(True, int) is True, and `steps: true` is not a count.
    if isinstance(v, bool) or type(v) is not int:
        raise ValueError(
            f"params are malformed: {key!r} must be a JSON integer, got "
            f"{type(v).__name__} ({v!r}) -- a verifier interprets values, it does "
            f"not coerce them")
    return v


def validate_params(p: dict) -> dict:
    """Refuse a tau_field_fixed param block that would exhaust the verifier or leave
    the int64 envelope, BEFORE a single cell is allocated. Raises ValueError with a
    specific reason naming the offending parameter; verify() turns that into a
    refusal note rather than a crash.

    Returns the derived integer constants (the same ones build_fixed_inputs puts in
    its dict) so nothing is validated in one expression and computed in another.

    The value chain below is checked in Python's arbitrary-precision integers, so
    the check itself cannot overflow while looking for overflow. It bounds the WORST
    CASE reachable from the clamp invariant lo <= t <= hi, which the loop restores
    every step; the worst case is not always attained, so the bound is a sound
    over-approximation -- it can refuse a receipt that would not in fact have
    wrapped, and it can never admit one that would.
    """
    if not isinstance(p, dict):
        raise ValueError("params must be an object")
    try:
        n = _exact_int(p, "grid")
        steps = _exact_int(p, "steps")
        frac_bits = _exact_int(p, "frac_bits", 24)
        sources = p["sources"]
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"tau_field_fixed params are malformed: {e}") from e
    if not (MIN_GRID <= n <= MAX_GRID):
        raise ValueError(f"grid {n} outside [{MIN_GRID}, {MAX_GRID}]: refused before "
                         f"allocating (a grid this size is a memory denial of service, "
                         f"and grid<2 is a NaN that casts differently per CPU)")
    if not (0 <= steps <= MAX_TAU_STEPS):
        raise ValueError(f"steps {steps} outside [0, {MAX_TAU_STEPS}]: refused before "
                         f"looping (an unbounded step count is a time denial of service)")
    if not (0 <= frac_bits <= MAX_FRAC_BITS):
        raise ValueError(
            f"frac_bits {frac_bits} outside [0, {MAX_FRAC_BITS}]: above "
            f"{MAX_FRAC_BITS} the clamp 4*round(10.0*2**frac_bits) leaves int64 and "
            f"numpy, torch and the Rust FFI stop agreeing on the same receipt")
    if not isinstance(sources, (list, tuple)) or len(sources) > MAX_SOURCES:
        raise ValueError(f"sources must be a list of at most {MAX_SOURCES} entries")
    if n * n * max(steps, 1) > MAX_CELL_STEPS:
        raise ValueError(f"grid*grid*steps = {n * n * max(steps, 1)} exceeds "
                         f"{MAX_CELL_STEPS}: the total work this receipt asks the "
                         f"verifier to do is bounded, and this is over the bound")

    scale = 1 << frac_bits
    lo, hi = int(round(0.01 * scale)), int(round(10.0 * scale))

    # |lap| <= 4*(hi-lo), and the temporaries that build it -- `up+dn+lf+rt` and
    # `4*t` -- are each <= 4*hi. MAX_FRAC_BITS is DERIVED from this inequality, so
    # the check above already excludes it; kept as an unreachable guard so the
    # constant and the arithmetic that justifies it cannot drift apart silently.
    if 4 * hi > INT64_MAX:                             # pragma: no cover - MAX_FRAC_BITS
        raise ValueError(f"frac_bits {frac_bits}: 4*hi = {4 * hi} exceeds int64")
    lap_max = 4 * (hi - lo)

    total_strength = 0.0
    for i, src in enumerate(sources):
        if not isinstance(src, (list, tuple)) or len(src) != 4:
            raise ValueError(f"source[{i}] must be a 4-tuple "
                             f"(cx, cy, strength, width), got {src!r}")
        cx = _finite(src[0], f"source[{i}].cx")
        cy = _finite(src[1], f"source[{i}].cy")
        strength = _finite(src[2], f"source[{i}].strength")
        width = _finite(src[3], f"source[{i}].width")
        for axis, coord in (("cx", cx), ("cy", cy)):
            if abs(coord) > MAX_SOURCE_COORD:
                raise ValueError(
                    f"source[{i}].{axis} {coord!r} exceeds +-{MAX_SOURCE_COORD:g}: "
                    f"(coord - x)**2 would overflow f64 to inf, and inf-inf is the "
                    f"NaN whose int64 cast differs per CPU")
        if width < MIN_SOURCE_WIDTH:
            raise ValueError(
                f"source[{i}].width {width!r} below {MIN_SOURCE_WIDTH!r}: a width of "
                f"0 makes the exponent 0/0 = NaN at a coincident grid node, a "
                f"negative width overflows exp to +inf, and a subnormal one is "
                f"flushed to zero on machines running FTZ -- all three end in an "
                f"int64 cast that differs per CPU")
        total_strength += abs(strength)

    if not math.isfinite(total_strength):
        raise ValueError("sum of |source strength| overflows f64")
    # |s| <= sum|strength| because exp(-d**2/width) <= 1 for every positive width,
    # so this bounds |S| = |round(s*scale)| from above without building the field.
    s_max = math.ceil(total_strength) * scale + 1
    if s_max > INT64_MAX:
        raise ValueError(
            f"total source strength {total_strength!r} scales to {s_max}, outside "
            f"int64: np.round(...).astype(np.int64) of an out-of-range value is a "
            f"platform-dependent cast, not a number")

    d = _scaled(_finite(p["D"], "D"), scale, "D")
    g = _scaled(_finite(p["gamma"], "gamma"), scale, "gamma")
    dt = _scaled(_finite(p["dt"], "dt"), scale, "dt")

    if abs(d) * lap_max > INT64_MAX:
        raise ValueError(
            f"D {p['D']!r} too large at frac_bits {frac_bits}: |D|*4*(hi-lo) = "
            f"{abs(d) * lap_max} exceeds int64, so D*lap wraps -- silently in numpy "
            f"and in `rustc -O`, as a panic in a debug Rust build. "
            f"|D| must be <= {INT64_MAX // lap_max / scale!r}")
    if abs(g) * hi > INT64_MAX:
        raise ValueError(
            f"gamma {p['gamma']!r} too large at frac_bits {frac_bits}: |gamma|*hi = "
            f"{abs(g) * hi} exceeds int64, so gamma*t wraps once t reaches the top "
            f"clamp. |gamma| must be <= {INT64_MAX // hi / scale!r}")

    # inner = tdiv(D*lap) - tdiv(G*t) + S, each term at its own worst case.
    inner_max = (abs(d) * lap_max) // scale + (abs(g) * hi) // scale + s_max
    if inner_max > INT64_MAX:
        raise ValueError(
            f"D/gamma/strength combination overflows int64 at frac_bits "
            f"{frac_bits}: worst-case |inner| = {inner_max} exceeds int64")
    if abs(dt) * inner_max > INT64_MAX:
        raise ValueError(
            f"dt {p['dt']!r} too large for this D/gamma/strength at frac_bits "
            f"{frac_bits}: |dt|*|inner| = {abs(dt) * inner_max} exceeds int64, so "
            f"dt*inner wraps. |dt| must be <= {INT64_MAX // inner_max / scale!r}")
    if hi + (abs(dt) * inner_max) // scale > INT64_MAX:
        raise ValueError(
            f"dt {p['dt']!r} too large for this D/gamma/strength at frac_bits "
            f"{frac_bits}: the accumulation t + tdiv(dt*inner) exceeds int64")

    return {"n": n, "steps": steps, "SCALE": scale,
            "D": d, "G": g, "DT": dt, "lo": lo, "hi": hi}


def build_fixed_inputs(p: dict) -> dict:
    """Deterministic integer inputs from parameters alone.

    Every substrate consumes this identically. Nothing external is read -- the
    receipt carries everything needed to rebuild the input, which is what makes
    offline verification possible.
    """
    derived = validate_params(p)
    np = _np()
    scale, n = derived["SCALE"], derived["n"]

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

    # The envelope above is derived from the parameters; this reads the field that
    # was actually built. It is the last place a NaN or an inf can be turned into a
    # refusal instead of the platform-dependent cast on the next line, and it costs
    # one pass over an array that line reads anyway.
    if not np.all(np.isfinite(s)):
        raise ValueError(
            "the source field contains a non-finite value despite in-range "
            "parameters; refusing rather than casting it to int64, whose result "
            "for NaN/inf differs per CPU (INT64_MIN on x86-64, 0 on aarch64)")

    return {**derived, "S": np.round(s * scale).astype(np.int64)}


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

    # THREE REUSED BUFFERS, NOT A DOZEN TEMPORARIES.
    #
    # The envelope at the top of this file bounds grid, steps, sources and
    # grid*grid*steps, and says why: "without them the kernel will happily try to
    # allocate 149 GiB". The dimension it never bounds is how many copies of the field
    # are ALIVE AT ONCE -- and at the admitted maximum grid of 4096, one copy is
    # 134 MiB. Written one expression per line, numpy materialises every
    # sub-expression: `up + dn + lf + rt - 4*t` alone is five arrays. A ~200-byte
    # receipt at grid 4096 measured a peak of 1694 MiB -- thirteen live copies -- which
    # is an out-of-memory kill on a modest verification container, delivered through
    # the file the verifier was invited to check.
    #
    # The constants cannot move: kernel.py requires every one of them to equal the
    # producer's, so lowering MAX_GRID would refuse receipts the producer mints. So the
    # FOOTPRINT is what gives. `acc`, `tmp` and `bias_buf` are allocated once and
    # reused, and every operation writes through `out=`.
    #
    # THE ARITHMETIC IS UNCHANGED, operation for operation and in the same order.
    # int64 addition wraps associatively, so accumulating up+dn+lf+rt in place lands on
    # exactly the value numpy's left-to-right expression produced.
    # tests/test_kernel_memory_footprint.py holds the two formulations to bit-for-bit
    # equality across the envelope -- the only reason rewriting a numeric kernel whose
    # whole promise is "the same bytes on every machine" is admissible at all.
    acc = np.empty_like(t)
    tmp = np.empty_like(t)
    bias_buf = np.empty_like(t)
    _63 = np.int64(63)
    _mask = np.int64(scale - 1)
    _frac = np.int64(frac_bits)

    def tdiv_into(a):
        """`tdiv(a)` written into `a`. Same bias-then-arithmetic-shift as above."""
        np.right_shift(a, _63, out=bias_buf)
        np.bitwise_and(bias_buf, _mask, out=bias_buf)
        np.add(a, bias_buf, out=a)
        np.right_shift(a, _frac, out=a)

    for _ in range(steps):
        acc[1:] = t[:-1]; acc[0] = t[0]                  # up
        tmp[:-1] = t[1:]; tmp[-1] = t[-1]                # dn
        np.add(acc, tmp, out=acc)
        tmp[:, 1:] = t[:, :-1]; tmp[:, 0] = t[:, 0]      # lf
        np.add(acc, tmp, out=acc)
        tmp[:, :-1] = t[:, 1:]; tmp[:, -1] = t[:, -1]    # rt
        np.add(acc, tmp, out=acc)

        np.multiply(t, np.int64(4), out=tmp)
        np.subtract(acc, tmp, out=acc)                   # acc == lap

        np.multiply(acc, np.int64(D), out=acc)           # D*lap
        tdiv_into(acc)
        np.multiply(t, np.int64(G), out=tmp)             # G*t
        tdiv_into(tmp)
        np.subtract(acc, tmp, out=acc)
        np.add(acc, S, out=acc)                          # acc == inner

        np.multiply(acc, np.int64(DT), out=acc)
        tdiv_into(acc)
        np.add(t, acc, out=t)
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
