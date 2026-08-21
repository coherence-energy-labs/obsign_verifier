"""`tau_field_fixed` bounds every dimension it names -- except the one it allocates.

kernel.py's envelope is explicit about why the work bounds exist:

    THE WORK BOUNDS -- grid, steps, sources, grid*grid*steps. Without them the
    kernel will happily try to allocate 149 GiB (grid 100000) or loop for 28 hours
    (steps 1e9): a denial of service delivered through the file you were invited to
    check. Mirrors the replay VM's MAX_MEM / MAX_STEPS philosophy: bound each
    dimension, and the product.

The dimension the envelope does NOT bound is the number of int64 arrays alive at
once. At the admitted maximum `grid` of 4096 one array is 4096*4096*8 = 134 MiB, and
`evolve` materialised about a dozen of them per step -- four shifted copies, the
laplacian, `4*t`, the products, and a fresh `t` each iteration, all as separate numpy
temporaries. Measured before the fix, on a ~200-byte receipt at grid 4096 / steps 4
(one SIXTEENTH of the admitted grid*grid*steps budget):

    peak RSS 1694 MiB

which is an out-of-memory kill on any modest verification container, delivered
through the file. The constants themselves cannot move -- kernel.py requires every
one of them to equal the producer's, so lowering MAX_GRID would refuse receipts the
producer mints -- so the fix is the footprint, not the envelope: reuse three
preallocated buffers instead of allocating a dozen temporaries per step.

The output must not move by one bit, and that is what this file mostly checks: the
independent reference below is the ORIGINAL expression-per-step formulation, kept
here so the comparison is against the old code rather than against the new code's
opinion of itself.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

np = pytest.importorskip("numpy")

from obsign_verify.kernel import MAX_GRID, array_sha256, build_fixed_inputs, evolve

# ------------------------------------------------------------------ peak RSS, portably
#
# `import resource` is POSIX-only, and at MODULE level it does not merely skip this
# file on Windows -- it is an ImportError during collection, which aborts the WHOLE
# pytest run. The 529 tests in this suite were unreachable on the platform the CI
# matrix declares (windows-latest), so every gate here was dark there.
#
# The lazy answer is to skip the memory tests off POSIX. That would make the one gate
# standing between a stranger and a 1.7 GiB allocation delivered through a ~200-byte
# file pass by not running, on the platform most likely to be a desktop. Windows
# reports the same quantity through `GetProcessMemoryInfo`, so the measurement is
# ported rather than dropped, and the skip is reserved for a platform that offers
# NEITHER -- where it is named, and says which call is missing.

def _peak_rss_mib() -> float | None:
    """Peak resident set of THIS process, in MiB, or None if the OS will not say.

    POSIX: `ru_maxrss` (KiB on Linux, bytes on macOS -- both handled).
    Windows: `PROCESS_MEMORY_COUNTERS.PeakWorkingSetSize`, the same "high-water mark
    of physical pages held" quantity, in bytes.
    """
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class _PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD),
                        ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]

        counters = _PMC()
        counters.cb = ctypes.sizeof(_PMC)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        handle = ctypes.WinDLL("kernel32", use_last_error=True).GetCurrentProcess()
        if not psapi.GetProcessMemoryInfo(wintypes.HANDLE(handle),
                                          ctypes.byref(counters), counters.cb):
            return None
        return counters.PeakWorkingSetSize / 1024 / 1024
    try:
        import resource
    except ImportError:                      # neither POSIX nor Windows
        return None
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB, macOS reports bytes. Nothing reports MiB, so pick by size.
    return (peak / 1024 / 1024) if sys.platform == "darwin" else (peak / 1024)


#: The source of the same measurement, to run inside a subprocess. Written out rather
#: than imported so the child needs nothing on its path but the package under test.
_PEAK_SRC = (
    "import sys\n"
    "def peak_mib():\n"
    "    if sys.platform == 'win32':\n"
    "        import ctypes\n"
    "        from ctypes import wintypes\n"
    "        class P(ctypes.Structure):\n"
    "            _fields_ = [('cb', wintypes.DWORD), ('f', wintypes.DWORD)] + [\n"
    "                (n, ctypes.c_size_t) for n in\n"
    "                ('peak', 'ws', 'qppp', 'qpp', 'qpnp', 'qnp', 'pf', 'ppf')]\n"
    "        c = P(); c.cb = ctypes.sizeof(P)\n"
    "        h = ctypes.WinDLL('kernel32').GetCurrentProcess()\n"
    "        ctypes.WinDLL('psapi').GetProcessMemoryInfo(\n"
    "            wintypes.HANDLE(h), ctypes.byref(c), c.cb)\n"
    "        return c.peak / 1024 / 1024\n"
    "    import resource\n"
    "    p = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss\n"
    "    return p / 1024 / 1024 if sys.platform == 'darwin' else p / 1024\n")

_no_peak = pytest.mark.skipif(
    _peak_rss_mib() is None,
    reason="this OS exposes neither getrusage(RUSAGE_SELF).ru_maxrss (POSIX) nor "
           "GetProcessMemoryInfo.PeakWorkingSetSize (Windows), so peak RSS cannot "
           "be measured here -- the bit-exactness tests in this file still run")


def _reference_evolve(inp: dict):
    """The pre-fix `evolve`, verbatim in its allocate-a-temporary-per-operation form.

    Kept as a literal second implementation: a rewrite of a numeric kernel is only
    safe if something that was NOT rewritten agrees with it, bit for bit.
    """
    scale = inp["SCALE"]
    frac_bits = int(scale).bit_length() - 1
    n, steps = inp["n"], inp["steps"]
    D, G, DT, lo, hi = inp["D"], inp["G"], inp["DT"], inp["lo"], inp["hi"]
    S = inp["S"].astype(np.int64)
    t = np.full((n, n), scale, dtype=np.int64)

    def tdiv(a):
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


_PARAMS = [
    # Every one of these is INSIDE the admissibility envelope (validate_params accepts
    # it): a bit-exactness test on a refused receipt would prove nothing.
    {"grid": 8, "steps": 5, "frac_bits": 24, "sources": [[0.5, 0.5, 1.0, 0.2]],
     "D": 0.1, "gamma": 0.1, "dt": 0.1},
    {"grid": 2, "steps": 0, "frac_bits": 0, "sources": [], "D": 0.0,
     "gamma": 0.0, "dt": 0.0},
    {"grid": 3, "steps": 4, "frac_bits": 16, "sources": [[0.0, 0.0, 1.0, 1.0]],
     "D": 0.05, "gamma": 0.05, "dt": 0.05},
    {"grid": 17, "steps": 13, "frac_bits": 20,
     "sources": [[0.1, 0.9, -3.5, 0.05], [0.9, 0.1, 2.25, 0.5]],
     "D": 0.9, "gamma": 0.75, "dt": 0.5},
    # frac_bits 1 with a NEGATIVE dt and a subnormal-adjacent width: the tdiv bias is
    # scale-1 == 1 here, which is where a floor/truncate confusion would show.
    {"grid": 5, "steps": 7, "frac_bits": 1, "sources": [[0.5, 0.5, -1.0, 1e-300]],
     "D": -0.5, "gamma": -0.25, "dt": 1.0},
    {"grid": 33, "steps": 3, "frac_bits": 12, "sources": [[0.25, 0.75, 1e6, 0.01]],
     "D": 0.2, "gamma": 0.0, "dt": 0.125},
    {"grid": 6, "steps": 9, "frac_bits": 30, "sources": [[0.3, 0.3, 2.0, 0.15]],
     "D": 0.004, "gamma": 0.004, "dt": 0.004},
]


@pytest.mark.parametrize("params", _PARAMS, ids=[f"p{i}" for i in range(len(_PARAMS))])
def test_the_low_footprint_evolve_is_bit_identical(params):
    """Nothing about the number may change: same bytes, same hash, same dtype/shape."""
    inp = build_fixed_inputs(params)
    got = evolve(build_fixed_inputs(params))
    want = _reference_evolve(inp)
    assert got.shape == want.shape and got.dtype == want.dtype
    assert array_sha256(got) == array_sha256(want)
    assert np.array_equal(got, want)


@_no_peak
def test_a_receipt_at_the_admitted_grid_does_not_cost_a_gigabyte():
    """THE EXPLOIT, measured. `grid` 4096 is inside the envelope -- and this is only
    a sixteenth of the admitted grid*grid*steps -- so nothing here is refused; the
    question is only what it costs to accept it."""
    one_array_mib = MAX_GRID * MAX_GRID * 8 / 1024 / 1024
    assert one_array_mib > 100, "precondition: one array at the admitted grid is large"

    code = (
        _PEAK_SRC
        + "import json\n"
        "from obsign_verify.kernel import build_fixed_inputs, evolve\n"
        "p = {'grid': %d, 'steps': 2, 'frac_bits': 24,\n"
        "     'sources': [[0.5, 0.5, 1.0, 0.2]], 'D': 0.1, 'gamma': 0.1, 'dt': 0.1}\n"
        "evolve(build_fixed_inputs(p))\n"
        "print(json.dumps({'mib': peak_mib()}))\n"
        % MAX_GRID)
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, timeout=1800, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr[-2000:]
    import json
    peak = json.loads(proc.stdout.strip().splitlines()[-1])["mib"]

    # Six buffers' worth: t, S, and the three the loop reuses, plus interpreter and
    # numpy overhead. The pre-fix code held about a dozen and measured 1694 MiB.
    budget = 7 * one_array_mib + 250
    assert peak <= budget, (
        f"a ~200-byte receipt at the admitted maximum grid peaked at {peak:.0f} MiB "
        f"(one array is {one_array_mib:.0f} MiB, so that is "
        f"{peak / one_array_mib:.1f} live arrays). The envelope bounds grid, steps, "
        f"sources and their product, and never bounds how many copies of the field "
        f"are alive at once -- so the memory denial of service the bounds exist to "
        f"stop is still reachable inside them.")


@_no_peak
def test_the_peak_is_reported_for_the_record():
    """Not an assertion, a measurement: `pytest -s` prints what a verifier pays."""
    peak_before = _peak_rss_mib()
    inp = build_fixed_inputs({"grid": 512, "steps": 4, "frac_bits": 24,
                              "sources": [[0.5, 0.5, 1.0, 0.2]],
                              "D": 0.1, "gamma": 0.1, "dt": 0.1})
    evolve(inp)
    peak_after = _peak_rss_mib()
    print(f"\ngrid 512: peak RSS {peak_before:.0f} -> {peak_after:.0f} MiB")
