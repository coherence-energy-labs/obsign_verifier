"""One place that answers "where is the Rust verifier, and is it current?".

Four test files grew their own copy of this. They did not stay the same:

  * one omitted the `.exe` suffix, so `exe.exists()` was False after a PERFECTLY
    SUCCESSFUL build and the column reported "rust binary is not built" -- a skip that
    reads like a pass in every summary line -- on the platform the CI matrix declares;
  * two never build, so a binary predating the source they are meant to be testing
    passes silently. A test that consumes an artifact it does not build is dated by
    whoever last ran cargo, not by the commit under test;
  * one has no `OBSIGN_REQUIRE=rust` escape at all, so the leg cannot be made
    mandatory even when a runner is configured to demand it.

`rust_binary()` builds, and raises with the compiler's output when the build fails.
`rust_binary_or_skip()` is for legs that are genuinely optional -- and it still refuses
to skip when OBSIGN_REQUIRE names rust, because a skip is not a pass.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

RUST = Path(__file__).resolve().parent.parent / "rust"

#: `.exe` on Windows. Not naming it is not a cosmetic slip -- see the module docstring.
RUST_BIN = "obsign-verify-rs" + (".exe" if sys.platform == "win32" else "")

REQUIRED = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}

_BUILT: list[Path] = []


def rust_binary() -> Path:
    """Build (once per process) and return the release binary. Raises if it fails."""
    if _BUILT:
        return _BUILT[0]
    exe = RUST / "target" / "release" / RUST_BIN
    build = subprocess.run(["cargo", "build", "--release", "--offline"], cwd=RUST,
                           capture_output=True, text=True, encoding="utf-8",
                           timeout=1800, check=False)
    if not exe.exists():
        raise AssertionError(f"cargo build failed:\n{build.stdout}\n{build.stderr}")
    _BUILT.append(exe)
    return exe


def rust_binary_or_skip() -> Path:
    """As `rust_binary`, but skip when Rust is absent AND not required.

    The order matters: OBSIGN_REQUIRE=rust turns every reason to skip into a failure,
    including "cargo is not installed", so a runner that believes it is exercising the
    Rust leg finds out when it is not.
    """
    required = "rust" in REQUIRED
    if shutil.which("cargo") is None:
        if required:
            raise AssertionError("OBSIGN_REQUIRE=rust was set but cargo is not installed")
        exe = RUST / "target" / "release" / RUST_BIN
        if exe.is_file():
            return exe
        pytest.skip("cargo not installed and no prebuilt binary "
                    "(set OBSIGN_REQUIRE=rust to make this leg mandatory)")
    try:
        return rust_binary()
    except AssertionError:
        if required:
            raise
        pytest.skip("cargo build failed (set OBSIGN_REQUIRE=rust to make this fatal)")
