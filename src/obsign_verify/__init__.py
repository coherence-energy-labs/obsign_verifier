"""Verify an Obsign receipt: re-derive the number yourself, offline.

    from obsign_verify import verify, load_receipt
    result = verify(load_receipt(open("receipt.json", encoding="utf-8").read()))

Imports NOTHING from the engine that produced the receipt. That independence is
the point -- if this package imported the producer, "it verifies" would mean "the
producer agrees with itself".
"""

from .canonical import canonical_sha256, claim_of, load_receipt
from .verify import verify

__all__ = ["verify", "load_receipt", "claim_of", "canonical_sha256", "__version__"]
# Kept as a literal rather than read from package metadata so `--version` still answers
# correctly from a source tree nobody installed. That makes it a SECOND copy of the
# version, which is a drift waiting to happen -- so test_version_matches_pyproject holds
# it to the value in pyproject.toml and fails the build if the two ever disagree.
__version__ = "0.3.0"


def data_path(*parts: str):
    """Absolute path to a file shipped INSIDE the package.

    The conformance vectors and the challenge bundles are package data, not repo
    files. A `pip install` has to give a stranger everything the README tells them
    to run -- the first cut shipped neither, so `obsign-verify challenge/...` and
    `pytest` both failed for anyone who installed rather than cloned.
    """
    from pathlib import Path
    return Path(__file__).resolve().parent.joinpath("data", *parts)
