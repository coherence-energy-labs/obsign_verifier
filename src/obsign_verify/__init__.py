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
__version__ = "0.1.0"
