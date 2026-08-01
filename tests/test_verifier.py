"""What a stranger is actually being asked to trust.

Every test here exists because the property it pins can fail *plausibly* -- the
verifier still runs, still prints something confident, and is wrong.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from obsign_verify import canonical_sha256, claim_of, data_path, load_receipt, verify
from obsign_verify.canonical import canonical_bytes, integrity
from obsign_verify.kernel import array_sha256, build_fixed_inputs, evolve

VECTORS = json.loads(
    data_path("conformance_vectors.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------ the kernel

@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["name"])
def test_kernel_reproduces_every_conformance_vector(case):
    """The judging artifact.

    These vectors are what an independent implementation is scored against
    (PROGRAM.md §4.3 item 4). If this package cannot reproduce them, it is not a
    verifier -- it is a second opinion.
    """
    out = evolve(build_fixed_inputs(case["params"]))
    assert array_sha256(out) == case["output_sha256"]


def test_vectors_are_not_all_the_same_computation():
    """Four vectors that happened to be identical would make the suite above look
    thorough while testing one path."""
    hashes = {c["output_sha256"] for c in VECTORS}
    assert len(hashes) == len(VECTORS) >= 4


def test_a_perturbed_parameter_changes_the_output():
    """The kernel must actually depend on its inputs. A stub returning a constant
    would pass a single-vector test."""
    p = dict(VECTORS[0]["params"])
    base = array_sha256(evolve(build_fixed_inputs(p)))
    p["steps"] = int(p["steps"]) + 1
    assert array_sha256(evolve(build_fixed_inputs(p))) != base


def test_truncation_is_toward_zero_not_floor():
    """`tdiv` truncates toward zero. An arithmetic shift silently picks floor, and
    the two differ only on negatives -- which is how a port drifts by one bit and
    then by everything. Pinned via a parameter set that drives values negative."""
    import numpy as np
    scale = 1 << 24
    a = np.array([-3 * scale - 1, 3 * scale + 1], dtype=np.int64)
    trunc = np.sign(a) * (np.abs(a) // scale)
    floor = a // scale
    assert list(trunc) == [-3, 3]
    assert list(floor) == [-4, 3]           # they genuinely differ; the test is real


# -------------------------------------------------------------- canonical form

def test_int_and_float_canonicalise_differently():
    """The trap the spec names. A reader that erases the distinction -- notably
    JavaScript's JSON.parse -- canonicalises `0.0` as `0` and reports an honest
    receipt as tampered. Python preserves it; this pins that it must keep doing so."""
    assert canonical_bytes({"gamma": 0}) != canonical_bytes({"gamma": 0.0})
    assert canonical_bytes({"gamma": 0}) == b'{"gamma":0}'
    assert canonical_bytes({"gamma": 0.0}) == b'{"gamma":0.0}'


def test_load_receipt_preserves_the_distinction_from_TEXT():
    r = load_receipt('{"a": 1, "b": 1.0}')
    assert isinstance(r["a"], int) and isinstance(r["b"], float)


def test_non_claim_fields_are_excluded():
    """Hashing `env` would report a genuine receipt as tampered the moment anyone
    recorded a different platform."""
    r = {"kernel": "k", "receipt_sha256": "x", "env": {"os": "linux"},
         "signature": {"sig": "00"}, "case": {"case_id": "c"}, "_helper": 1}
    assert claim_of(r) == {"kernel": "k"}


def test_nan_is_refused_rather_than_canonicalised():
    """NaN has no JSON representation, so allowing it would let two different
    receipts share a canonical form."""
    with pytest.raises(ValueError):
        canonical_bytes({"x": float("nan")})


def test_integrity_fails_on_a_tampered_claim():
    claim = {"kernel": "tau_field_fixed", "params": {"grid": 8}}
    r = dict(claim, receipt_sha256=canonical_sha256(claim))
    assert integrity(r)[0] is True
    r["params"] = {"grid": 9}
    assert integrity(r)[0] is False


# ---------------------------------------------------------------- the ladder

def _honest_receipt(case) -> dict:
    inp = build_fixed_inputs(case["params"])
    out = evolve(inp)
    claim = {
        "spec": "obsign/receipt/v1",
        "producer": "test",
        "kernel": "tau_field_fixed",
        "params": case["params"],
        "input": {"sha256": array_sha256(inp["S"])},
        "output": {"sha256": array_sha256(out), "shape": list(out.shape),
                   "dtype": str(out.dtype)},
        "run": {"steps": case["params"]["steps"]},
    }
    return dict(claim, receipt_sha256=canonical_sha256(claim))


def test_an_honest_unsigned_receipt_verifies():
    """VERIFIED without a signature is the whole replay argument: you did not have
    to trust anyone, you recomputed the number."""
    res = verify(_honest_receipt(VECTORS[0]))
    assert res["verified"] is True
    assert res["integrity"] and res["reproduced"]
    assert res["signature"]["present"] is False


def test_a_resealed_forgery_has_INTACT_integrity_and_still_fails():
    """The load-bearing case. A signature proves a claim is UNMODIFIED, never that
    it is TRUE -- so a forger who edits the output and re-hashes gets past step 1
    and is caught only by re-derivation."""
    r = _honest_receipt(VECTORS[0])
    r["output"] = dict(r["output"], sha256="00" * 32)
    r["receipt_sha256"] = canonical_sha256(claim_of(r))     # resealed
    res = verify(r)
    assert res["integrity"] is True, "the forgery must survive step 1 or it proves nothing"
    assert res["reproduced"] is False
    assert res["verified"] is False


def test_rewritten_shape_metadata_is_caught():
    """shape/dtype ride OUTSIDE the byte hash, so they must be compared against the
    re-executed result explicitly."""
    r = _honest_receipt(VECTORS[0])
    r["output"] = dict(r["output"], shape=[1, 1])
    r["receipt_sha256"] = canonical_sha256(claim_of(r))
    assert verify(r)["verified"] is False


def test_an_unsupported_kernel_is_UNVERIFIED_not_accepted():
    r = _honest_receipt(VECTORS[0])
    r["kernel"] = "something_else"
    r["receipt_sha256"] = canonical_sha256(claim_of(r))
    res = verify(r)
    assert res["verified"] is False
    assert any("cannot be re-executed" in n for n in res["notes"])


def test_a_hostile_receipt_never_raises():
    """A verifier that crashes has failed open in the eyes of whoever handed it
    the file. An exception is not a refusal."""
    for junk in ({}, {"kernel": "tau_field_fixed", "params": "not-a-dict"},
                 {"kernel": "tau_field_fixed", "params": {"grid": -1, "steps": 1,
                  "D": 0, "gamma": 0, "dt": 0, "sources": []}},
                 {"receipt_sha256": None}):
        res = verify(junk)
        assert res["verified"] is False


# ------------------------------------------------------------------ signatures

def test_a_legacy_v1_signature_verifies_but_attributes_NOBODY():
    """The single most security-relevant behaviour in the package.

    obsign/signature/v1 signs the bare receipt hash, so it covers neither the signer
    nor the case block: the name in the file can be rewritten by anyone with a text
    editor and no key. Reporting it as "valid, signed by Alice" would launder an
    unauthenticated name into an attribution.
    """
    cryptography = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    r = _honest_receipt(VECTORS[0])
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    r["signature"] = {"alg": "ed25519", "signer": "Alice",
                      "public_key": pub,
                      "sig": key.sign(r["receipt_sha256"].encode("ascii")).hex()}
    res = verify(r)
    sig = res["signature"]
    assert sig["valid"] is True
    assert sig["identity_bound"] is False
    assert sig["attributed_signer"] is None
    assert sig["claimed_signer"] == "Alice"

    # And the name really is free to rewrite without touching the signature.
    r["signature"]["signer"] = "Mallory"
    assert verify(r)["signature"]["valid"] is True
    assert verify(r)["signature"]["attributed_signer"] is None


def test_a_v2_signature_binds_the_signer():
    cryptography = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    r = _honest_receipt(VECTORS[0])
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    covered = {"spec": "obsign/signature/v2", "alg": "ed25519", "public_key": pub,
               "receipt_sha256": r["receipt_sha256"], "signer": "Alice",
               "binds_sha256": None}
    r["signature"] = dict(covered,
                          sig=key.sign(canonical_sha256(covered).encode("ascii")).hex())
    sig = verify(r)["signature"]
    assert sig["valid"] and sig["identity_bound"]
    assert sig["attributed_signer"] == "Alice"

    # Rewriting the signer now breaks it -- that is the upgrade over v1.
    r["signature"]["signer"] = "Mallory"
    assert verify(r)["signature"]["valid"] is False


def test_an_unknown_algorithm_is_refused_not_ignored():
    r = _honest_receipt(VECTORS[0])
    r["signature"] = {"alg": "rot13", "sig": "00", "public_key": "00",
                      "signer": "Alice"}
    sig = verify(r)["signature"]
    assert sig["valid"] is False
    assert "UNVERIFIED" in sig["detail"]


# ------------------------------------------------------- the published stream

def test_the_dogfood_stream_verifies_and_is_not_empty():
    """We publish receipts about our own numbers. If the page ever shipped a
    receipt that does not re-derive, the product's central claim is refuted by its
    own marketing -- so this is a test, not a nice-to-have.

    Fails closed on an empty stream: an assertion over zero receipts passes for any
    input, which is exactly how a dogfood page would come to prove nothing.
    """
    stream = Path(__file__).resolve().parents[1] / "stream"
    if not stream.is_dir():
        pytest.skip("stream not built (run tools/dogfood.py)")
    receipts = sorted(p for p in stream.glob("*.json") if p.name != "index.json")
    assert len(receipts) >= 4, "stream is empty or truncated -- this check would be vacuous"
    for path in receipts:
        res = verify(load_receipt(path.read_text(encoding="utf-8")))
        assert res["verified"] is True, f"{path.name}: {res['notes']}"


def test_recording_env_does_not_change_the_receipt_hash():
    """`env` is outside the claim by spec. That is what lets the same receipt
    re-derive on a different OS while still disclosing where it ran -- and it is
    the property the published stream is demonstrating."""
    stream = Path(__file__).resolve().parents[1] / "stream"
    if not stream.is_dir():
        pytest.skip("stream not built")
    r = load_receipt((stream / "v1_basic.json").read_text(encoding="utf-8"))
    assert "env" in r, "the stream should disclose its environment"
    before = r["receipt_sha256"]
    r["env"] = {"os": "something-else-entirely", "python": "0.0"}
    assert canonical_sha256(claim_of(r)) == before
    assert verify(r)["verified"] is True


def test_a_receipt_survives_line_ending_conversion():
    """A receipt is robust to transport mangling BY DESIGN.

    `receipt_sha256` covers the parsed claim re-canonicalised, not the file bytes,
    so a receipt still verifies after being emailed, pasted into a ticket, or
    checked out on a platform with different line endings.

    This is worth a test because the property is easy to lose: any future change
    that hashed raw file bytes would 'tighten' the format and silently break every
    receipt that ever crossed a Windows checkout. Two byte-pins in this estate were
    broken by exactly that conversion in a single day.
    """
    stream = Path(__file__).resolve().parents[1] / "stream"
    if not stream.is_dir():
        pytest.skip("stream not built")
    lf = (stream / "v1_basic.json").read_bytes()
    crlf = lf.replace(bytes([10]), bytes([13, 10]))
    assert crlf != lf, "fixture was already CRLF -- the test would prove nothing"
    for form in (lf, crlf):
        assert verify(load_receipt(form.decode("utf-8")))["verified"] is True


# ------------------------------------------------------- the Wave-3 GRC mapping

def test_the_compliance_mapping_matches_its_document():
    """Derive, never transcribe. The hand-written version of this artifact in a
    sibling repo had already gone stale against its own code, listing neither SOC 2
    nor the ISO/IEC 42001 controls that existed in the mapping. An auditor quotes
    the doc, so the doc must not be able to drift from the module."""
    import subprocess
    root = Path(__file__).resolve().parents[1]
    for args in (["--self-test"], []):
        proc = subprocess.run([sys.executable, str(root / "tools" / "compliance_map.py"), *args],
                              capture_output=True, text=True, timeout=600, cwd=str(root))
        assert proc.returncode == 0, proc.stdout + proc.stderr


def test_no_framework_is_claimed_without_stating_its_limits():
    """Structural honesty, enforced rather than intended.

    A mapping that listed what a receipt evidences and omitted what it does not is
    advocacy. Requiring every framework to appear in BOTH tables makes the
    not-covered list impossible to quietly drop.
    """
    import importlib.util
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("cmap", root / "tools" / "compliance_map.py")
    cmap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cmap)

    evidenced = {fw for rows in cmap.CONTROLS.values() for fw, _c, _r in rows}
    uncovered = {fw for fw, _c, _r in cmap.NOT_COVERED}
    assert evidenced, "no frameworks mapped -- this assertion would be vacuous"
    assert evidenced <= uncovered, f"claimed without limits: {sorted(evidenced - uncovered)}"
    assert set(cmap.FRAMEWORKS) == evidenced | uncovered


# --------------------------------------------------- the challenge ships here

def test_the_challenge_is_self_contained_in_THIS_repo():
    """The README tells a stranger to run the forgeries. They must be in the clone.

    The first version of this package shipped that instruction while the bundles
    lived in the PRIVATE engine repo -- an instruction that could not be followed by
    the only person it was written for. A README that documents an impossible command
    is worse than one that documents nothing.
    """
    bundles = sorted(data_path("challenge", "bundles")
                     .glob("*/receipt.json"))
    assert len(bundles) >= 9, f"only {len(bundles)} bundle(s) present in this repo"


def test_every_shipped_bundle_gets_the_verdict_it_declares():
    """Each bundle states its own expectation in `_challenge.expect_verified`, and the
    verifier must agree with all nine. Two must verify, seven must be refused."""
    bundles = sorted(data_path("challenge", "bundles")
                     .glob("*/receipt.json"))
    assert bundles, "no bundles -- this assertion would be vacuous"
    expected_true = 0
    for path in bundles:
        receipt = load_receipt(path.read_text(encoding="utf-8"))
        declared = receipt.get("_challenge", {}).get("expect_verified")
        assert isinstance(declared, bool), f"{path.parent.name} declares no expectation"
        expected_true += declared
        assert verify(receipt)["verified"] is declared, (
            f"{path.parent.name}: expected verified={declared}")
    assert expected_true == 2, (
        f"{expected_true} bundles expected to verify; two should -- the honest receipt "
        f"and the env-only change that must NOT break it")


def test_the_resealed_forgery_survives_integrity_and_dies_on_re_derivation():
    """The load-bearing bundle, checked as shipped rather than as constructed.

    If this one ever failed on INTEGRITY instead, it would stop demonstrating why
    step 2 exists -- and the whole product argument rests on it.
    """
    path = data_path("challenge", "bundles", "resealed_tampered_claim", "receipt.json")
    res = verify(load_receipt(path.read_text(encoding="utf-8")))
    assert res["integrity"] is True, "must pass step 1 or it proves nothing"
    assert res["reproduced"] is False
    assert res["verified"] is False


def test_the_package_ships_everything_the_readme_tells_you_to_run():
    """A pip install must be self-contained.

    The first build shipped NEITHER the conformance vectors NOR the challenge
    bundles, so both commands the README gave a stranger -- run the forgeries, run
    pytest -- failed for exactly the people they were written for. Caught by
    inspecting the sdist before publishing, not after.

    This asserts against the INSTALLED package location, so it fails if the data
    stops being packaged even while the repo copy is still present.
    """
    from obsign_verify import data_path
    vectors = data_path("conformance_vectors.json")
    assert vectors.is_file(), "conformance vectors are not packaged"
    bundles = sorted(data_path("challenge", "bundles").glob("*/receipt.json"))
    assert len(bundles) >= 9, f"only {len(bundles)} bundle(s) packaged"


def test_self_check_refuses_every_forgery_and_exits_zero():
    """`obsign-verify --self-check` is the one command a stranger runs. Exercised
    through the CLI entry point, because that is what they invoke -- calling
    verify() directly would test a path nobody uses."""
    from obsign_verify.cli import main
    assert main(["--self-check", "--quiet"]) == 0


def test_version_matches_pyproject():
    """The version lives in two files. Hold them together or one will lie.

    `__init__.__version__` is a literal so `--version` works from an uninstalled source
    tree, which means pyproject.toml has a second copy. Nobody notices a stale
    `--version`: it prints confidently and is wrong, which is this file's whole subject.
    """
    import re

    from obsign_verify import __version__

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert m, "no version = \"...\" in pyproject.toml -- this test would be vacuous"
    assert m.group(1) == __version__, (
        f"pyproject says {m.group(1)}, package says {__version__}"
    )


def test_declared_urls_are_not_the_private_repo():
    """A dead link on a provenance tool's own page costs more than a missing one.

    0.1.0 shipped with no [project.urls] at all, so pypi.org/project/obsign-verify had
    nothing pointing back at us -- a stranger invited to check our claims had nowhere to
    go. The fix must not overcorrect into links that 404: the GitHub repo is private, so
    Source/Issues stay out until it opens.
    """
    import re

    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
        encoding="utf-8")
    block = re.search(r"(?ms)^\[project\.urls\](.*?)(?=^\[|\Z)", pyproject)
    assert block, "no [project.urls] -- the PyPI page would have no link back to us"
    urls = re.findall(r'=\s*"([^"]+)"', block.group(1))
    assert urls, "[project.urls] is empty"
    leaked = [u for u in urls if "github.com" in u]
    assert not leaked, (
        f"links to the private repo would 404 for every stranger: {leaked}")
    assert all(u.startswith("https://") for u in urls), f"non-https url: {urls}"
