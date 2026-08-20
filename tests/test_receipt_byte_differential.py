"""Four parsers, one question: are these bytes a receipt?

Every implementation in this estate agrees about arithmetic. The defects that have
actually cost something were disagreements about DOCUMENTS -- `1e400`, the 5000-digit
integer, the 2000-level nest, the raw control character -- and each one was decided
inside a parser, before verification ran, on input that never had to be a valid
receipt. `test_wire_format_limits.py` closed those twelve cases by hand. This closes
the space around them by generating the bytes.

Four columns, because four parsers exist and a stranger may reach any of them:

    python   src/obsign_verify/canonical.py       `pip install obsign-verify`
    npm      js/src/canonical.js                  `npm i obsign-verify`
    browser  web/verify/verify-core.js            the public verify page
    rust     rust/                                a third reading, another author

Two of those columns are conditional and neither is required. The browser parser lives
in the producer's repository, so it appears only when `OBSIGN_WEB_VERIFY_CORE` points at
it or the sibling checkout is there. The Rust column appears only when somebody has
already built the crate -- this file never runs a compiler and never fails because a
crate it does not own is mid-edit. An absent column is skipped, never assumed to agree.

Two properties are asserted of every generated document:

  LOADABILITY. Every implementation must answer the same. A receipt one verifier reads
  and another refuses is a receipt a forger hands to whichever one gives the answer
  they want, and "any implementation re-derives the same answer" is the product.

  CANONICAL BYTES. For a document they all load, the canonical string must be
  byte-identical, because those bytes are hashed and that hash is the claim.

WHAT THE CAMPAIGN FOUND

Six live divergences, every one of them a place where JavaScript read bytes the other
implementations would not:

    MAX_STRING_BYTES enforced in Python and nowhere in JavaScript -- declared in
      js/src/canonical.js and never read
    MAX_DEPTH counted one way in Python and another in the npm parser, an off-by-one
      visible only when the innermost container is empty
    an unpaired surrogate escape refused by Python alone, and by accident: a
      UnicodeEncodeError out of a length check, not a rule anybody had written
    a verify page with no wire-format limits table at all -- duplicate members resolved
      last-value-wins, no depth, member, digit, string or size bound
    a verify page that died of stack exhaustion instead of refusing
    a JavaScript decoder that repaired invalid UTF-8, collapsing distinct FILES onto
      one claim hash -- three different files, one receipt_sha256

Rust settled the two that were Python-against-JavaScript: a third reading by another
author agreed with Python on both, which is what turns "two implementations differ"
into "one implementation is the outlier".

All six are closed, and the tolerance list is EMPTY: `_KNOWN` is built only from
vectors still marked `open`, and there are none, so any divergence at all now fails the
campaign. `corpus/receipt_bytes/` holds nine vectors that keep it that way. A settled
vector is marked `agreed` and is NOT deleted -- the bytes that once loaded in one
implementation and not another are the cheapest possible test that they now get one
answer, and each carries a `history` field, which is the only artifact that says WHY
the limit sits where it sits. Delete the vector and you keep the number and lose the
reason.

RUNNING IT LONGER

The default is one seed and a bounded case count, so CI stays fast and deterministic.
`OBSIGN_FUZZ=full` runs the long campaign, including the multi-megabyte vectors;
`OBSIGN_FUZZ_CASES` and `OBSIGN_FUZZ_SEEDS` set the two knobs directly.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import fuzz_receipt_bytes as fuzz
import pytest

from obsign_verify.canonical import canonical_bytes, load_receipt

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
_RUNNER = _HERE / "receipt_bytes_runner.mjs"
_CORPUS = _HERE / "corpus" / "receipt_bytes"

_HAS_NODE = shutil.which("node") is not None
_REQUIRE = {m.strip() for m in os.environ.get("OBSIGN_REQUIRE", "").split(",")}
_FULL = os.environ.get("OBSIGN_FUZZ", "").lower() in ("full", "long", "1", "true")
_CASES = int(os.environ.get("OBSIGN_FUZZ_CASES", "20000" if _FULL else "1200"))
_SEEDS = int(os.environ.get("OBSIGN_FUZZ_SEEDS", "5" if _FULL else "1"))


def _browser_path() -> Path | None:
    """The producer's verify page, if this checkout can see it."""
    env = os.environ.get("OBSIGN_WEB_VERIFY_CORE")
    for cand in ([Path(env)] if env else []) + [
            _REPO.parent / "obsign" / "web" / "verify" / "verify-core.js"]:
        if cand.is_file():
            return cand.resolve()
    return None


_BROWSER = _browser_path()

#: The Rust crate, if somebody has already built it. Deliberately NOT built here: it is
#: a fourth reading of the wire format and a welcome one, but this file must not make
#: `pytest -q` wait on a compiler, and it must not fail because a sibling crate is
#: mid-edit. Present-and-executable or absent; nothing in between.
_RUST = _REPO / "rust" / "target" / "release" / "obsign-verify-rs"
_HAS_RUST = _RUST.is_file() and os.access(_RUST, os.X_OK)


# --------------------------------------------------------------------------- columns

def python_column(text: str) -> dict:
    """What `load_receipt` plus `canonical_bytes` do with this text.

    A ValueError is a REFUSAL -- `WireFormatError` subclasses it, so does
    `JSONDecodeError`, so does the `UnicodeEncodeError` a lone surrogate provokes.
    Anything else is the loader falling over, which the docstring on `integrity`
    forbids in as many words: "a verifier that crashes on malformed input has failed
    open in the eyes of whoever supplied it".
    """
    try:
        obj = load_receipt(text)
    except ValueError as e:
        return {"loads": False, "err": f"{type(e).__name__}: {e}", "fatal": False}
    except Exception as e:                             # noqa: BLE001 - that is the point
        return {"loads": False, "err": f"{type(e).__name__}: {e}", "fatal": True}
    try:
        b = canonical_bytes(obj)
    except Exception as e:                             # noqa: BLE001
        return {"loads": True, "sha": None, "err": f"{type(e).__name__}: {e}",
                "fatal": not isinstance(e, ValueError)}
    return {"loads": True, "sha": hashlib.sha256(b).hexdigest(), "len": len(b),
            "head": b[:120].decode("ascii", "replace")}


def node_columns(cases: list[tuple[str, str]], as_files: bool = False) -> list[dict]:
    """One subprocess for the whole batch. Node startup dwarfs the parsing.

    `as_files` hands Node the PATHS instead of the text, so it decodes the bytes with
    `readFileSync(f, 'utf8')` exactly as `bin/obsign-verify.js` does. That is the only
    honest way to ask what JavaScript makes of bytes Python cannot decode at all.
    """
    fd, name = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    tmp = Path(name)
    key = "file" if as_files else "text"
    try:
        tmp.write_text(json.dumps([{"id": i, key: t} for i, t in cases]),
                       encoding="utf-8")
        argv = ["node", str(_RUNNER), str(tmp)]
        if _BROWSER is not None:
            argv.append(str(_BROWSER))
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=900,
                              check=False)
    finally:
        tmp.unlink(missing_ok=True)
    assert proc.returncode == 0, (proc.stdout[-2000:] + proc.stderr[-2000:])
    return json.loads(proc.stdout)


#: A raw surrogate code point in the TEXT cannot be carried to a Rust `String`, which is
#: UTF-8 by construction. That is a property of the transport, not of the receipt
#: format, so those cases are dropped from the Rust column rather than reported as a
#: disagreement. The lone-surrogate ESCAPE -- the interesting case, corpus 003 -- is
#: pure ASCII in the text and travels fine.
_SURROGATE = tuple(chr(c) for c in range(0xD800, 0xE000))


def rust_columns(cases: list[tuple[str, str]]) -> dict[str, dict]:
    """The Rust crate's answers, through the harness interface it already exposes.

    `rust/` belongs to another author and is read, never written: this drives the
    `--harness load` and `--harness canon` modes that `test_cross_language_differential`
    established, and treats any failure of the binary as "no Rust column" rather than as
    a finding. A fourth reading is worth having and worth not depending on.
    """
    usable = [(i, t) for i, t in cases if not any(c in t for c in _SURROGATE)]
    if not usable:
        return {}
    fd, name = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    tmp = Path(name)
    try:
        tmp.write_text(json.dumps([[i, t] for i, t in usable]), encoding="utf-8")
        got = {}
        for mode in ("load", "canon"):
            proc = subprocess.run([str(_RUST), "--harness", mode, str(tmp)],
                                  capture_output=True, text=True, timeout=900,
                                  check=False)
            if proc.returncode != 0:
                return {}
            got[mode] = json.loads(proc.stdout.strip().splitlines()[-1])
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    finally:
        tmp.unlink(missing_ok=True)
    out = {}
    for cid, _t in usable:
        canon = got["canon"].get(cid)
        out[cid] = {"loads": bool(got["load"].get(cid)),
                    "sha": None if canon is None
                    else hashlib.sha256(canon.encode("utf-8")).hexdigest()}
    return out


# ------------------------------------------------------------------------ signatures
#
# A divergence is named by WHO split and WHY, never by the document that exposed it --
# a thousand mutations of one defect must collapse to one name or the corpus becomes a
# list of duplicates and stops meaning anything.

_REASONS: tuple[tuple[str, str], ...] = (
    ("duplicate object member", "duplicate-member"),
    ("nesting deeper than", "depth"),
    ("nesting is too deep", "depth"),
    ("members", "member-count"),
    ("digits", "int-digits"),
    ("string longer than", "string-bytes"),
    ("key longer than", "string-bytes"),
    ("larger than", "receipt-bytes"),
    ("array of", "array-length"),
    ("array longer than", "array-length"),
    ("surrogates not allowed", "lone-surrogate"),
)


def reason(err: str | None) -> str:
    for needle, tag in _REASONS:
        if needle in (err or ""):
            return tag
    return "syntax"


def signature(cols: dict) -> str | None:
    """`None` when the implementations agree; otherwise a stable divergence name.

    When the two SHIPPED parsers disagree the refusing side's reason is part of the
    name, because that reason is the defect. When they agree and only the browser
    differs, the reason is noise -- the browser applies no wire-format limit at all,
    so every such split is the same single defect wearing a different hat.
    """
    keys = [k for k in ("python", "npm", "browser") if k in cols]
    loads = {k: cols[k]["loads"] for k in keys}
    if len(set(loads.values())) == 1:
        if all(loads.values()) and len({cols[k].get("sha") for k in keys}) > 1:
            return "canonical-bytes " + " ".join(
                f"{k}={str(cols[k].get('sha'))[:12]}" for k in keys)
        return None
    if loads["python"] != loads["npm"]:
        odd = "python" if not loads["python"] else "npm"
        return f"{odd}=refuse [{reason(cols[odd].get('err'))}]"
    side = "load" if loads["browser"] else "refuse"
    others = "refuse" if not loads["python"] else "load"
    return f"browser={side} while both shipped parsers {others}"


# ---------------------------------------------------------------------------- corpus

def corpus_entries() -> list[dict]:
    """Every frozen divergence, with the bytes that produced it."""
    out = []
    for p in sorted(_CORPUS.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        d["path"] = p
        out.append(d)
    return out


def corpus_text(entry: dict) -> str:
    """The vector's receipt text.

    Payloads are JSON-escaped, base64, or a repeat spec -- never raw -- so that not one
    byte-pinned vector contains a literal CR or LF. `.gitattributes` protects
    `stream/**` and `src/obsign_verify/data/**` with `-text`; it does not know about
    `tests/corpus`, and this estate has twice had a byte-pin silently converted on a
    Windows checkout. A vector that cannot survive its own repository is not a vector.

    `text_repeat` also keeps a 65537-byte string and a 20,000-level nest to a line
    each: the bytes are exactly determined by four fields, and the diff stays readable.
    """
    if "bytes_base64" in entry:
        return base64.b64decode(entry["bytes_base64"]).decode("utf-8")
    if "text_repeat" in entry:
        r = entry["text_repeat"]
        body = r["unit"] * r["count"] + r.get("middle", "")
        if "after_unit" in r:
            body += r["after_unit"] * r["count"]
        return r["before"] + body + r["after"]
    return entry["text"]


#: Divergence signatures the campaign tolerates -- from vectors still marked OPEN, and
#: only those. A settled vector keeps its historical signature so the record stays
#: readable, and it must NOT keep granting tolerance: if the MAX_STRING_BYTES split
#: came back tomorrow, a `_KNOWN` built from every entry would wave it through in
#: silence, and the corpus would have turned from a ratchet into a permission slip.
_KNOWN = {e["signature"] for e in corpus_entries() if e.get("status") == "open"}


# ----------------------------------------------------------------------- the fuzzers

def test_the_generators_are_not_vacuous():
    """A fuzzer that emits nothing interesting passes every differential ever written.

    Assert the COUNT and the CONTENT, not that a list is non-empty -- the same lesson
    the CRLF gate in verify.yml learned by silently checking 5 files of 14.
    """
    vectors = fuzz.targeted_vectors()
    assert len(vectors) >= 200, f"only {len(vectors)} targeted vectors"
    ids = [name for name, _ in vectors]
    assert len(set(ids)) == len(ids), (
        "two targeted vectors share an id, so the differential would compare one "
        "implementation's answer about one document with another's about a different "
        "one: " + ", ".join(sorted({i for i in ids if ids.count(i) > 1}))[:200])
    for must in ("dup-top", "depth-obj-leaf-33", "int-digits-4301",
                 "string-bytes-65537", "num::1e400", "num::NaN", "bom-then-object"):
        assert must in set(ids), f"the targeted set lost {must!r}"
    seeds = fuzz.seed_texts()
    assert len(seeds) >= 10, f"only {len(seeds)} seed receipts -- mutation has no target"
    generated = list(fuzz.campaign(0, 200))
    assert len({t for _, t in generated}) >= 190, "the generator repeats itself"
    assert sum(1 for _, t in generated if len(t) > 200) >= 50, \
        "every generated case is tiny -- structure is not being exercised"


def test_python_never_crashes_on_any_generated_document():
    """Python-only, so it runs everywhere including a runner with no node.

    `load_receipt` may refuse anything. It may not raise RecursionError, KeyError or
    TypeError: `cli.py` catches ValueError around it, and an exception outside that set
    reaches a stranger as a traceback from the tool they were told to trust.
    """
    crashed = []
    for cid, text in fuzz.targeted_vectors() + list(fuzz.campaign(0, _CASES)):
        col = python_column(text)
        if col.get("fatal"):
            crashed.append((cid, col["err"], text[:120]))
    assert not crashed, ("load_receipt raised something that is not a refusal:\n  "
                         + "\n  ".join(map(str, crashed[:10])))


# -------------------------------------------------------------- the differential

def _run_campaign(seed: int, count: int) -> tuple[int, int, list, list]:
    """Returns (checked, mutually loaded, unexpected divergences, crash reports)."""
    cases = (fuzz.targeted_vectors(include_huge=_FULL) if seed == 0 else []) \
        + list(fuzz.campaign(seed, count))
    checked = loaded = 0
    bad: list[str] = []
    crashes: list[str] = []
    for off in range(0, len(cases), 400):          # bounded transport per subprocess
        chunk = cases[off:off + 400]
        for (cid, text), row in zip(chunk, node_columns(chunk)):
            assert row["id"] == cid
            cols = {"python": python_column(text), "npm": row["npm"]}
            if "browser" in row:
                cols["browser"] = row["browser"]
            checked += 1
            for who, col in cols.items():
                if col.get("fatal"):
                    crashes.append(f"[{cid}] {who} CRASHED: {col.get('err')} "
                                   f"on {text[:90]!r}")
            sig = signature(cols)
            if sig is None:
                loaded += cols["python"]["loads"]
            elif sig not in _KNOWN:
                bad.append(f"[{cid}] {sig}\n      text={text[:160]!r}\n      "
                           + "\n      ".join(f"{k}: {json.dumps(v)[:200]}"
                                             for k, v in cols.items()))
    return checked, loaded, bad, crashes


@pytest.mark.skipif(not _HAS_NODE and "node" not in _REQUIRE, reason="node not installed")
@pytest.mark.parametrize("seed", range(_SEEDS))
def test_the_parsers_agree_on_every_generated_document(seed):
    """The campaign. A divergence not already frozen in the corpus fails here."""
    assert _HAS_NODE, "OBSIGN_REQUIRE=node was set but node is not installed"
    checked, loaded, bad, crashes = _run_campaign(seed, _CASES)
    assert checked > 500, f"only {checked} documents reached the parsers"
    assert loaded > 50, (f"only {loaded} documents loaded in all implementations -- "
                         f"agreement on refusal alone proves very little")
    assert not crashes, ("a parser crashed rather than refusing:\n  "
                         + "\n  ".join(crashes[:10]))
    assert not bad, (
        f"{len(bad)} NEW divergence(s) -- these bytes mean different things to "
        f"different verifiers, and nothing in corpus/receipt_bytes/ describes them:\n  "
        + "\n  ".join(bad[:6]))
    # Printed rather than asserted: the SIZE of a campaign is the thing a reader wants
    # and the thing a summary line hides. `pytest -s` shows it.
    print(f"[receipt-bytes seed={seed}] {checked} documents through "
          f"{'3' if _BROWSER else '2'} parsers, {loaded} loaded everywhere and "
          f"canonicalised identically")


@pytest.mark.skipif(not _HAS_RUST and "rust" not in _REQUIRE,
                    reason="rust/target/release/obsign-verify-rs is not built")
@pytest.mark.parametrize("seed", range(_SEEDS))
def test_the_rust_reading_answers_what_python_answers(seed):
    """A fourth reading of the wire format, and the tie-breaker on two open defects.

    `rust/` is a third implementation written from the spec by another author, so it is
    an independent vote on every question the other three disagree about -- and on the
    two Python/npm splits it votes with Python. It refuses the 65537-byte string that
    JavaScript loads (corpus 001) and it loads the 33-container nest that the npm
    parser refuses (corpus 002), which is what turns "two implementations differ" into
    "one implementation is the outlier".

    It is not built here and not required. Whoever has already run `cargo build
    --release` gets the column; everyone else gets a skip.
    """
    cases = (fuzz.targeted_vectors() if seed == 0 else []) \
        + list(fuzz.campaign(seed, _CASES))
    checked = agreed = 0
    bad: list[str] = []
    for off in range(0, len(cases), 400):
        chunk = cases[off:off + 400]
        rust = rust_columns(chunk)
        if not rust:
            if "rust" in _REQUIRE:
                raise AssertionError("OBSIGN_REQUIRE=rust was set but the rust "
                                     "harness produced nothing -- a skip reads "
                                     "like a pass in every summary line")
            pytest.skip("the rust harness produced nothing -- treated as absent")
        for cid, text in chunk:
            if cid not in rust:
                continue                      # a raw surrogate, see _SURROGATE
            py, rs = python_column(text), rust[cid]
            checked += 1
            if py["loads"] != rs["loads"]:
                bad.append(f"[{cid}] python={'loads' if py['loads'] else 'refuses'} "
                           f"rust={'loads' if rs['loads'] else 'refuses'} "
                           f"({py.get('err', '')[:80]}) on {text[:110]!r}")
            elif py["loads"] and py["sha"] != rs["sha"]:
                bad.append(f"[{cid}] both load, canonical bytes differ: "
                           f"python={py['sha'][:16]} rust={str(rs['sha'])[:16]} "
                           f"on {text[:110]!r}")
            elif py["loads"]:
                agreed += 1
    assert checked > 300, f"only {checked} documents reached the rust binary"
    assert not bad, (
        f"{len(bad)} document(s) where the Rust reading and the Python reading "
        f"disagree about the wire format:\n  " + "\n  ".join(bad[:8]))
    print(f"[receipt-bytes-rust seed={seed}] {checked} documents, {agreed} loaded in "
          f"both with identical canonical bytes")


# ------------------------------------------------------------- the frozen divergences
#
# One test per live defect. Each is `xfail(strict=True)`: it documents today's
# behaviour, keeps the suite honest about being broken, and FAILS on the day someone
# repairs it -- at which point the corpus entry has done its job and comes out.

@pytest.mark.skipif(not _HAS_NODE, reason="node not installed")
def test_a_string_past_the_limit_is_refused_by_both_shipped_parsers():
    """MAX_STRING_BYTES is in the limits table of both files. Only one applies it.

    `js/src/canonical.js` defines `const MAX_STRING_BYTES = 65536` beside the four
    limits it does enforce, under a comment promising "the same table as
    src/obsign_verify/canonical.py" -- and no line of the parser ever mentions it
    again. Python's `_check_shape` enforces it on strings AND on object keys, so a
    receipt carrying one long string loads under `npm i obsign-verify` and is refused
    by `pip install obsign-verify`. That is the exact shape of the split the table was
    written to close, surviving inside the file that closed it.
    """
    text = '{"a":"' + "x" * 65537 + '"}'
    py = python_column(text)
    js = node_columns([("s", text)])[0]["npm"]
    assert py["loads"] is False, "precondition: Python refuses it"
    assert js["loads"] is False, (
        "the npm parser LOADED a string longer than MAX_STRING_BYTES that Python "
        "refuses -- the limits table is declared in both files and applied in one")


@pytest.mark.skipif(not _HAS_NODE, reason="node not installed")
def test_the_two_parsers_draw_the_depth_limit_in_the_same_place():
    """An off-by-one in a shared limit is still a split.

    `js/src/canonical.js` increments a counter on ENTERING each container and refuses
    above 32, so it admits at most 32 nested containers. Python's `_check_shape` starts
    the top-level object at depth 0 and refuses a VALUE deeper than 32, which admits 33
    containers whenever the innermost one is empty. `{"a":[[...]]}` with 32 arrays is
    the smallest witness: Python reads it, JavaScript does not.

    Which number is right is a spec decision. That they differ is not: both files carry
    the same table under a comment saying the limits are "part of the format".
    """
    text = '{"a":' + "[" * 32 + "]" * 32 + "}"
    py = python_column(text)
    js = node_columns([("d", text)])[0]["npm"]
    assert py["loads"] == js["loads"], (
        f"depth limit diverges: python loads={py['loads']} npm loads={js['loads']} "
        f"on 33 nested containers -- MAX_DEPTH is 32 in both files and means two "
        f"different things")


@pytest.mark.skipif(not _HAS_NODE, reason="node not installed")
def test_an_unpaired_surrogate_escape_gets_one_answer():
    r"""`{"\ud800":1}` is three different documents depending on who opens it.

    Python refuses -- but by accident, and with the wrong error. `_check_shape` calls
    `len(k.encode("utf-8"))` to apply the string-length limit, an unpaired surrogate
    has no UTF-8 encoding, and the resulting `UnicodeEncodeError` is what refuses the
    receipt. Nothing in the wire format says unpaired surrogates are excluded, and
    `canonical_bytes` handles them perfectly well (`ensure_ascii=True` writes them
    back as `\ud800`), so the refusal is a side effect of a length check.

    Both JavaScript parsers accept it and agree byte-for-byte on the canonical form.
    So the document loads in two implementations of three, and the one that refuses
    does so for a reason it did not choose. Either the format excludes unpaired
    surrogates -- in which case say so and refuse deliberately in all three -- or it
    does not, and Python must stop tripping over its own length check.
    """
    text = r'{"\ud800":1}'
    py = python_column(text)
    js = node_columns([("g", text)])[0]["npm"]
    assert py["loads"] == js["loads"], (
        f"python loads={py['loads']} ({py.get('err')}) npm loads={js['loads']}")


@pytest.mark.skipif(_BROWSER is None, reason="the producer's verify-core.js is not here")
def test_the_browser_refuses_a_duplicate_member_like_the_others():
    """The worst of the browser splits, because it is silent and it changes the claim.

    `{"a":1,"a":2}` is refused by Python and by npm, in both cases with a paragraph
    explaining that last-value-wins is a convention rather than a guarantee. The public
    verify page applies the convention: `o[k] = value()` overwrites, the document
    canonicalises to `{"a":2}`, and the page reports an integrity verdict on a
    document the two other verifiers say does not exist.

    That is a forgery primitive, not a nit. Put the value a reader is meant to see
    first and the value the hash covers second, and the page shows one number while
    attesting another -- on the one screen whose entire job is telling a stranger what
    to believe.

    The same file has no MAX_DEPTH, no MAX_MEMBERS_PER_OBJECT, no MAX_INT_DIGITS, no
    MAX_STRING_BYTES and no MAX_RECEIPT_BYTES either; this is the sharpest witness of
    one missing table, and corpus/receipt_bytes/ carries the rest.
    """
    rows = node_columns([("dup", '{"a":1,"a":2}')])[0]
    assert rows["browser"]["loads"] is False, (
        "the browser parser LOADED a document with a duplicate member and "
        f"canonicalised it to {rows['browser'].get('head')!r} -- "
        "silently choosing which of two values the receipt contains")


@pytest.mark.skipif(_BROWSER is None, reason="the producer's verify-core.js is not here")
def test_the_browser_refuses_deep_nesting_instead_of_dying():
    """A crash is not a refusal, and this one is reachable by pasting a file.

    `load_receipt` catches RecursionError from CPython's parser and re-raises it as a
    WireFormatError precisely because "a RecursionError escaping a loader reads as a
    crash rather than a refusal, and a verifier that crashes on hostile input has
    failed open in the eyes of whoever handed it the file". The npm parser reaches its
    depth limit at 33 and never recurses far enough to matter. `parseReceipt` has no
    depth counter at all, so 100,000 open brackets exhaust the V8 stack.

    verify-core.js already learned this once -- "pasting the literal `null` took the
    verify page down" is a comment in the file. This is the same bug with a deeper
    input.
    """
    text = '{"a":' + "[" * 100_000 + "]" * 100_000 + "}"
    row = node_columns([("deep", text)])[0]["browser"]
    assert not row.get("fatal"), (
        f"the browser parser died rather than refusing: {row.get('err')}")


# ------------------------------------------------------------------- the corpus itself

def test_the_corpus_is_present_and_describes_itself():
    """A corpus that lost its files would make the campaign tolerate everything.

    A vector is not deleted when its divergence closes; it is marked `agreed`. The
    bytes that once loaded in one implementation and not another are the cheapest
    possible test that they now get one answer, and the `history` field is the only
    artifact that says WHY the limit sits where it sits. Deleting a settled vector
    throws away the reason and keeps only the number.
    """
    entries = corpus_entries()
    assert len(entries) >= 8, f"only {len(entries)} frozen vector(s)"
    for e in entries:
        assert e.get("note"), f"{e['path'].name} has no prose saying what it proves"
        assert e.get("history"), f"{e['path'].name} does not say what it came from"
        assert e.get("signature"), f"{e['path'].name} has no signature"
        assert e.get("status") in ("agreed", "open"), e["path"].name
        assert e.get("observed") and e.get("expected"), e["path"].name
        assert set(e["observed"]) == set(e["expected"]), (
            f"{e['path'].name}: observed and expected name different implementations")
        assert "text" in e or "bytes_base64" in e or "text_repeat" in e, e["path"].name
        if e["status"] == "agreed":
            assert e["observed"] == e["expected"], (
                f"{e['path'].name} is marked agreed but records a divergence")
        else:
            assert e["observed"] != e["expected"], (
                f"{e['path'].name} is marked open but records agreement")
    assert sum(1 for e in entries if e["status"] == "agreed") >= 6, (
        "almost nothing in this corpus is settled -- either a parser regressed or the "
        "schema drifted")


@pytest.mark.parametrize("entry", corpus_entries(),
                         ids=[e["path"].stem for e in corpus_entries()])
def test_every_frozen_vector_still_behaves_as_recorded(entry):
    """Python's half of each vector, checkable with no node and no sibling checkout.

    If this fails, either the defect moved or someone fixed it. Both are news, and the
    second one means this vector has done its job and comes out of the corpus.
    """
    if entry.get("decode") == "utf-8-strict":
        raw = base64.b64decode(entry["bytes_base64"])
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            assert entry["observed"]["python"] == "refuse-at-decode", entry["path"].name
            return
        assert entry["observed"]["python"] != "refuse-at-decode", entry["path"].name
    else:
        text = corpus_text(entry)
    got = "load" if python_column(text)["loads"] else "refuse"
    assert got == entry["observed"]["python"], (
        f"{entry['path'].name}: Python now says {got}, the vector recorded "
        f"{entry['observed']['python']}. {entry['note']}")


@pytest.mark.skipif(not _HAS_NODE, reason="node not installed")
def test_every_frozen_vector_still_behaves_as_recorded_in_javascript():
    """The other half, and the only half that can see 004-007 at all.

    For a browser-only divergence Python simply refuses, which it would do anyway --
    the vector is only load-bearing when something actually runs verify-core.js. One
    subprocess for the whole corpus.
    """
    entries = corpus_entries()
    tmpdir = Path(tempfile.mkdtemp())
    cases, as_file = [], []
    for e in entries:
        if e.get("decode") == "utf-8-strict":
            p = tmpdir / f"{e['id']}.bin"
            p.write_bytes(base64.b64decode(e["bytes_base64"]))
            cases.append((e["id"], str(p)))
            as_file.append(True)
        else:
            cases.append((e["id"], corpus_text(e)))
            as_file.append(False)
    try:
        rows = node_columns([c for c, f in zip(cases, as_file) if not f])
        rows += node_columns([c for c, f in zip(cases, as_file) if f], as_files=True)
    finally:
        for p in tmpdir.glob("*"):
            p.unlink()
        tmpdir.rmdir()
    by_id = {r["id"]: r for r in rows}
    wrong = []
    for e in entries:
        row = by_id[e["id"]]
        for who in ("npm", "browser"):
            if who not in row or who not in e["observed"]:
                continue
            col = row[who]
            got = "crash" if col.get("fatal") else ("load" if col["loads"] else "refuse")
            if got != e["observed"][who]:
                wrong.append(f"{e['id']}: {who} now {got}, "
                             f"vector recorded {e['observed'][who]}")
    assert not wrong, ("a frozen divergence changed shape -- fixed, or moved:\n  "
                       + "\n  ".join(wrong))


@pytest.mark.skipif(not _HAS_RUST and "rust" not in _REQUIRE,
                    reason="rust/target/release/obsign-verify-rs is not built")
def test_every_frozen_vector_still_behaves_as_recorded_in_rust():
    """The tie-break column, and the reason every one of these vectors has a verdict.

    Two of the divergences below are Python against JavaScript, which on its own is
    two implementations differing and no way to say which is wrong. Rust is a third
    reading of the same spec by another author, and on all nine vectors it answers
    exactly as Python does -- including refusing the invalid-UTF-8 files at the
    decoder, where it reports "cannot read: stream did not contain valid UTF-8". That
    makes JavaScript the outlier in every case rather than merely the other side.
    """
    entries = [e for e in corpus_entries()
               if "rust" in e["observed"] and e.get("decode") != "utf-8-strict"]
    # An empty corpus is success, not a broken census: every vector was a real
    # divergence and is deleted only once all implementations agree.
    got = rust_columns([(e["id"], corpus_text(e)) for e in entries])
    if not got:
        if "rust" in _REQUIRE:
            raise AssertionError("OBSIGN_REQUIRE=rust was set but the rust harness "
                                 "produced nothing -- a skip reads like a pass")
        pytest.skip("the rust harness produced nothing -- treated as absent")
    wrong = [f"{e['id']}: rust now "
             f"{'load' if got[e['id']]['loads'] else 'refuse'}, vector recorded "
             f"{e['observed']['rust']}"
             for e in entries
             if ("load" if got[e["id"]]["loads"] else "refuse") != e["observed"]["rust"]]
    assert not wrong, ("a frozen divergence changed shape in the rust reading:\n  "
                       + "\n  ".join(wrong))


@pytest.mark.skipif(not _HAS_NODE, reason="node not installed")
def test_two_different_files_do_not_share_one_claim_hash():
    r"""A canonical form whose whole job is telling documents apart, failing to.

    `{"a":"\xff"}` and `{"a":"\x80"}` are different files. Neither is valid UTF-8, so
    the Python CLI never opens either: `path.read_text(encoding="utf-8")` raises before
    `load_receipt` is called. `bin/obsign-verify.js` reads both with
    `fs.readFileSync(file, 'utf8')`, which substitutes U+FFFD without complaint, and
    both arrive at the parser as the same string. Same canonical bytes, same
    `receipt_sha256`, two files.

    canonical.py already states the property this breaks, about a different case:
    permitting NaN "would let two different receipts share a canonical form". Silent
    U+FFFD substitution lets them, for every reader built on Node's utf8 decoder or the
    browser's default TextDecoder, and it happens one layer above every wire-format
    limit either implementation checks. Both platforms offer a strict mode; the fix is
    to use it and refuse, which is what Python does by default.
    """
    tmpdir = Path(tempfile.mkdtemp())
    try:
        cases = []
        for name, raw in (("ff", b'{"a":"\xff"}'), ("x80", b'{"a":"\x80"}')):
            p = tmpdir / f"{name}.bin"
            p.write_bytes(raw)
            cases.append((name, str(p)))
        rows = {r["id"]: r["npm"] for r in node_columns(cases, as_files=True)}
    finally:
        for p in tmpdir.glob("*"):
            p.unlink()
        tmpdir.rmdir()
    # The PROPERTY is "two distinct files never share one claim hash". Refusing both
    # satisfies it outright and is the outcome Python and Rust already produced;
    # loading both with distinct hashes would satisfy it too. Only loading both and
    # agreeing on one hash is the failure, so that is what this rules out -- pinning
    # the property, not the mechanism that currently delivers it.
    loaded = [n for n in ("ff", "x80") if rows[n]["loads"]]
    if len(loaded) == 2:
        assert rows["ff"]["sha"] != rows["x80"]["sha"], (
            f"two distinct receipt files both canonicalise to "
            f"{rows['ff'].get('head')!r} and share the claim hash "
            f"{rows['ff']['sha'][:16]}..")
    else:
        assert not loaded, (
            f"one of two invalid-UTF-8 files loaded and the other did not: {rows}")


@pytest.mark.skipif(_BROWSER is None, reason="the producer's verify-core.js is not here")
def test_two_different_files_do_not_share_one_claim_hash_in_the_browser():
    r"""The same property, on the parser a stranger actually reaches.

    Python and Rust never open these files at all, and both JavaScript parsers now
    refuse them with "receipt is not valid UTF-8". Before that, `{"a":"\xff"}`,
    `{"a":"\x80"}` and `{"a":"\xc3"}` -- three different files -- reached the page
    through a lenient decoder and became one string, one canonical form and one
    `receipt_sha256`.

    That is the exact property canonical.py names when it explains `allow_nan=False`:
    permitting NaN "would let two different receipts share a canonical form". A
    canonical form that cannot tell two files apart is not doing the one job it has,
    and this happens before any wire-format limit on the page is consulted.
    `TextDecoder` takes `{fatal: true}`.
    """
    tmpdir = Path(tempfile.mkdtemp())
    try:
        cases = []
        for name, raw in (("ff", b'{"a":"\xff"}'), ("x80", b'{"a":"\x80"}')):
            q = tmpdir / f"{name}.bin"
            q.write_bytes(raw)
            cases.append((name, str(q)))
        rows = {r["id"]: r["browser"] for r in node_columns(cases, as_files=True)}
    finally:
        for q in tmpdir.glob("*"):
            q.unlink()
        tmpdir.rmdir()
    loaded = [n for n in ("ff", "x80") if rows[n]["loads"]]
    if len(loaded) == 2:
        assert rows["ff"]["sha"] != rows["x80"]["sha"], (
            f"two distinct receipt files both canonicalise to "
            f"{rows['ff'].get('head')!r} on the verify page and share the claim hash "
            f"{rows['ff']['sha'][:16]}..")
