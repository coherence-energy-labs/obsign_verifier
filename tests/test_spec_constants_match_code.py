"""The specification's numbers must be the code's numbers.

`docs/SPEC.md` exists so a fourth implementation can be written without reading
`src/`. That promise is worth exactly as much as the agreement between the document
and the code, and prose cannot hold a number still: `docs/RL.md` said "26 opcodes"
for the whole life of a 31-opcode machine, in a section titled "Limits, stated
plainly", and nothing was able to notice.

So the numbers do not live in prose. They live in `docs/spec/limits.json` and
`docs/spec/opcodes.json`, which SPEC.md renders, and this file holds those two files
to the three implementations:

    * Python  -- imported, so the check reads the value the interpreter uses.
    * JavaScript and Rust -- read out of the source text by regex, because there is
      no way to import them from here, and a constant that agrees in Python while
      diverging in a port is the exact failure `COMPAT.md` says must not exist
      ("all implementations must agree on what LOADS").

A constant recorded in `limits.json` with no implementation to check it against
would be a documented number nobody verifies, so every entry must name at least one
source and every named source must yield the value.

WHY THE OPCODE COUNT IS CHECKED IN THE DOCUMENTS TOO. `RL.md` and `COMPAT.md` both
state it in English. Neither statement is reachable from the other, and the
disagreement between them (26 vs 31) is finding C1 of `rust/README.md`. The count is
therefore extracted from the prose and required to equal `len(replay.OPS)` -- and
each document is required to state it at all, so this check cannot pass by finding
nothing.
"""

from __future__ import annotations

import ast
import json
import re
from importlib import import_module
from pathlib import Path

import pytest

from obsign_verify import replay as replaymod

ROOT = Path(__file__).resolve().parents[1]
LIMITS_PATH = ROOT / "docs" / "spec" / "limits.json"
OPCODES_PATH = ROOT / "docs" / "spec" / "opcodes.json"
SPEC_PATH = ROOT / "docs" / "SPEC.md"

#: Documents that state the opcode count in prose, and must keep stating it. `SPEC.md`
#: is included because it is the document a reimplementer works from: a specification
#: that disagrees with the machine is worse than no specification.
COUNT_DOCS = (Path("docs") / "RL.md", Path("docs") / "COMPAT.md",
              Path("docs") / "SPEC.md")

#: The two English forms a count is written in: "31 opcodes" and "31-opcode".
_COUNT_PATTERNS = (re.compile(r"\b(\d+)\s+opcodes?\b"),
                   re.compile(r"\b(\d+)-opcode\b"))


def _read(rel: str) -> str:
    path = ROOT / rel
    assert path.is_file(), f"{rel} does not exist, so this check would be vacuous"
    return path.read_text(encoding="utf-8")


def _eval_literal(text: str):
    """Evaluate a source-level constant expression from any of the three languages.

    Only the arithmetic the constant tables actually use is permitted -- shifts,
    products, sums and negation over numeric literals -- so this cannot be turned
    into an `eval` of arbitrary source by a future edit to a checked file.
    """
    cleaned = re.sub(r"(\d)n\b", r"\1", text.strip())      # JavaScript BigInt suffix
    cleaned = cleaned.replace("_", "")                     # digit separators
    node = ast.parse(cleaned, mode="eval").body

    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return n.value
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, (ast.USub, ast.UAdd)):
            v = ev(n.operand)
            return -v if isinstance(n.op, ast.USub) else v
        if isinstance(n, ast.BinOp):
            a, b = ev(n.left), ev(n.right)
            if isinstance(n.op, ast.LShift):
                return a << b
            if isinstance(n.op, ast.Mult):
                return a * b
            if isinstance(n.op, ast.Add):
                return a + b
            if isinstance(n.op, ast.Sub):
                return a - b
        raise AssertionError(f"unsupported constant expression: {text!r}")

    return ev(node)


def _python_value(source_rel: str, symbol: str):
    """Import the module the SPEC names and read the symbol out of it.

    Imported rather than regexed: the value the interpreter actually holds is the
    one that decides verdicts, and a regex over Python source would agree with a
    constant that a later line reassigns.
    """
    assert source_rel.startswith("src/") and source_rel.endswith(".py"), source_rel
    module = source_rel[len("src/"):-len(".py")].replace("/", ".")
    mod = import_module(module)
    assert hasattr(mod, symbol), f"{module} has no {symbol}"
    return getattr(mod, symbol)


def _js_value(source_rel: str, symbol: str) -> str:
    # Either its own declaration, or a continuation declarator in a comma-separated
    # one (`const COST_CELL = 1, COST_INPUT = 16, ...`). Missing the second form made
    # four real constants silently unfindable, which is a dark check, not a pass.
    text = _read(source_rel)
    m = re.search(
        rf"(?:(?:const|let|var)\s+|,\s*){re.escape(symbol)}\s*=\s*([^;,]+)[;,]", text)
    assert m, f"{source_rel} does not declare {symbol}"
    return m.group(1)


def _rust_value(source_rel: str, symbol: str) -> str:
    text = _read(source_rel)
    m = re.search(
        rf"(?:pub\s+)?const\s+{re.escape(symbol)}\s*:\s*[A-Za-z0-9_:<>]+\s*=\s*([^;]+);",
        text)
    assert m, f"{source_rel} does not declare {symbol}"
    return m.group(1)


_EXTRACT = {"javascript": _js_value, "rust": _rust_value}


def _limits() -> dict:
    assert LIMITS_PATH.is_file(), (
        "docs/spec/limits.json does not exist -- the SPEC's numbers are unchecked")
    data = json.loads(LIMITS_PATH.read_text(encoding="utf-8"))
    assert data.get("constants"), "limits.json declares no constants"
    return data


def _constant_ids() -> list[str]:
    try:
        return sorted(_limits()["constants"])
    except Exception:                       # collection must not blow up; the test below reports it
        return []


def test_limits_file_exists_and_is_well_formed():
    data = _limits()
    for name, entry in data["constants"].items():
        assert "value" in entry, f"{name} records no value"
        assert entry.get("contract"), f"{name} names no contract section"
        assert entry.get("sources") or entry.get("patterns"), (
            f"{name} is recorded with nothing to check it against -- a documented "
            f"number no implementation is held to is prose with a colon in it")


@pytest.mark.parametrize("name", _constant_ids() or ["<limits.json missing>"])
def test_constant_matches_every_implementation_that_declares_it(name):
    """Each recorded constant equals the value each named implementation holds."""
    constants = _limits()["constants"]
    entry = constants[name]
    want = entry["value"]
    symbols = entry.get("symbols") or {}
    aliases = entry.get("aliases") or {}
    checked = []

    for lang, source_rel in (entry.get("sources") or {}).items():
        symbol = symbols.get(lang, name)
        if lang == "python":
            got = _python_value(source_rel, symbol)
            assert got == want, f"{name}: {source_rel} holds {got!r}, SPEC says {want!r}"
        else:
            raw = _EXTRACT[lang](source_rel, symbol).strip()
            if lang in aliases:
                assert raw == aliases[lang], (
                    f"{name}: {source_rel} declares {raw!r}, SPEC records the alias "
                    f"{aliases[lang]!r}")
            else:
                got = _eval_literal(raw)
                assert got == want, (
                    f"{name}: {source_rel} declares {raw!r} = {got!r}, "
                    f"SPEC says {want!r}")
        checked.append(f"{lang}:{source_rel}")

    # Constants that are written as bare literals inside an expression rather than
    # given a name (the liveness budget multiplier, the per-run step floor) are
    # pinned by a capturing regex instead. Same requirement: it must be findable and
    # it must carry the recorded value.
    for lang, spec in (entry.get("patterns") or {}).items():
        text = _read(spec["file"])
        m = re.search(spec["regex"], text)
        assert m, (f"{name}: {spec['file']} no longer matches the pinned pattern "
                   f"{spec['regex']!r} -- the SPEC's number is no longer in the code")
        got = _eval_literal(m.group(1))
        assert got == want, (f"{name}: {spec['file']} carries {got!r}, "
                             f"SPEC says {want!r}")
        checked.append(f"{lang}:{spec['file']}")

    assert checked, f"{name} was checked against nothing"


def test_opcode_table_matches_the_python_machine():
    """Every row of opcodes.json is the Python table's row, in the Python order."""
    assert OPCODES_PATH.is_file(), (
        "docs/spec/opcodes.json does not exist -- SPEC.md's instruction set is "
        "unchecked prose")
    data = json.loads(OPCODES_PATH.read_text(encoding="utf-8"))
    rows = data.get("opcodes")
    assert rows, "opcodes.json lists no opcodes"

    ops = list(replaymod.OPS.items())
    assert len(rows) == len(ops), (
        f"opcodes.json lists {len(rows)} opcodes, replay.OPS has {len(ops)}")

    for i, (row, (name, (arity, kind))) in enumerate(zip(rows, ops)):
        assert row["number"] == i, (
            f"opcode {row.get('name')!r}: SPEC numbers it {row['number']}, it is "
            f"row {i} of replay.OPS")
        assert row["name"] == name, (
            f"row {i}: SPEC names it {row['name']!r}, replay.OPS has {name!r}")
        assert row["arity"] == arity, (
            f"{name}: SPEC says arity {row['arity']}, replay.OPS says {arity}")
        assert row["kind"] == kind, (
            f"{name}: SPEC says kind {row['kind']!r}, replay.OPS says {kind!r}")
        assert row.get("semantics"), f"{name} is listed with no semantics"

    # A name in the machine and not in the narrative is a rung of the spec a
    # reimplementer never sees.
    spec_text = _read("docs/SPEC.md")
    absent = [name for name, _ in ops if not re.search(rf"\b{re.escape(name)}\b", spec_text)]
    assert not absent, f"docs/SPEC.md never mentions these opcodes: {absent}"


def test_opcode_count_agrees_across_the_documents():
    """RL.md and COMPAT.md must both state the count, and both must be right.

    This is finding C1: `RL.md` said 26 and `COMPAT.md` said 31 for the same
    machine. Requiring each document to state it is what stops this passing by
    finding nothing to disagree with.
    """
    want = len(replaymod.OPS)
    for rel in COUNT_DOCS:
        text = _read(rel.as_posix())
        found = [int(m) for pat in _COUNT_PATTERNS for m in pat.findall(text)]
        assert found, (
            f"{rel.as_posix()} states no opcode count -- it used to, and a check "
            f"that finds nothing is not a check")
        wrong = sorted({n for n in found if n != want})
        assert not wrong, (
            f"{rel.as_posix()} states {wrong} opcode(s); the machine has {want}")

    if OPCODES_PATH.is_file():
        rows = json.loads(OPCODES_PATH.read_text(encoding="utf-8"))["opcodes"]
        assert len(rows) == want, (
            f"docs/spec/opcodes.json lists {len(rows)}, the machine has {want}")
