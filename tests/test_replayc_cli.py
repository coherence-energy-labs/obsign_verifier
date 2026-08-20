"""The compiler's CLI, held to its exit codes and its words."""
from __future__ import annotations

import json
import pathlib

from obsign_verify.replayc.__main__ import main

SRC = "input a, b; output a * b + 1;"


def test_build_run_check_attest_roundtrip(tmp_path, capsys):
    rl = tmp_path / "p.rl"
    rl.write_text(SRC, encoding="utf-8")
    out = tmp_path / "p.json"

    assert main(["build", str(rl), "-o", str(out)]) == 0
    prog = json.loads(out.read_text())
    assert prog["spec"] == "obsign/replay/1"

    assert main(["check", str(rl)]) == 0
    assert "ok" in capsys.readouterr().out

    assert main(["run", str(rl), "-i", "6, 7"]) == 0
    cap = capsys.readouterr()
    assert cap.out.strip() == "43"
    assert "output_sha256" in cap.err

    assert main(["attest", str(rl), "--against", str(out)]) == 0
    assert "MATCH" in capsys.readouterr().out

    rl.write_text(SRC.replace("+ 1", "+ 2"), encoding="utf-8")
    assert main(["attest", str(rl), "--against", str(out)]) == 1
    assert "MISMATCH" in capsys.readouterr().err


def test_check_reports_errors_with_positions(tmp_path, capsys):
    bad = tmp_path / "bad.rl"
    bad.write_text("input a: fx32, b: fx16; output a + b;", encoding="utf-8")
    try:
        code = main(["check", str(bad)])
    except SystemExit as e:                    # _compile_or_die raises SystemExit(2)
        code = e.code
    assert code == 2
    assert "scale mismatch" in capsys.readouterr().err


def test_run_reports_traps_as_refusals(tmp_path, capsys):
    rl = tmp_path / "t.rl"
    rl.write_text("input a, b; output a / b;", encoding="utf-8")
    assert main(["run", str(rl), "-i", "1,0"]) == 1
    assert "TRAP" in capsys.readouterr().err
