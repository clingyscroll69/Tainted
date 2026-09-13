"""Test-integrity mutation-testing wrapper: parsers and graceful degradation."""

from __future__ import annotations

import json

from tainted.checks.test_integrity import (
    CommandResult,
    MutationResult,
    parse_stryker,
    run_mutation_testing,
)


def test_parse_stryker_counts_survivors():
    report = json.dumps(
        {
            "files": {
                "src/a.ts": {
                    "mutants": [
                        {"status": "Killed", "mutatorName": "ArithmeticOperator"},
                        {
                            "status": "Survived",
                            "mutatorName": "ConditionalExpression",
                            "location": {"start": {"line": 42}},
                            "replacement": "false",
                        },
                        {"status": "NoCoverage", "mutatorName": "StringLiteral",
                         "location": {"start": {"line": 7}}},
                    ]
                }
            }
        }
    )
    result = parse_stryker(report)
    assert result.total == 3
    assert result.killed == 1
    assert result.survived == 2
    assert result.score == 1 / 3
    survivor_lines = {m.line for m in result.survivors}
    assert survivor_lines == {42, 7}


def test_tool_missing_is_reported_not_zeroed(tmp_path):
    (tmp_path / "package.json").write_text("{}")

    def missing_runner(cmd, cwd):
        return CommandResult(returncode=127, tool_missing=True)

    result = run_mutation_testing(str(tmp_path), runner=missing_runner)
    assert result.available is False  # honest: not a misleading score of 0
    assert result.score is None
    assert "not installed" in result.note.lower()


def test_no_suite_found(tmp_path):
    (tmp_path / "notes.txt").write_text("nothing to mutate")
    result = run_mutation_testing(str(tmp_path))
    assert result.available is False
    assert result.tool == "none"
