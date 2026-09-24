"""Agent formats beyond MCP and LangChain-Python.

The tool plane is only as wide as what it can parse, and vibe-coded agents do not all live in
Python. Each format here also carries the provable/coded distinction, which decides whether the
sandbox will attempt a proof or the report will argue statically and say so.
"""

from __future__ import annotations

from pathlib import Path

from tainted.static.tools import (
    _is_flowise,
    discover_scopes,
    parse_crewai_python,
    parse_flowise_export,
    parse_js_agent,
    parse_n8n_export,
)

CONFIGS = str(Path(__file__).parent / "fixtures" / "agent_configs")


def _scopes():
    return {s.name: s for s in discover_scopes(CONFIGS)}


# --------------------------------------------------------------------------- #
# Flowise, and not mistaking it for n8n
# --------------------------------------------------------------------------- #
def test_flowise_is_not_parsed_as_n8n():
    """Both are `{nodes, edges}`; the wrong label sends the fix to the wrong framework."""
    scope = _scopes()["support_triage"]
    assert scope.kind == "flowise"
    assert scope.coded is False  # a chatflow is configuration, so it is provable


def test_flowise_labels_and_descriptions_survive_for_the_labeller():
    flowise = {
        "name": "flow",
        "nodes": [{"id": "n0", "data": {"label": "Read Inbox", "category": "Tools",
                                        "description": "reads mail"}}],
    }
    assert _is_flowise(flowise) is True
    tool = parse_flowise_export(flowise, "flow.json")[0].tools[0]
    assert tool.name == "Read Inbox"
    # The LLM labels source/sink from the description, so it has to reach it.
    assert "reads mail" in tool.description


def test_n8n_export_is_still_recognised_as_n8n():
    n8n = {"name": "wf", "nodes": [{"name": "Gmail", "type": "n8n-nodes-base.gmail"}]}
    assert _is_flowise(n8n) is False
    assert parse_n8n_export(n8n, "wf.json")[0].kind == "n8n"


# --------------------------------------------------------------------------- #
# CrewAI — one scope per Agent, not one per file
# --------------------------------------------------------------------------- #
def test_crewai_yields_one_scope_per_agent():
    scopes = _scopes()
    assert "researcher" in scopes and "reader" in scopes
    assert scopes["researcher"].kind == "crewai"
    assert {t.name for t in scopes["researcher"].tools} == {
        "scrape", "search", "post_to_slack"
    }
    # The reader agent holds no sink; a file-level scope would have merged the two and
    # invented a co-location that does not exist.
    assert {t.name for t in scopes["reader"].tools} == {"scrape", "search"}


def test_crewai_tool_descriptions_are_recovered_from_both_shapes():
    scope = [s for s in _scopes().values() if s.name == "researcher"][0]
    by_name = {t.name: t.description for t in scope.tools}
    assert "web page" in by_name["scrape"]  # from the constructor kwarg
    assert "Slack" in by_name["post_to_slack"]  # from the function docstring


def test_crewai_agents_are_coded_and_therefore_not_sandbox_provable():
    assert _scopes()["researcher"].coded is True


def test_crewai_agent_without_tools_is_not_a_scope():
    source = "from crewai import Agent\na = Agent(role='x', goal='y')\n"
    assert parse_crewai_python(source, "a.py") == []


# --------------------------------------------------------------------------- #
# LangChain-JS
# --------------------------------------------------------------------------- #
def test_js_agent_tools_are_recovered_with_descriptions():
    scope = _scopes()["js_agent"]
    assert scope.kind == "langchain-js"
    assert scope.coded is True
    by_name = {t.name: t.description for t in scope.tools}
    assert set(by_name) == {"fetch_page", "send_webhook"}
    assert "POST arbitrary JSON" in by_name["send_webhook"]


def test_js_file_with_no_tool_constructors_yields_nothing():
    assert parse_js_agent("export const x = 1;\n", "x.ts") == []


def test_an_n8n_node_with_a_null_name_still_gets_a_name():
    """A `.get` default fills only a missing key; `"name": null` used to reach the graph."""
    scopes = parse_n8n_export(
        {"name": "flow", "nodes": [{"name": None, "type": "n8n-nodes-base.gmail"}]}, "flow.json"
    )
    assert scopes[0].tools[0].name == "n8n-nodes-base.gmail"
