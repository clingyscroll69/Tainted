"""The `tainted_tutorial` tool — how the calling agent learns to drive this server."""

from __future__ import annotations

import asyncio

from tainted_mcp.server import server, tainted_tutorial
from tainted_mcp.tutorial import LESSONS


def test_tutorial_tool_is_registered():
    tools = asyncio.run(server.list_tools())
    assert "tainted_tutorial" in {t.name for t in tools}


def test_no_topic_lists_the_topics():
    out = tainted_tutorial()
    assert [t["topic"] for t in out["topics"]] == [l["topic"] for l in LESSONS]


def test_a_topic_returns_the_lesson():
    out = tainted_tutorial(topic="ownership")
    assert out["topic"] == "ownership"
    assert out["steps"]


def test_unknown_topic_returns_an_error_and_the_real_topics():
    out = tainted_tutorial(topic="nope")
    assert "error" in out
    assert "ownership" in out["topics"]


def test_the_ownership_lesson_states_the_boundary():
    """An agent reading this must not come away thinking the check is routable."""
    lesson = next(l for l in LESSONS if l["topic"] == "ownership")
    body = " ".join(s["body"] for s in lesson["steps"]).lower()
    assert "localhost" in body
