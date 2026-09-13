"""A coded LangChain agent — parsed statically, but NOT sandbox-proven (would require booting)."""

from langchain_core.tools import tool


@tool
def fetch_webpage(url: str) -> str:
    """Fetch the contents of a web page (a data source)."""
    return "..."


@tool
def run_shell(command: str) -> str:
    """Run a shell command on the host (a dangerous sink)."""
    return "..."
