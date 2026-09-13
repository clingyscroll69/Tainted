"""A CrewAI crew: two agents, and only one of them holds both a source and a sink."""

from crewai import Agent, Crew, Task
from crewai_tools import ScrapeWebsiteTool, SerperDevTool

scrape = ScrapeWebsiteTool(description="Fetch and read the contents of any web page.")
search = SerperDevTool(description="Search the web for a query.")


def post_to_slack(message: str) -> str:
    """Post a message to the team's Slack channel."""
    return "..."


# Holds a source (scrape) and a sink (post_to_slack) — the co-located scope.
researcher = Agent(
    role="researcher",
    goal="Research a topic and report on it",
    tools=[scrape, search, post_to_slack],
)

# Holds only sources — no sink, so no confused-deputy exposure.
reader = Agent(
    role="reader",
    goal="Summarize pages",
    tools=[scrape, search],
)

crew = Crew(agents=[researcher, reader], tasks=[])
