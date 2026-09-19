"""Where this deployment runs `prove`.

`prove` executes untrusted, network-active exploits against a stranger's target from a
stranger's repository. This deployment contains every such run in a Docker container it spawns
as a sibling — see `tainted.execution.docker`.

The website's targets are always remote (internal hosts are refused at `app.py:363` and `:605`),
so the container gets the default bridge network and is fully isolated from the machine running
the server. That is the opposite of the CLI and MCP, whose targets are always localhost and who
therefore need `--network=host`.

**The server itself is no longer a container.** A containerised website cannot safely spawn
sandbox containers: it would need the host's Docker socket mounted into it, and socket access is
root-equivalent — granted to the exact process that runs strangers' generated exploits. So the
website ships as a wheel and runs as a process on a host that has Docker.
"""

from __future__ import annotations

import os

from tainted.execution.base import (  # noqa: F401 - the surface's public names
    Executor,
    LocalExecutor,
    OnCandidates,
    OnFinding,
    ProveOutcome,
    SandboxUnavailable,
)
from tainted.execution.docker import DockerExecutor


def default_executor() -> Executor:
    """The executor this deployment runs `prove` in.

    Always the Docker one. There is no configuration that turns it into an in-process run:
    `TAINTED_REQUIRE_SANDBOX` governs whether the app offers `prove` at all, and
    `run.apply_deployment_defaults()` sets it to 1.
    """
    return DockerExecutor(network="bridge")


def require_sandbox() -> bool:
    """Whether this deployment refuses to run `prove` on its own metal.

    Now means "require Docker". Kept by name because it is what `run.apply_deployment_defaults()`
    sets and what `.env.example` documents.
    """
    return os.environ.get("TAINTED_REQUIRE_SANDBOX", "").lower() in ("1", "true", "yes")
