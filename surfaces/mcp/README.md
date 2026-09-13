# Tainted MCP server

Tainted, called by the assistant that's writing the code. An MCP call is
short-lived, which fits `analyze` but can't hold open a real attack run. So:

- `tainted_analyze` — runs synchronously, read-only.
- `tainted_prove_start` / `tainted_prove_status` / `tainted_prove_result` — an
  async job: start it, poll it, fetch the finished report.
- `tainted_fix_interview` — asks the questions a fix needs answered first.
- `tainted_fix` — interactive. It only returns a patch; the client applies the
  edits.

- `tainted_tutorial` — how to drive this server: call order, the index contract, the
  async prove job, the ownership boundary, the fix interview, and how to report a result
  without overclaiming. Call it with no topic to list the topics. The server's own
  instructions point at it, so a client reads it before the first `prove`.

Every tool that names a possible hole takes an `index`. That is a position in the
ranked list `tainted_analyze` returns, counting from 0. An index past the end comes
back as `{"error": "no candidate at index N (have M)"}`.

## Fixing an agent-injection hole

Most fixes are decided by the code. An agent-injection fix is not. There are four
repairs, and the right one depends on facts only you hold: whether the agent really
needs both tools, whether a person can approve the risky action, and whether that
action can afford to be slower. Tainted will not guess, so it asks.

Call `tainted_fix_interview(repo_path, index)` first:

```json
{
  "candidate": "Agent `support_bot` could be tricked into misusing a tool",
  "interview": [
    {"key": "needs_both",      "question": "Does `support_bot` really need both of these tools to do its job?",   "options": ["no", "yes"]},
    {"key": "human_available", "question": "Is a person available to approve the risky action before it runs?",   "options": ["yes", "no"]},
    {"key": "latency_ok",      "question": "Can this action be slower, to add a check before it runs?",           "options": ["yes", "no"]}
  ]
}
```

Then pass the answers to `tainted_fix` as `{question_key: choice}`:

```json
{"repo_path": "/path/to/app", "index": 0,
 "answers": {"needs_both": "yes", "human_available": "no", "latency_ok": "yes"}}
```

The answers pick the repair:

| Answers | Repair |
|---|---|
| `needs_both: no` | **scope split** — split the two tools into separate agents |
| `needs_both: yes`, `human_available: yes` | **mediation** — a person or a policy gate approves the risky action |
| `needs_both: yes`, `human_available: no`, `latency_ok: yes` | **sink confirmation** — confirm each risky call before it runs |
| `needs_both: yes`, `human_available: no`, `latency_ok: no` | **provenance** — track where the data came from, and block it at the risky call |

Two shortcuts:

- For every other check the code decides the fix. `tainted_fix_interview` returns an
  empty `interview` and a `note` saying to call `tainted_fix` directly.
- You can skip the interview call. If `tainted_fix` needs answers it does not have, it
  returns the same questions under `interview` alongside an `error`.

`prove` only fires at a target the human named, and only if that target is verified or
local — never a URL that arrived through another tool's output. Its live
HTTP calls are also constrained by the engine's **plan-commitment** self-defense:
`prove` commits to its list of probes up front, and any request outside that list is
refused (`blocked_calls` lists what got refused).

## Deploy

From a repo that has the core (`tainted/`, root `pyproject.toml`) plus this folder:

```bash
pip install -e .                 # core engine
pip install -e surfaces/mcp      # this surface
export GEMINI_API_KEY=...          # optional
tainted-mcp                        # runs a stdio MCP server
```

Register it with an MCP client (for example Claude Desktop or Claude Code):

```json
{
  "mcpServers": {
    "tainted": { "command": "tainted-mcp" }
  }
}
```

SSE and streamable-HTTP transports are available too, via `server.run(transport=...)`
in `server.py`.
