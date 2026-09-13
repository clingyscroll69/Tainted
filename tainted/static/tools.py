"""Parse agent tool configurations into a scope/tool graph — the tool plane's substrate.

Configured agents parse directly (MCP manifests, n8n / Flowise exports). Coded agents go
through Python `ast` to recover tool registrations (LangChain `@tool`, CrewAI). The output is a
set of scopes, each holding tools; whether a tool is a source or a sink is the LLM's judgment,
attached later.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv"}


@dataclass
class ToolSpec:
    name: str
    description: str = ""
    role: Optional[str] = None  # "source" | "sink" | "neither" (LLM-assigned)
    severity: Optional[str] = None
    source_file: str = ""

    def as_prompt_dict(self) -> dict:
        return {"name": self.name, "description": self.description}


@dataclass
class AgentScope:
    """A single agent scope — the unit of co-location. If it holds both a source and a sink,
    it is a confused-deputy exposure candidate."""

    name: str
    kind: str  # "mcp" | "n8n" | "flowise" | "langchain" | "crewai"
    source_file: str
    tools: list[ToolSpec] = field(default_factory=list)
    coded: bool = False  # coded agents can't be sandbox-proven without a runnable entrypoint

    @property
    def sources(self) -> list[ToolSpec]:
        return [t for t in self.tools if t.role == "source"]

    @property
    def sinks(self) -> list[ToolSpec]:
        return [t for t in self.tools if t.role == "sink"]

    @property
    def is_colocated(self) -> bool:
        return bool(self.sources) and bool(self.sinks)


# --------------------------------------------------------------------------- #
# Config parsers
# --------------------------------------------------------------------------- #
def parse_mcp_manifest(data: dict, source_file: str) -> list[AgentScope]:
    """An MCP manifest: `{ "name": ..., "tools": [{ "name", "description" }] }`."""
    name = data.get("name") or Path(source_file).stem
    tools = [
        ToolSpec(
            name=t.get("name", "?"),
            description=t.get("description", ""),
            source_file=source_file,
        )
        for t in data.get("tools", [])
        if isinstance(t, dict)
    ]
    if not tools:
        return []
    return [AgentScope(name=name, kind="mcp", source_file=source_file, tools=tools)]


def parse_n8n_export(data: dict, source_file: str) -> list[AgentScope]:
    """An n8n workflow export: `{ "name": ..., "nodes": [{ "name", "type", ... }] }`."""
    nodes = data.get("nodes")
    if not isinstance(nodes, list):
        return []
    tools = [
        ToolSpec(
            name=n.get("name", n.get("type", "?")),
            description=n.get("type", ""),
            source_file=source_file,
        )
        for n in nodes
        if isinstance(n, dict)
    ]
    name = data.get("name") or Path(source_file).stem
    return [AgentScope(name=name, kind="n8n", source_file=source_file, tools=tools)]


def parse_flowise_export(data: dict, source_file: str) -> list[AgentScope]:
    """A Flowise chatflow export.

    Structurally close enough to n8n to be mistaken for it — both are `{nodes, edges}` — and
    labelling a Flowise flow "n8n" would put the wrong framework in the report and send the fix
    interview to the wrong place. The tell is the node shape: Flowise carries its metadata in
    `data.{label,name,category}`, n8n in a flat `type`.
    """
    nodes = data.get("nodes")
    if not isinstance(nodes, list):
        return []
    tools: list[ToolSpec] = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        node_data = n.get("data") if isinstance(n.get("data"), dict) else {}
        label = node_data.get("label") or node_data.get("name") or n.get("id", "?")
        description = " ".join(
            str(part)
            for part in (node_data.get("category"), node_data.get("description"))
            if part
        )
        tools.append(
            ToolSpec(name=str(label), description=description, source_file=source_file)
        )
    if not tools:
        return []
    name = data.get("name") or Path(source_file).stem
    return [AgentScope(name=name, kind="flowise", source_file=source_file, tools=tools)]


def _is_flowise(data: dict) -> bool:
    nodes = data.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return False
    first = nodes[0]
    if not isinstance(first, dict):
        return False
    node_data = first.get("data")
    return isinstance(node_data, dict) and (
        "category" in node_data or "label" in node_data or "inputAnchors" in node_data
    )


def parse_langchain_python(source: str, source_file: str) -> list[AgentScope]:
    """Recover `@tool`-decorated functions and StructuredTool definitions from Python code.

    One scope per file (a coarse but safe scope boundary for coded agents). Marked `coded`, so
    the tool plane knows it cannot be sandbox-proven without a runnable entrypoint.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    tools: list[ToolSpec] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _has_tool_decorator(node):
                tools.append(
                    ToolSpec(
                        name=node.name,
                        description=ast.get_docstring(node) or "",
                        source_file=source_file,
                    )
                )
    if not tools:
        return []
    return [
        AgentScope(
            name=Path(source_file).stem,
            kind="langchain",
            source_file=source_file,
            tools=tools,
            coded=True,
        )
    ]


def _has_tool_decorator(node) -> bool:
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = (
            target.id
            if isinstance(target, ast.Name)
            else target.attr
            if isinstance(target, ast.Attribute)
            else ""
        )
        if name in ("tool", "StructuredTool"):
            return True
    return False


def parse_crewai_python(source: str, source_file: str) -> list[AgentScope]:
    """Recover CrewAI `Agent(role=..., tools=[...])` definitions.

    CrewAI declares its scope explicitly, which makes it *more* precise than the file-level
    boundary used for LangChain: each `Agent(...)` names its own tool list, so a file holding
    a reader agent and a sender agent yields two scopes rather than one false co-location.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    # Tool objects assigned at module level: `search = SerperDevTool()` -> name by variable.
    tool_docs = _tool_descriptions(tree)
    scopes: list[AgentScope] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "Agent":
            continue
        role = _kwarg_str(node, "role") or _kwarg_str(node, "name")
        tool_names = _kwarg_list_names(node, "tools")
        if not tool_names:
            continue
        scopes.append(
            AgentScope(
                name=role or f"{Path(source_file).stem}_agent",
                kind="crewai",
                source_file=source_file,
                tools=[
                    ToolSpec(
                        name=n,
                        description=tool_docs.get(n, ""),
                        source_file=source_file,
                    )
                    for n in tool_names
                ],
                coded=True,
            )
        )
    return scopes


def _tool_descriptions(tree: ast.AST) -> dict[str, str]:
    """Map a tool variable/function name to whatever description the source gives it."""
    docs: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            docs[node.name] = ast.get_docstring(node) or ""
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            constructor = _call_name(node.value.func)
            described = _kwarg_str(node.value, "description") or constructor
            for target in node.targets:
                if isinstance(target, ast.Name):
                    docs[target.id] = described
    return docs


def _call_name(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _kwarg_str(call: ast.Call, key: str) -> Optional[str]:
    for kw in call.keywords:
        if kw.arg == key and isinstance(kw.value, ast.Constant):
            if isinstance(kw.value.value, str):
                return kw.value.value
    return None


def _kwarg_list_names(call: ast.Call, key: str) -> list[str]:
    for kw in call.keywords:
        if kw.arg != key or not isinstance(kw.value, (ast.List, ast.Tuple)):
            continue
        names: list[str] = []
        for element in kw.value.elts:
            if isinstance(element, ast.Name):
                names.append(element.id)
            elif isinstance(element, ast.Call):
                names.append(_call_name(element.func))
            elif isinstance(element, ast.Attribute):
                names.append(element.attr)
        return names
    return []


# --------------------------------------------------------------------------- #
# JavaScript / TypeScript agents
# --------------------------------------------------------------------------- #
_JS_TOOL_CONSTRUCTORS = {
    "DynamicStructuredTool",
    "DynamicTool",
    "StructuredTool",
    "Tool",
    "tool",
}


def parse_js_agent(source: str, source_file: str) -> list[AgentScope]:
    """Recover LangChain-JS style tool definitions: `new DynamicStructuredTool({name, ...})`.

    The JS ecosystem is where a lot of vibe-coded agents actually live, so recovering only the
    Python ones would leave the tool plane blind on the stack it most needs to see.
    """
    from tainted.static.parsing import language_for_path, node_text, parse, walk

    language = language_for_path(source_file)
    if language is None:
        return []
    try:
        tree = parse(source, language)
    except Exception:
        return []
    src = source.encode("utf-8")

    tools: list[ToolSpec] = []
    for node in walk(tree.root_node):
        if node.type not in ("new_expression", "call_expression"):
            continue
        constructor = node.child_by_field_name("constructor") or node.child_by_field_name(
            "function"
        )
        if constructor is None:
            continue
        ctor_name = node_text(constructor, src).split(".")[-1]
        if ctor_name not in _JS_TOOL_CONSTRUCTORS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        fields = _object_fields(args, src)
        name = fields.get("name")
        if not name:
            continue
        tools.append(
            ToolSpec(
                name=name,
                description=fields.get("description", ""),
                source_file=source_file,
            )
        )

    if not tools:
        return []
    return [
        AgentScope(
            name=Path(source_file).stem,
            kind="langchain-js",
            source_file=source_file,
            tools=tools,
            coded=True,
        )
    ]


def _object_fields(args_node, src: bytes) -> dict[str, str]:
    """String-valued fields of the first object literal in an argument list."""
    from tainted.static.parsing import node_text, walk

    fields: dict[str, str] = {}
    for node in walk(args_node):
        if node.type != "pair":
            continue
        key_node = node.child_by_field_name("key")
        value_node = node.child_by_field_name("value")
        if key_node is None or value_node is None:
            continue
        if value_node.type not in ("string", "template_string"):
            continue
        key = node_text(key_node, src).strip("\"'`")
        value = node_text(value_node, src).strip("\"'`")
        fields.setdefault(key, value)
    return fields


# --------------------------------------------------------------------------- #
# Repository scan
# --------------------------------------------------------------------------- #
_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs")


def discover_scopes(repo_path: str) -> list[AgentScope]:
    """Find every agent scope in a repository across the supported formats.

    Configured formats (MCP, n8n, Flowise) parse to provable scopes — the manifest *is* the
    program. Coded formats (LangChain, CrewAI, LangChain-JS) parse to scopes marked `coded`,
    which the sandbox refuses by design: proving one means booting the repository.
    """
    root = Path(repo_path)
    scopes: list[AgentScope] = []

    for path in root.rglob("*"):
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        rel = str(path.relative_to(root))

        if path.suffix == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(data, dict):
                continue
            if "nodes" in data:
                scopes.extend(
                    parse_flowise_export(data, rel)
                    if _is_flowise(data)
                    else parse_n8n_export(data, rel)
                )
            elif "tools" in data:
                scopes.extend(parse_mcp_manifest(data, rel))

        elif path.suffix == ".py":
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "crewai" in text.lower() or "Agent(" in text:
                scopes.extend(parse_crewai_python(text, rel))
            if "@tool" in text or "StructuredTool" in text:
                scopes.extend(parse_langchain_python(text, rel))

        elif path.suffix in _JS_EXTS:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if any(ctor in text for ctor in _JS_TOOL_CONSTRUCTORS):
                scopes.extend(parse_js_agent(text, rel))

    return scopes
