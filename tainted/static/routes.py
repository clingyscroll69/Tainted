"""Route discovery — recovering the request surface the BOLA check reasons about.

BOLA is the *absence* of a predicate, so before anything can ask "is an ownership check
missing?" something has to say where a request parameter reaches a database read. That is this
module's whole job: recover routes, their parameters, and the reads inside their handlers.
It recovers facts and never judges meaning — whether a missing predicate is a *bug* is the
LLM's call (ranking) and the live probe's verdict (membership).

Framework-aware by necessity, because a route is declared differently everywhere:

  * **Flask / FastAPI** — Python `ast`. Decorators carry the path and the method.
  * **Express** — tree-sitter. `app.get("/invoices/:id", handler)`.
  * **Next.js App Router** — tree-sitter plus the filesystem: `app/api/invoices/[id]/route.ts`
    exporting `GET`. The `[id]` segment *is* the parameter declaration.
  * **Next.js Pages API** — the same, for `pages/api/**`.

Inside a handler the structure comes from the parser (which function, which lines) and the
predicate question is answered over that function's own text — a bounded region, so a regex
there is precise rather than the repo-wide guesswork it would be at file scope.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

from tainted.static.exclude import is_excluded
from tainted.static.parsing import (
    first_string_argument,
    language_for_path,
    node_text,
    parse,
    walk,
)

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv"}
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "all")


# --------------------------------------------------------------------------- #
# The recovered request surface
# --------------------------------------------------------------------------- #
@dataclass
class DbRead:
    """A database read found inside a handler body."""

    expression: str  # the matched construct, trimmed
    line: int  # absolute line in the file
    table: Optional[str] = None  # when the table/model name is recoverable
    kind: str = "query"  # supabase | prisma | sql | orm | mongo | query


@dataclass
class RouteHandler:
    """One route, its parameters, and what its handler does with them."""

    framework: str  # flask | fastapi | express | next-app | next-pages
    method: str  # GET / POST / ... (uppercase); "*" for catch-alls
    path: str  # the declared route path, as written
    params: list[str] = field(default_factory=list)  # path parameter names
    file: str = ""
    line: int = 0
    body: str = ""  # the handler's own source text
    db_reads: list[DbRead] = field(default_factory=list)
    # Two different signals, deliberately kept apart (see `_scan_body`).
    scoping_signals: list[str] = field(default_factory=list)  # predicate names the owner
    identity_signals: list[str] = field(default_factory=list)  # handler knows who is calling

    @property
    def reads_db(self) -> bool:
        return bool(self.db_reads)

    @property
    def has_ownership_check(self) -> bool:
        """True when the *query predicate* names an owner — not merely that identity was read.

        The distinction is the entire bug: an app that fetches `req.user` and then queries by
        `id` alone has identity and does not use it, which reads as safe to a shallow scan and
        is exactly the vulnerability.
        """
        return bool(self.scoping_signals)

    @property
    def param_reaching_read(self) -> Optional[str]:
        """The first path parameter that appears in a database read's expression."""
        for param in self.params:
            for read in self.db_reads:
                if re.search(rf"\b{re.escape(param)}\b", read.expression):
                    return param
        # Fall back to the first parameter: many handlers destructure before querying
        # (`const { id } = params`), so the name is in the body even if not in the read itself.
        for param in self.params:
            if re.search(rf"\b{re.escape(param)}\b", self.body):
                return param
        return None

    @property
    def tables(self) -> list[str]:
        seen: list[str] = []
        for read in self.db_reads:
            if read.table and read.table not in seen:
                seen.append(read.table)
        return seen

    def __str__(self) -> str:
        return f"{self.method} {self.path} ({self.file}:{self.line})"


# --------------------------------------------------------------------------- #
# Parameter extraction, per framework dialect
# --------------------------------------------------------------------------- #
_RE_FLASK_PARAM = re.compile(r"<(?:[^:>]+:)?([^>]+)>")  # <int:invoice_id>
_RE_BRACE_PARAM = re.compile(r"\{([^}:]+)\}")  # FastAPI {invoice_id}
_RE_COLON_PARAM = re.compile(r":(\w+)")  # Express :invoiceId
_RE_BRACKET_PARAM = re.compile(r"\[\.{0,3}(\w+)\]")  # Next [id] / [...slug]


def _params_from_path(path: str, framework: str) -> list[str]:
    if framework == "flask":
        return _RE_FLASK_PARAM.findall(path)
    if framework == "fastapi":
        return _RE_BRACE_PARAM.findall(path)
    if framework == "express":
        return _RE_COLON_PARAM.findall(path)
    return _RE_BRACKET_PARAM.findall(path)


# --------------------------------------------------------------------------- #
# What happens inside a handler
# --------------------------------------------------------------------------- #
@dataclass
class _ReadPattern:
    kind: str
    pattern: re.Pattern
    table_group: Optional[int] = None


_READ_PATTERNS: list[_ReadPattern] = [
    # Supabase / PostgREST client.
    _ReadPattern("supabase", re.compile(r"\.from\(\s*['\"`](\w+)['\"`]\s*\)[\s\S]{0,200}?\.select\("), 1),
    _ReadPattern("supabase", re.compile(r"\.table\(\s*['\"`](\w+)['\"`]\s*\)[\s\S]{0,200}?\.select\("), 1),
    # Prisma.
    _ReadPattern("prisma", re.compile(r"prisma\.(\w+)\s*\.\s*(?:findUnique|findFirst|findMany)\s*\("), 1),
    # Mongo / Mongoose.
    _ReadPattern("mongo", re.compile(r"(?:db\.)?(\w+)\s*\.\s*(?:findOne|findById)\s*\("), 1),
    # Knex / query builder.
    _ReadPattern("orm", re.compile(r"knex\(\s*['\"`](\w+)['\"`]\s*\)"), 1),
    # SQLAlchemy.
    _ReadPattern("orm", re.compile(r"(?:session|db\.session)\.query\(\s*(\w+)"), 1),
    _ReadPattern("orm", re.compile(r"\b(\w+)\.query\.(?:get|filter_by|filter)\s*\("), 1),
    _ReadPattern("orm", re.compile(r"(?:session|db\.session)\.get\(\s*(\w+)"), 1),
    # Raw SQL, either dialect.
    _ReadPattern("sql", re.compile(r"select\s+[\s\S]{0,200}?\bfrom\s+[\"'`]?(\w+)", re.I), 1),
    _ReadPattern("sql", re.compile(r"(?:cursor|conn|client|db)\.execute\s*\("), None),
]

# The predicate names the owner: this is what makes a read safe.
_SCOPING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("auth.uid()", re.compile(r"auth\s*\.\s*uid\s*\(\s*\)", re.I)),
    (
        ".eq(owner column)",
        re.compile(
            r"\.eq\(\s*['\"`](user_id|userId|owner|owner_id|ownerId|author_id|authorId|"
            r"created_by|createdBy|account_id|accountId|profile_id|profileId)['\"`]",
            re.I,
        ),
    ),
    (
        "where owner clause",
        # `where: { id, userId }` (Prisma), `where(...)`, `filter_by(user_id=...)`. The optional
        # colon matters: an object-literal `where:` is the commonest correct scoping in JS/TS.
        re.compile(
            r"(?:where|filter_by|filter)\s*:?\s*[\(\{\[][\s\S]{0,160}?\b(user_id|userId|owner|"
            r"owner_id|ownerId|author_id|authorId|created_by|createdBy|account_id|accountId)\b",
            re.I,
        ),
    ),
    (
        "owner column in SQL predicate",
        re.compile(
            r"\bwhere\b[\s\S]{0,160}?\b(user_id|owner|owner_id|author_id|created_by|account_id)\b",
            re.I,
        ),
    ),
    (
        "explicit ownership comparison",
        re.compile(
            r"\b(?:record|row|item|doc|data|result)\s*(?:\?\.)?\.\s*"
            r"(?:user_id|userId|owner|ownerId|author_id)\s*(?:!==|!=|===|==)",
            re.I,
        ),
    ),
]

# The handler knows who is calling. Necessary for a check, nowhere near sufficient.
_IDENTITY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("req.user", re.compile(r"\breq(?:uest)?\s*\.\s*user\b")),
    ("session user", re.compile(r"\bsession\s*(?:\.|\[)\s*['\"]?user", re.I)),
    ("current_user", re.compile(r"\b(?:current_user|currentUser)\b")),
    ("getUser()", re.compile(r"\b(?:getUser|getSession|auth)\s*\(\s*\)")),
    ("supabase auth", re.compile(r"auth\s*\.\s*getUser\s*\(")),
    ("flask-login", re.compile(r"\blogin_required\b|\bcurrent_user\b")),
]


def scoping_signals(text: str) -> list[str]:
    """Which owner-predicate signals appear in a region of code.

    Public so every candidate source — the route scan and the Semgrep taint pass alike — asks
    the question the same way. One definition of "the predicate names the owner", not two.
    """
    return [name for name, pat in _SCOPING_PATTERNS if pat.search(text)]


def identity_signals(text: str) -> list[str]:
    """Which caller-identity signals appear in a region of code."""
    return [name for name, pat in _IDENTITY_PATTERNS if pat.search(text)]


def _scan_body(body: str, start_line: int) -> tuple[list[DbRead], list[str], list[str]]:
    """Recover reads and both classes of ownership signal from one handler's text."""
    reads: list[DbRead] = []
    for rp in _READ_PATTERNS:
        for m in rp.pattern.finditer(body):
            table = None
            if rp.table_group is not None:
                try:
                    table = m.group(rp.table_group)
                except (IndexError, re.error):
                    table = None
            reads.append(
                DbRead(
                    expression=_clip(m.group(0)),
                    line=start_line + body[: m.start()].count("\n"),
                    table=table,
                    kind=rp.kind,
                )
            )
    return _dedupe_reads(reads), scoping_signals(body), identity_signals(body)


def _dedupe_reads(reads: list[DbRead]) -> list[DbRead]:
    seen: set[tuple[int, Optional[str]]] = set()
    out: list[DbRead] = []
    for r in sorted(reads, key=lambda r: r.line):
        key = (r.line, r.table)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _clip(text: str, limit: int = 160) -> str:
    collapsed = " ".join(text.split())
    return collapsed[:limit]


# --------------------------------------------------------------------------- #
# Python — Flask and FastAPI, via `ast`
# --------------------------------------------------------------------------- #
_FASTAPI_DECORATORS = set(_HTTP_METHODS)


def python_routes(source: str, rel_path: str) -> list[RouteHandler]:
    """Recover Flask `@app.route` and FastAPI `@app.get`-style routes."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    routes: list[RouteHandler] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            found = _route_from_decorator(dec)
            if found is None:
                continue
            framework, method, path = found
            body = _segment(lines, node.lineno, getattr(node, "end_lineno", node.lineno))
            reads, scoping, identity = _scan_body(body, node.lineno)
            params = _params_from_path(path, framework)
            for arg in _request_args(node):
                if arg not in params:
                    params.append(arg)
            routes.append(
                RouteHandler(
                    framework=framework,
                    method=method,
                    path=path,
                    params=params,
                    file=rel_path,
                    line=node.lineno,
                    body=body,
                    db_reads=reads,
                    scoping_signals=scoping,
                    identity_signals=identity,
                )
            )
    return routes


def _route_from_decorator(dec) -> Optional[tuple[str, str, str]]:
    """(framework, method, path) for a route decorator, else None."""
    if not isinstance(dec, ast.Call):
        return None
    func = dec.func
    if not isinstance(func, ast.Attribute):
        return None
    attr = func.attr.lower()
    path = _first_str(dec.args)
    if path is None:
        return None

    if attr == "route":  # Flask (and APIRouter.route)
        methods = _methods_kwarg(dec) or ["GET"]
        return "flask", methods[0], path
    if attr in _FASTAPI_DECORATORS:  # FastAPI / APIRouter .get/.post/...
        return "fastapi", attr.upper(), path
    return None


# Names a handler receives from the framework rather than from the caller. Treating one of
# these as a request parameter is how a query builder gets mistaken for an object reference.
_INJECTED_ARGS = {
    "self", "cls", "request", "req", "res", "response", "next",
    "session", "db", "conn", "connection", "cursor", "engine", "client",
    "background_tasks", "current_user", "user",
}
_DEPENDENCY_CALLS = {"Depends", "Security", "Header", "Cookie", "Body", "Form", "File"}


def _request_args(node) -> list[str]:
    """Handler signature arguments that plausibly carry caller-supplied values.

    FastAPI's `session=Depends(get_session)` is the framework handing the handler a database
    session; it is not something the caller controls, and mistaking it for a request parameter
    makes every dependency-injected route look like an object reference.
    """
    args = node.args
    positional = args.args + args.kwonlyargs
    # Line defaults up with the arguments they belong to (defaults bind to the tail).
    defaults: dict[str, object] = {}
    for arg, default in zip(args.args[len(args.args) - len(args.defaults) :], args.defaults):
        defaults[arg.arg] = default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default is not None:
            defaults[arg.arg] = default

    out: list[str] = []
    for arg in positional:
        if arg.arg.lower() in _INJECTED_ARGS:
            continue
        default = defaults.get(arg.arg)
        if isinstance(default, ast.Call) and _call_name(default.func) in _DEPENDENCY_CALLS:
            continue
        out.append(arg.arg)
    return out


def _call_name(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _first_str(args) -> Optional[str]:
    for a in args:
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            return a.value
    return None


def _methods_kwarg(dec: ast.Call) -> Optional[list[str]]:
    for kw in dec.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            out = [
                e.value.upper()
                for e in kw.value.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            ]
            if out:
                return out
    return None


def _segment(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1 : end])


# --------------------------------------------------------------------------- #
# JavaScript / TypeScript — Express, via tree-sitter
# --------------------------------------------------------------------------- #
_ROUTER_OBJECTS = {"app", "router", "server", "api", "express"}


def express_routes(source: str, rel_path: str, language: str) -> list[RouteHandler]:
    """Recover `app.get("/x/:id", handler)` / `router.post(...)` registrations."""
    try:
        tree = parse(source, language)
    except Exception:
        return []
    src = source.encode("utf-8")
    routes: list[RouteHandler] = []

    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            continue
        prop = func.child_by_field_name("property")
        obj = func.child_by_field_name("object")
        if prop is None or obj is None:
            continue
        method = node_text(prop, src).lower()
        if method not in _HTTP_METHODS:
            continue
        obj_name = node_text(obj, src).split(".")[-1].lower()
        if obj_name not in _ROUTER_OBJECTS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        path = first_string_argument(args, src)
        if path is None or not path.startswith("/"):
            continue

        body = node_text(node, src)
        line = node.start_point[0] + 1
        reads, scoping, identity = _scan_body(body, line)
        routes.append(
            RouteHandler(
                framework="express",
                method="*" if method == "all" else method.upper(),
                path=path,
                params=_params_from_path(path, "express"),
                file=rel_path,
                line=line,
                body=body,
                db_reads=reads,
                scoping_signals=scoping,
                identity_signals=identity,
            )
        )
    return routes


# --------------------------------------------------------------------------- #
# Next.js — the filesystem declares the route, the module declares the methods
# --------------------------------------------------------------------------- #
def next_app_routes(source: str, rel_path: str, language: str) -> list[RouteHandler]:
    """`app/api/invoices/[id]/route.ts` exporting GET/POST/… — the App Router shape."""
    params = _RE_BRACKET_PARAM.findall(rel_path)
    url_path = _next_url_path(rel_path)
    try:
        tree = parse(source, language)
    except Exception:
        return []
    src = source.encode("utf-8")
    routes: list[RouteHandler] = []

    for node in walk(tree.root_node):
        if node.type not in ("function_declaration", "lexical_declaration", "variable_declarator"):
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = node_text(name_node, src)
        if name.lower() not in _HTTP_METHODS:
            continue
        body = node_text(node, src)
        line = node.start_point[0] + 1
        reads, scoping, identity = _scan_body(body, line)
        routes.append(
            RouteHandler(
                framework="next-app",
                method=name.upper(),
                path=url_path,
                params=list(params),
                file=rel_path,
                line=line,
                body=body,
                db_reads=reads,
                scoping_signals=scoping,
                identity_signals=identity,
            )
        )
    return routes


def next_pages_routes(source: str, rel_path: str, language: str) -> list[RouteHandler]:
    """`pages/api/invoices/[id].ts` — one default-exported handler serving every method."""
    params = _RE_BRACKET_PARAM.findall(rel_path)
    url_path = _next_url_path(rel_path)
    line = 1
    reads, scoping, identity = _scan_body(source, line)
    if not reads:
        return []
    return [
        RouteHandler(
            framework="next-pages",
            method="*",
            path=url_path,
            params=list(params),
            file=rel_path,
            line=line,
            body=source,
            db_reads=reads,
            scoping_signals=scoping,
            identity_signals=identity,
        )
    ]


def _next_url_path(rel_path: str) -> str:
    """Turn a Next file path into the URL it serves."""
    p = rel_path.replace("\\", "/")
    for marker in ("/app/", "/pages/"):
        if marker in p:
            p = p.split(marker, 1)[1]
            break
    else:
        p = re.sub(r"^(app|pages)/", "", p)
    p = re.sub(r"/route\.(ts|tsx|js|jsx|mjs)$", "", p)
    p = re.sub(r"\.(ts|tsx|js|jsx|mjs)$", "", p)
    p = re.sub(r"/index$", "", p)
    # Route groups `(marketing)` are organizational and do not appear in the URL.
    p = re.sub(r"/?\([^)]+\)", "", p)
    return "/" + p.strip("/")


def _is_next_app_route(rel_path: str) -> bool:
    p = rel_path.replace("\\", "/")
    return bool(re.search(r"(^|/)app/.*/route\.(ts|tsx|js|jsx|mjs)$", p))


def _is_next_pages_api(rel_path: str) -> bool:
    p = rel_path.replace("\\", "/")
    return bool(re.search(r"(^|/)pages/api/.*\.(ts|tsx|js|jsx|mjs)$", p))


# --------------------------------------------------------------------------- #
# Repository scan
# --------------------------------------------------------------------------- #
_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")


def discover_routes(repo_path: str, exclude: Sequence[str] = ()) -> list[RouteHandler]:
    """Every route the repository declares, across the supported frameworks."""
    root = Path(repo_path)
    routes: list[RouteHandler] = []

    for path in _candidate_files(root, exclude):
        rel = str(path.relative_to(root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if path.suffix == ".py":
            routes.extend(python_routes(text, rel))
            continue

        language = language_for_path(rel)
        if language is None:
            continue
        if _is_next_app_route(rel):
            routes.extend(next_app_routes(text, rel, language))
        elif _is_next_pages_api(rel):
            routes.extend(next_pages_routes(text, rel, language))
        else:
            routes.extend(express_routes(text, rel, language))

    return routes


def _candidate_files(root: Path, exclude: Sequence[str] = ()) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if exclude and is_excluded(str(path.relative_to(root)), exclude):
            continue
        if path.suffix == ".py" or path.suffix in _JS_EXTS:
            yield path
