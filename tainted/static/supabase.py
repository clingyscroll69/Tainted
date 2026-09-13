"""Supabase ownership-model audit.

On the Supabase stack the frontend is frequently not a boundary: the browser holds a token and
addresses the database directly, so the only thing between one user and every user's rows is a
row-level-security (RLS) policy the AI was never asked to write. This module recovers that model
from SQL and code:

  1. Parse migrations/config for declared tables, RLS-enable statements, and policies.
  2. Parse client TS/JS for tables the browser reads via `.from().select()`.
  3. Audit each client-read table: RLS enabled? a policy present? does it reference `auth.uid()`?

A client-read table with RLS off, or a policy of `true`, is a structural hole confirmed on
inspection — it needs no ranking or live proof to be real.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import logging

import sqlglot
from sqlglot import exp

# RLS DDL (ALTER … ENABLE ROW LEVEL SECURITY, CREATE POLICY) is Postgres-specific and always
# falls back to sqlglot's raw `Command` — expected, and handled by regex. Silence the noise.
logging.getLogger("sqlglot").setLevel(logging.ERROR)

from tainted.static.parsing import find_supabase_table_ops, language_for_path


# --------------------------------------------------------------------------- #
# The recovered SQL ownership model
# --------------------------------------------------------------------------- #
@dataclass
class Policy:
    table: str
    name: str
    command: str  # select / insert / update / delete / all
    using_expr: str  # the raw USING(...) / WITH CHECK(...) expression
    source_file: str
    line: int = 0

    @property
    def references_auth_uid(self) -> bool:
        return bool(re.search(r"auth\s*\.\s*uid\s*\(\s*\)", self.using_expr, re.I))

    @property
    def is_permissive_true(self) -> bool:
        """A policy whose predicate is literally `true` — everyone passes."""
        stripped = self.using_expr.strip().strip("()").strip().lower()
        return stripped in ("true", "1", "1=1")


# Column names that conventionally hold the owning user's id, best first.
_OWNER_COLUMN_CANDIDATES = (
    "user_id",
    "owner_id",
    "owner",
    "author_id",
    "author",
    "created_by",
    "account_id",
    "profile_id",
    "user",
)


@dataclass
class TableModel:
    name: str
    declared: bool = False
    rls_enabled: bool = False
    policies: list[Policy] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    # Populated from client code:
    client_read: bool = False
    client_written: bool = False
    read_sites: list[str] = field(default_factory=list)

    def infer_owner_column(self) -> Optional[str]:
        """Best guess at the column naming the owning user, by convention."""
        cols = {c.lower() for c in self.columns}
        for candidate in _OWNER_COLUMN_CANDIDATES:
            if candidate in cols:
                # Return the column in its original casing.
                for c in self.columns:
                    if c.lower() == candidate:
                        return c
        return None

    @property
    def has_select_policy(self) -> bool:
        return any(p.command in ("select", "all") for p in self.policies)

    @property
    def select_policies(self) -> list[Policy]:
        return [p for p in self.policies if p.command in ("select", "all")]


@dataclass
class SupabaseModel:
    tables: dict[str, TableModel] = field(default_factory=dict)

    def table(self, name: str) -> TableModel:
        key = _norm_table(name)
        if key not in self.tables:
            self.tables[key] = TableModel(name=key)
        return self.tables[key]


def _strip_sql_comments(sql: str) -> str:
    """Remove `-- line` and `/* block */` comments so DDL regexes don't match commentary."""
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"--[^\n]*", "", sql)
    return sql


def _norm_table(name: str) -> str:
    """Normalize `public.invoices` / `"invoices"` -> `invoices`."""
    name = name.strip().strip('"').strip("`").strip("'")
    if "." in name:
        name = name.split(".")[-1]
    return name.strip('"')


# --------------------------------------------------------------------------- #
# SQL migration parsing
# --------------------------------------------------------------------------- #
_RE_ENABLE_RLS = re.compile(
    r"alter\s+table\s+(?:only\s+)?([\w\".]+)\s+enable\s+row\s+level\s+security",
    re.I,
)
_RE_POLICY = re.compile(
    r"create\s+policy\s+(?P<name>\"[^\"]+\"|'[^']+'|[\w]+)\s+on\s+(?P<table>[\w\".]+)"
    r"(?P<rest>.*?)(?=;|\Z)",
    re.I | re.S,
)
_RE_FOR = re.compile(r"\bfor\s+(select|insert|update|delete|all)\b", re.I)
_RE_USING = re.compile(r"\busing\s*\((?P<expr>.*?)\)\s*(?:with\s+check|;|\Z)", re.I | re.S)
_RE_WITH_CHECK = re.compile(r"with\s+check\s*\((?P<expr>.*?)\)\s*(?:;|\Z)", re.I | re.S)


def parse_migration_sql(sql: str, source_file: str, model: SupabaseModel) -> None:
    """Fold one SQL file's facts into the model.

    sqlglot reliably recovers CREATE TABLE; RLS-enable and CREATE POLICY are Postgres DDL that
    sqlglot leaves as raw commands, so those are matched with targeted regexes.
    """
    sql = _strip_sql_comments(sql)

    # Declared tables via sqlglot (robust across formatting). CREATE TABLE wraps the table in
    # a Schema node when columns are present, so reach for the Table node rather than `.name`.
    try:
        for stmt in sqlglot.parse(sql, read="postgres"):
            if isinstance(stmt, exp.Create) and (stmt.kind or "").upper() == "TABLE":
                tbl = stmt.find(exp.Table)
                if tbl is not None and tbl.name:
                    tm = model.table(tbl.name)
                    tm.declared = True
                    for col in stmt.find_all(exp.ColumnDef):
                        name = col.this.name if col.this else None
                        if name and name not in tm.columns:
                            tm.columns.append(name)
    except Exception:
        pass  # never let a parse quirk sink the whole audit

    # RLS enable.
    for m in _RE_ENABLE_RLS.finditer(sql):
        model.table(m.group(1)).rls_enabled = True

    # Policies.
    for m in _RE_POLICY.finditer(sql):
        table = m.group("table")
        rest = m.group("rest") or ""
        cmd_m = _RE_FOR.search(rest)
        command = (cmd_m.group(1).lower() if cmd_m else "all")
        using_m = _RE_USING.search(rest) or _RE_WITH_CHECK.search(rest)
        using_expr = (using_m.group("expr").strip() if using_m else "")
        line = sql[: m.start()].count("\n") + 1
        model.table(table).policies.append(
            Policy(
                table=_norm_table(table),
                name=_norm_table(m.group("name")),
                command=command,
                using_expr=using_expr,
                source_file=source_file,
                line=line,
            )
        )


# --------------------------------------------------------------------------- #
# Client read/write discovery
# --------------------------------------------------------------------------- #
def parse_client_file(path: str, source: str, model: SupabaseModel) -> None:
    language = language_for_path(path)
    if language is None:
        return
    try:
        ops = find_supabase_table_ops(source, language)
    except Exception:
        return
    for op in ops:
        tm = model.table(op.table)
        if op.is_read:
            tm.client_read = True
            tm.read_sites.append(f"{path}:{op.line}")
        if op.is_write:
            tm.client_written = True


# --------------------------------------------------------------------------- #
# Repository scan
# --------------------------------------------------------------------------- #
_MIGRATION_GLOBS = [
    "supabase/migrations/*.sql",
    "**/migrations/**/*.sql",
    "**/migrations/*.sql",
    "supabase/*.sql",
]
_CLIENT_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv"}


def build_model(repo_path: str) -> SupabaseModel:
    """Scan a repository and build its Supabase ownership model."""
    root = Path(repo_path)
    model = SupabaseModel()

    seen: set[Path] = set()
    for pattern in _MIGRATION_GLOBS:
        for sql_path in root.glob(pattern):
            if sql_path in seen or not sql_path.is_file():
                continue
            if any(part in _SKIP_DIRS for part in sql_path.parts):
                continue
            seen.add(sql_path)
            try:
                text = sql_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            parse_migration_sql(text, str(sql_path.relative_to(root)), model)

    for client_path in root.rglob("*"):
        if not client_path.is_file() or client_path.suffix not in _CLIENT_EXTS:
            continue
        if any(part in _SKIP_DIRS for part in client_path.parts):
            continue
        try:
            text = client_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "from(" not in text:  # cheap pre-filter
            continue
        parse_client_file(str(client_path.relative_to(root)), text, model)

    return model
