"""Deterministic fixes: fixes the code alone tells Tainted how to write.

For RLS, that means turning on row-level security and adding an owner-scoped SELECT
policy on `auth.uid()`. The fix is written as a new migration file, so you can review
it before applying it.
"""

from __future__ import annotations

import re

from tainted.fix.paths import safe_segment
from tainted.models import Candidate, FileEdit


# Used when Tainted can't infer the owning column from the schema. Emitting this instead of
# guessing keeps the fix honest: you fill in the real column yourself.
OWNER_PLACEHOLDER = "<owner_column>"


def _owner_column(candidate: Candidate) -> tuple[str, bool]:
    """Return (column, inferred). Falls back to a placeholder you have to fill in."""
    col = candidate.metadata.get("owner_column")
    if col:
        return col, True
    return OWNER_PLACEHOLDER, False


def generate_rls_fix(candidate: Candidate) -> tuple[list[FileEdit], str, bool]:
    """Produce the migration edits, a note for the user, and whether the fix is complete.

    `complete` is False when the owner column had to be left as a placeholder: the shape
    of the fix is right, but it still needs one value only you can supply.
    """
    table = candidate.metadata.get("table", "<table>")
    owner_col, inferred = _owner_column(candidate)
    policy_name = f"{table}_owner_select"

    migration = _migration_sql(table, owner_col, policy_name, candidate)
    edits = [
        FileEdit(
            # The table name came out of the repository; it names a file only as one segment.
            file=f"supabase/migrations/{_stamp()}_tainted_fix_{safe_segment(table)}_rls.sql",
            original="",
            replacement=migration,
            description=(
                f"Turn on row-level security on `{table}` and add an owner-scoped "
                f"SELECT policy on `{owner_col}`."
            ),
        )
    ]
    note = (
        f"Owner column inferred as `{owner_col}`."
        if inferred
        else f"Could not tell which column is the owner. Filled in `{OWNER_PLACEHOLDER}`. Set it before applying."
    )
    return edits, note, inferred


def _migration_sql(
    table: str, owner_col: str, policy_name: str, candidate: Candidate
) -> str:
    existing_policy = candidate.metadata.get("policy")
    lines = [
        f"-- Tainted remediation for `{table}`: {candidate.title}",
        f"alter table public.{table} enable row level security;",
    ]
    if existing_policy:
        # A permissive `true` policy exists. Drop it before installing the scoped one.
        lines.append(f'drop policy if exists "{existing_policy}" on public.{table};')
    lines += [
        f'create policy "{policy_name}"',
        f"  on public.{table} for select",
        f"  using (auth.uid() = {owner_col});",
    ]
    return "\n".join(lines) + "\n"


def _stamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


# --------------------------------------------------------------------------- #
# BOLA — add the missing owner check, in the framework's own syntax
# --------------------------------------------------------------------------- #
def generate_bola_fix(candidate: Candidate) -> tuple[list[FileEdit], str, bool]:
    """Add the clause that checks the owner, in the syntax the framework expects.

    The fix is one clause, but the syntax differs by framework. Tainted matches the
    syntax the query already uses, so the patch is one you can actually apply.
    """
    framework = candidate.metadata.get("framework", "")
    kind = candidate.metadata.get("db_read_kind", "query")
    owner_col, inferred = _owner_column(candidate)
    param = candidate.metadata.get("param", "id")
    table = candidate.metadata.get("table") or "<table>"

    guidance = _bola_snippet(kind, table, param, owner_col)
    edit = FileEdit(
        file=candidate.location.file,
        original=candidate.location.snippet,
        replacement=guidance,
        description=(
            f"Scope the read of `{table}` to the caller by adding `{owner_col}` to the "
            f"query ({framework or kind})."
        ),
    )
    note = (
        f"The read at {candidate.location} checks the record's id but not its owner. "
        + (
            f"Owner column inferred as `{owner_col}`."
            if inferred
            else f"Could not tell which column is the owner. Filled in `{OWNER_PLACEHOLDER}`. "
            f"Set it before applying."
        )
        + " You apply this by hand on purpose. Only the surrounding code knows where the "
        "caller's id comes from, and a wrong guess there produces a patch that runs and "
        "protects nothing."
    )
    return [edit], note, inferred


def _bola_snippet(kind: str, table: str, param: str, owner_col: str) -> str:
    """The corrected read, per client dialect."""
    if kind == "supabase":
        return (
            f"// Scope the read to the caller. Without the second .eq(), any signed-in user\n"
            f"// can read every row just by guessing an id.\n"
            f"const {{ data: {{ user }} }} = await supabase.auth.getUser();\n"
            f"if (!user) return new Response('unauthorized', {{ status: 401 }});\n"
            f"const {{ data }} = await supabase\n"
            f"  .from('{table}')\n"
            f"  .select('*')\n"
            f"  .eq('id', {param})\n"
            f"  .eq('{owner_col}', user.id)   // <-- the missing predicate\n"
            f"  .single();\n"
        )
    if kind == "prisma":
        return (
            f"// Use findFirst, not findUnique, so the owner check can join the query.\n"
            f"// findUnique only accepts unique fields, which is why this bug is so common.\n"
            f"const record = await prisma.{table}.findFirst({{\n"
            f"  where: {{ id: {param}, {owner_col}: req.user.id }},   // <-- owner added\n"
            f"}});\n"
        )
    if kind == "orm":
        return (
            f"# Scope the query to the caller.\n"
            f"record = {table}.query.filter_by(id={param}, {owner_col}=current_user.id).first()\n"
            f"if record is None:\n"
            f"    abort(404)  # 404, not 403. A 403 tells the caller the record exists.\n"
        )
    if kind == "mongo":
        return (
            f"const record = await {table}.findOne({{ _id: {param}, "
            f"{owner_col}: req.user.id }});\n"
        )
    return (
        f"-- Add the owner to the predicate:\n"
        f"select * from {table} where id = :{param} and {owner_col} = :caller_id;\n"
    )


# --------------------------------------------------------------------------- #
# Classic injection: bind the value, or whitelist what can't be bound
# --------------------------------------------------------------------------- #
_ORDER_BY_FIX = """\
// A column name can't be bound as a parameter. That's why dynamic ORDER BY survives an
// otherwise safe codebase. Whitelist the column instead of binding it.
const SORTABLE = { name: 'name', created: 'created_at', amount: 'amount' } as const;
const column = SORTABLE[req.query.sort as keyof typeof SORTABLE] ?? 'created_at';
const direction = req.query.dir === 'asc' ? 'ASC' : 'DESC';
await db.query(`SELECT * FROM items ORDER BY ${column} ${direction}`);
"""

_SQL_FIX = """\
// Bind the value instead of pasting it into the string. The driver escapes a bound value;
// string concatenation can't, no matter how carefully you check the input first.
await db.query('SELECT * FROM items WHERE id = $1', [id]);
"""

_COMMAND_FIX = """\
// Never build a shell string from user input. Pass arguments as a list and skip the shell,
// so there's no character left for an attacker to use.
import { execFile } from 'node:child_process';
execFile('convert', [inputPath, outputPath], (err, stdout) => { /* ... */ });
"""

_TEMPLATE_FIX = """\
# Render a fixed template and pass the user's value as data. render_template_string on user
# input runs whatever code the user sent you.
return render_template('report.html', title=user_title)
"""

# The Python half. Every snippet above is JavaScript, which is wrong for a Flask or FastAPI
# repo — the most common shape of the thing Tainted is pointed at. The advice was already
# right; it just arrived in a language the reader could not paste into their file.
_SQL_FIX_PY = """\
# Bind the value instead of pasting it into the string. The driver escapes a bound value;
# an f-string cannot, no matter how carefully you check the input first.
cur.execute("SELECT * FROM items WHERE id = %s", (item_id,))
"""

_ORDER_BY_FIX_PY = """\
# A column name can't be bound as a parameter. That's why dynamic ORDER BY survives an
# otherwise safe codebase. Whitelist the column instead of binding it.
SORTABLE = {"name": "name", "created": "created_at", "amount": "amount"}
column = SORTABLE.get(request.args.get("sort"), "created_at")
direction = "ASC" if request.args.get("dir") == "asc" else "DESC"
cur.execute(f"SELECT * FROM items ORDER BY {column} {direction}")  # both values are ours
"""

_COMMAND_FIX_PY = """\
# Never build a shell string from user input. Pass arguments as a list and skip the shell,
# so there's no character left for an attacker to use.
import subprocess
subprocess.run(["convert", input_path, output_path], shell=False, check=True)
"""

# Keyed by kind, then by whether the file being fixed is Python.
_INJECTION_SNIPPETS: dict[str, tuple[str, str]] = {
    # kind:        (python,            javascript)
    "order_by": (_ORDER_BY_FIX_PY, _ORDER_BY_FIX),
    "sql": (_SQL_FIX_PY, _SQL_FIX),
    "command": (_COMMAND_FIX_PY, _COMMAND_FIX),
    "template": (_TEMPLATE_FIX, _TEMPLATE_FIX),
}


def _snippet_for(kind: str, file: str) -> str:
    """The remediation for this hole, in the language of the file that has it."""
    python, javascript = _INJECTION_SNIPPETS[kind]
    return python if file.endswith(".py") else javascript


def generate_injection_fix(candidate: Candidate) -> tuple[list[FileEdit], str]:
    """The fix for a classic injection hole, by kind."""
    kind = candidate.metadata.get("kind", "sql")
    snippet = candidate.location.snippet or ""
    file = candidate.location.file or ""
    if kind == "sql" and re.search(r"order\s+by", snippet, re.I):
        replacement, note = _snippet_for("order_by", file), (
            "A dynamic ORDER BY can't be parameterized. Bind the direction and whitelist "
            "the column. This is the injection most likely to survive an ORM-based codebase."
        )
    elif kind == "sql":
        replacement, note = _snippet_for("sql", file), (
            "Replace the pasted-in value with a bound parameter. The fix itself is mechanical. "
            "Check whether the query needed a shape the ORM made awkward, since that's usually "
            "why it was skipped here."
        )
    elif kind == "command":
        replacement, note = _snippet_for("command", file), (
            "Drop the shell. `execFile` or `subprocess.run([...], shell=False)` passes "
            "arguments with no shell to interpret them, so there is nothing to inject into."
        )
    else:
        replacement, note = _snippet_for("template", file), (
            "Render a fixed template and pass the user's value as data. Template injection "
            "runs code, so escaping the input does not fix it. Not compiling it does."
        )

    return [
        FileEdit(
            file=candidate.location.file,
            original=snippet,
            replacement=replacement,
            description=f"Fix the {kind} injection at {candidate.location}.",
        )
    ], note
