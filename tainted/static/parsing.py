"""tree-sitter driver — the substrate all static analysis reads.

Provides language-agnostic parsing plus a small set of extractors the request plane needs.
The extractors are deliberately narrow: recover facts (which table a `.from()` call reads),
never judge meaning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable, Optional

# Map file extensions to tree-sitter language names.
EXT_LANGUAGE = {
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
}


def language_for_path(path: str) -> Optional[str]:
    for ext, lang in EXT_LANGUAGE.items():
        if path.endswith(ext):
            return lang
    return None


@lru_cache(maxsize=None)
def _get_parser(language: str):
    from tree_sitter_language_pack import get_parser

    return get_parser(language)


def parse(source: str, language: str):
    """Parse source into a tree-sitter tree. Raises if the language is unavailable."""
    parser = _get_parser(language)
    return parser.parse(source.encode("utf-8"))


def node_text(node, source_bytes: bytes) -> str:
    """The source text a node spans."""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def walk(node) -> Iterable:
    """Depth-first over every node in the tree."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


# Internal aliases kept so existing call sites read unchanged.
_node_text = node_text
_walk = walk


def first_string_argument(args_node, source_bytes: bytes) -> Optional[str]:
    """The first string literal in an argument list, unquoted. None when there isn't one."""
    for child in args_node.children:
        if child.type in ("string", "template_string"):
            return _strip_quotes(node_text(child, source_bytes))
    return None


def _strip_quotes(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] in "\"'`" and text[-1] == text[0]:
        return text[1:-1]
    return text


# --------------------------------------------------------------------------- #
# Supabase client table operations
# --------------------------------------------------------------------------- #
_READ_OPS = {"select"}
_WRITE_OPS = {"insert", "update", "delete", "upsert"}


@dataclass
class TableOp:
    """A Supabase client call chain: `supabase.from('t').select()...`."""

    table: str
    ops: list[str] = field(default_factory=list)
    line: int = 0
    snippet: str = ""

    @property
    def is_read(self) -> bool:
        return any(op in _READ_OPS for op in self.ops)

    @property
    def is_write(self) -> bool:
        return any(op in _WRITE_OPS for op in self.ops)


def find_supabase_table_ops(source: str, language: str) -> list[TableOp]:
    """Find every `.from('table')...` chain and classify the operations chained on it.

    Uses tree-sitter to locate the `from(<string>)` calls precisely, then inspects the
    enclosing statement's method names to record select/insert/update/delete/upsert.
    """
    tree = parse(source, language)
    src = source.encode("utf-8")
    results: list[TableOp] = []

    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            continue
        prop = func.child_by_field_name("property")
        if prop is None or _node_text(prop, src) != "from":
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        # First string argument = table name.
        table = None
        for a in args.children:
            if a.type in ("string", "template_string"):
                table = _strip_quotes(_node_text(a, src))
                break
        if not table:
            continue
        stmt = _enclosing_statement(node)
        stmt_text = _node_text(stmt, src)
        ops = _chained_methods(stmt_text)
        results.append(
            TableOp(
                table=table,
                ops=ops,
                line=node.start_point[0] + 1,
                snippet=stmt_text.strip()[:200],
            )
        )
    return results


def _enclosing_statement(node):
    cur = node
    while cur.parent is not None and cur.type not in (
        "expression_statement",
        "variable_declarator",
        "lexical_declaration",
        "return_statement",
        "await_expression",
    ):
        cur = cur.parent
    return cur


def _chained_methods(stmt_text: str) -> list[str]:
    """Recover chained method names by scanning `.name(` occurrences in the statement text."""
    import re

    return re.findall(r"\.\s*([A-Za-z_]\w*)\s*\(", stmt_text)
