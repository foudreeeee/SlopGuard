"""Optional tree-sitter symbol grounding.

The static symbol check in `verification.py` falls back to a substring test:
if the cited symbol appears anywhere in the file it passes — even if it only
shows up in a comment or a string literal. A hallucinated symbol that happens
to be a common English word slips through that way.

When tree-sitter is installed, this module tightens it: does the symbol appear
as an actual code identifier, not just as text? It parses the file and collects
the identifier tokens, so comments and string contents don't count.

Optional by design. No tree-sitter installed, an unsupported language, or a
parse error -> returns None and the caller keeps its substring behavior. The
project's core stays dependency-free.
"""

from __future__ import annotations

from pathlib import PurePosixPath

# file extension -> tree-sitter-language-pack language name
_LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
}

# Some grammars name their identifier leaves without the "identifier" substring.
_NAME_TYPES = {"name", "constant"}

_MAX_BYTES = 1_000_000  # don't parse huge/minified files; fall back instead


def language_for(path: str) -> str | None:
    return _LANG_BY_EXT.get(PurePosixPath(path).suffix.lower())


def symbol_is_code_identifier(content: str, path: str, symbol: str) -> bool | None:
    """Is `symbol` a code identifier in `content` (not just comment/string text)?

    Returns None when it can't be decided — no tree-sitter, unsupported
    language, oversized file, or a parse error — so the caller falls back.
    """
    language = language_for(path)
    if language is None:
        return None
    raw = content.encode("utf-8", "replace")
    if len(raw) > _MAX_BYTES:
        return None
    try:
        from tree_sitter_language_pack import get_parser

        tree = get_parser(language).parse(raw)
    except Exception:
        return None
    return symbol in _identifiers(tree.root_node, raw)


def _identifiers(root, raw: bytes) -> set[str]:
    found: set[str] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node.child_count == 0:
            if "identifier" in node.type or node.type in _NAME_TYPES:
                text = raw[node.start_byte : node.end_byte]
                found.add(text.decode("utf-8", "replace"))
        else:
            stack.extend(node.children)
    return found
