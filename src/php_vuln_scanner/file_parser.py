from __future__ import annotations

from tree_sitter import Language, Parser, Query, Tree, Node, QueryCursor
import tree_sitter_php
from pathlib import Path
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

PHP_LANGUAGE = Language(tree_sitter_php.language_php())


@dataclass(frozen=True)
class ParsedFile:
    """Helperclass to work with a parsed file"""

    path: Path
    rel_path: str
    source: bytes
    tree: Tree

    @property
    def root(self) -> Node:
        """Root node of the syntax tree"""
        return self.tree.root_node

    @property
    def has_parse_errors(self) -> bool:
        """if tree-sitter has found syntax errors in the file"""
        return self.root.has_error

    def text(self, node: Node) -> str:
        """The source test of the node"""
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def line(self, node: Node) -> int:
        """start line of a node, starts at 1"""
        return node.start_point[0] + 1

    def column(self, node: Node) -> int:
        """start column of a node, starts at 1"""
        return node.start_point[1] + 1

    def snippet(self, node: Node, max_chars: int = 200) -> str:
        """The complete source lines the node starts on, trimmed for reports"""
        line_start = self.source.rfind(b"\n", 0, node.start_byte) + 1
        line_end = self.source.find(b"\n", node.start_byte)
        if line_end == -1:
            line_end = len(self.source)
        text = self.source[line_start:line_end].decode("utf-8", errors="replace").strip()
        return text[:max_chars] + "…" if len(text) > max_chars else text


class ParsingService:
    """Parses PHP sources and answers tree-sitter queries for modules."""

    def __init__(self) -> None:
        self._parser = Parser(PHP_LANGUAGE)
        self._query_cache: dict[str, Query] = {}

    def parse_source(self, source: bytes, path: Path, rel_path: str) -> ParsedFile:
        """Parse a PHP file from source into a parsed file"""
        return ParsedFile(path=path, rel_path=rel_path, source=source, tree=self._parser.parse(source))

    def parse_file(self, path: Path, scan_root: Path) -> ParsedFile | None:
        """Parse a PHP file by path
        Unreadable files are skipped with a warning
        """
        try:
            source = path.read_bytes()
        except OSError as exc:
            logger.warning("skipping unreadable file %s: %s", path, exc)
            return None
        rel_path = str(path.relative_to(scan_root)) if path != scan_root else path.name
        return self.parse_source(source, path, rel_path)

    def parse_files(self, paths: list[Path], scan_root: Path) -> list[ParsedFile]:
        """Parses many file, skipping the unreadable ones"""
        parsed = (self.parse_file(path, scan_root) for path in paths)
        return [parsed_file for parsed_file in parsed if parsed_file is not None]

    def query(self, query_source: str) -> Query:
        """Compiles a tree-sitter query and caches it for later use"""
        # Try the cache first
        query = self._query_cache.get(query_source)
        if query is None:
            query = Query(PHP_LANGUAGE, query_source)
            self._query_cache[query_source] = query
        return query

    def captures(self, node: Node, query_source: str) -> dict[str, list[Node]]:
        return QueryCursor(self.query(query_source)).captures(node)

    def matches(self, node: Node, query_source: str) -> list[dict[str, list[Node]]]:
        return [capture for _, capture in QueryCursor(self.query(query_source)).matches(node)]
