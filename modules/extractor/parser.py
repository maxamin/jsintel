"""Multi-language parser using tree-sitter with graceful fallback."""
from __future__ import annotations
from typing import Any

try:
    from tree_sitter import Language, Parser, Tree
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
    Tree = Any  # type: ignore


def _make_parser(language_factory: Any) -> Parser | None:
    """Create a Parser for a language factory, returning None on any failure."""
    if not _HAS_TS:
        return None
    try:
        return Parser(Language(language_factory()))
    except Exception:
        return None


class TSParser:
    """Singleton multi-language parser. Returns None on any failure."""

    _instance: TSParser | None = None
    _js: Parser | None = None
    _ts: Parser | None = None
    _tsx: Parser | None = None

    def __new__(cls) -> TSParser:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_parsers()
        return cls._instance

    def _init_parsers(self) -> None:
        if _HAS_TS:
            try:
                import tree_sitter_javascript as ts_js
                self._js = _make_parser(ts_js.language)
            except Exception:
                self._js = None
            try:
                import tree_sitter_typescript as ts_ts
                self._ts = _make_parser(ts_ts.language_typescript)
                self._tsx = _make_parser(ts_ts.language_tsx)
            except Exception:
                self._ts = None
                self._tsx = None
        else:
            self._js = None
            self._ts = None
            self._tsx = None

    def parse(self, source: str, parser: Parser | None) -> Tree | None:
        if parser is None:
            return None
        try:
            return parser.parse(source.encode("utf-8", errors="ignore"))
        except Exception:
            return None

    def parse_js(self, source: str) -> Tree | None:
        return self.parse(source, self._js)

    def parse_typescript(self, source: str) -> Tree | None:
        return self.parse(source, self._ts)

    def parse_tsx(self, source: str) -> Tree | None:
        return self.parse(source, self._tsx)

    def parse_jsx(self, source: str) -> Tree | None:
        """JSX syntax is supported by the JavaScript grammar."""
        return self.parse(source, self._js)


# Backward-compatible alias.
JSParser = TSParser


def parse_js(source: str) -> Tree | None:
    """Convenience function for JavaScript/JSX."""
    return TSParser().parse_js(source)


def parse_typescript(source: str) -> Tree | None:
    """Convenience function for TypeScript."""
    return TSParser().parse_typescript(source)


def parse_tsx(source: str) -> Tree | None:
    """Convenience function for TSX."""
    return TSParser().parse_tsx(source)


def parse_jsx(source: str) -> Tree | None:
    """Convenience function for JSX (uses the JavaScript grammar)."""
    return TSParser().parse_jsx(source)
