from pathlib import Path

from modules.extractor.parser import parse_js, parse_jsx, parse_tsx, parse_typescript

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _has_errors(tree) -> bool:
    if tree is None or not hasattr(tree, "root_node"):
        return True
    for node in tree.root_node.children:
        if getattr(node, "type", None) == "ERROR":
            return True
    return False


class TestParser:
    def test_parse_javascript(self):
        tree = parse_js("const x = 1;")
        assert tree is not None
        assert tree.root_node.type == "program"
        assert not _has_errors(tree)

    def test_parse_jsx(self):
        tree = parse_jsx("const el = <div>hello</div>;")
        assert tree is not None
        assert tree.root_node.type == "program"
        assert not _has_errors(tree)

    def test_parse_typescript(self):
        source = (FIXTURES / "sample.ts").read_text(encoding="utf-8")
        tree = parse_typescript(source)
        assert tree is not None
        assert tree.root_node.type == "program"
        assert not _has_errors(tree)

    def test_parse_tsx(self):
        source = (FIXTURES / "sample.tsx").read_text(encoding="utf-8")
        tree = parse_tsx(source)
        assert tree is not None
        assert tree.root_node.type == "program"
        assert not _has_errors(tree)

    def test_parse_typescript_rejects_javascript_incorrectly(self):
        """TypeScript grammar should still parse plain JS without crashing."""
        tree = parse_typescript("var x = 1;")
        assert tree is not None
        assert tree.root_node.type == "program"

    def test_parse_empty_source_does_not_crash(self):
        tree = parse_js("")
        assert tree is not None
        assert tree.root_node.type == "program"
