"""Coverage for the two analyzers that lacked dedicated tests: callgraph and
dependency resolution."""
from modules.extractor.analyzers.callgraph_analyzer import CallGraphAnalyzer
from modules.extractor.analyzers.dependency_analyzer import DependencyAnalyzer
from modules.extractor.models import Asset
from modules.extractor.parser import parse_js


def _run(analyzer, source, url="http://h/app/main.js"):
    asset = Asset(url=url, asset_type="javascript", local_path=None, status="downloaded")
    tree = parse_js(source)
    object.__setattr__(asset, "_tree", tree)
    return list(analyzer.analyze_ast(asset, source, tree))


def test_callgraph_records_caller_callee_edges():
    findings = _run(CallGraphAnalyzer(), "function outer(){ inner(); } topLevel();")
    edges = {f.value.split(" @line")[0] for f in findings}
    assert all(f.finding_type == "call_graph" and f.severity == "info" for f in findings)
    assert "outer -> inner" in edges            # call inside a function scope
    assert "global -> topLevel" in edges        # call at module scope
    # source/sink carry the caller/callee for graph building
    inner = next(f for f in findings if f.sink == "inner")
    assert inner.source == "outer"


def test_callgraph_dedupes_identical_edges():
    # same caller->callee on the same line only recorded once
    f = _run(CallGraphAnalyzer(), "function a(){ b(); b(); }")
    lines = [x.value for x in f if x.sink == "b"]
    assert len(lines) == len(set(lines))


def test_callgraph_regex_fallback_is_silent_without_tree():
    # tree is None -> no AST -> yields nothing (never raises)
    a = Asset(url="http://h/x.js", asset_type="javascript", local_path=None, status="downloaded")
    assert list(CallGraphAnalyzer().analyze_ast(a, "b();", None)) == []


def test_dependency_resolves_relative_specifiers_against_asset_url():
    src = 'import x from "./util.js"; import y from "../lib/y.js"; import React from "react";'
    findings = _run(DependencyAnalyzer(), src, url="http://h/app/main.js")
    modules = {f.module for f in findings}
    assert "http://h/app/util.js" in modules      # ./ resolved against the asset URL
    assert "http://h/lib/y.js" in modules          # ../ climbs a directory
    assert not any("react" in m for m in modules)  # bare specifiers are not resolved


def test_dependency_resolves_dynamic_import():
    findings = _run(DependencyAnalyzer(), 'const m = import("./lazy.js");', url="http://h/a/b.js")
    assert {f.module for f in findings} == {"http://h/a/lazy.js"}
