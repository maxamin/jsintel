from pathlib import Path

import pytest

from modules.extractor.analyzers.classes_analyzer import ClassesAnalyzer
from modules.extractor.analyzers.cross_asset_analyzer import CrossAssetAnalyzer
from modules.extractor.analyzers.endpoints import EndpointAnalyzer
from modules.extractor.analyzers.exports_analyzer import ExportsAnalyzer
from modules.extractor.analyzers.framework import FrameworkAnalyzer
from modules.extractor.analyzers.imports import ImportAnalyzer
from modules.extractor.analyzers.secrets_analyzer import SecretsAnalyzer
from modules.extractor.analyzers.security_analyzer import SecurityAnalyzer
from modules.extractor.analyzers.taint_analyzer import TaintAnalyzer
from modules.extractor.analyzers.types_analyzer import TypesAnalyzer
from modules.extractor.analyzers.urls import URLAnalyzer
from modules.extractor.analyzers.websocket import WebSocketAnalyzer
from modules.extractor.models import Asset
from modules.extractor.parser import parse_js, parse_tsx, parse_typescript

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def make_asset(url: str = "http://test", asset_type: str = "javascript") -> Asset:
    return Asset(
        url=url,
        asset_type=asset_type,
        local_path=None,
        status="downloaded",
    )


def analyze(analyzer, source: str, *, url: str = "http://test", asset_type: str = "javascript"):
    asset = make_asset(url, asset_type=asset_type)
    if asset_type in ("typescript",):
        tree = parse_typescript(source)
    elif asset_type in ("tsx",):
        tree = parse_tsx(source)
    else:
        tree = parse_js(source)
    if tree is not None:
        asset = Asset(
            url=asset.url,
            asset_type=asset.asset_type,
            local_path=asset.local_path,
            status=asset.status,
            _tree=tree,
        )
    return list(analyzer.analyze(asset, source))


class TestTaintAnalyzer:
    def test_eval_location_href(self):
        findings = analyze(TaintAnalyzer(), "var x = location.href; eval(x);")
        assert any(f.finding_type == "taint_to_sink" for f in findings)

    def test_no_false_positive_on_safe_literal(self):
        findings = analyze(TaintAnalyzer(), 'eval("1+1");')
        assert len(findings) == 0

    def test_taint_propagation(self):
        findings = analyze(TaintAnalyzer(), "var a = location.search; var b = a; fetch(b);")
        assert any(f.finding_type == "taint_to_sink" and f.sink == "fetch" for f in findings)


class TestSecurityAnalyzer:
    def test_eval_detected(self):
        findings = analyze(SecurityAnalyzer(), "eval(userInput);")
        assert any(f.finding_type == "dangerous_eval" for f in findings)

    def test_postmessage_missing_origin(self):
        findings = analyze(
            SecurityAnalyzer(),
            'window.addEventListener("message", function(e) { console.log(e.data) });',
        )
        assert any(f.finding_type == "postmessage_missing_origin" for f in findings)

    def test_postmessage_with_origin_check(self):
        findings = analyze(
            SecurityAnalyzer(),
            "window.addEventListener('message', function(e) { if (e.origin === 'x') console.log(e.data) });",
        )
        assert not any(f.finding_type == "postmessage_missing_origin" for f in findings)

    def test_prototype_pollution(self):
        findings = analyze(SecurityAnalyzer(), "obj[key] = value;")
        assert any(f.finding_type == "prototype_pollution" for f in findings)


class TestSecretsAnalyzer:
    def test_stripe_key(self):
        findings = analyze(SecretsAnalyzer(), "var key = 'sk-abcdefghijklmnopqrstuvwxyz1234';")
        assert any(f.finding_type == "hardcoded_secret" and "stripe_key" in f.value for f in findings)

    def test_masked_value(self):
        findings = analyze(SecretsAnalyzer(), "var key = 'sk-abcdefghijklmnopqrstuvwxyz1234';")
        finding = next(f for f in findings if f.finding_type == "hardcoded_secret")
        assert "sk-a...1234" in finding.value


class TestFixtures:
    def test_dom_xss_fixture(self):
        source = (FIXTURES / "dom_xss.js").read_text(encoding="utf-8")
        findings = analyze(TaintAnalyzer(), source)
        assert any(f.finding_type == "taint_to_sink" for f in findings)

    def test_secrets_fixture(self):
        source = (FIXTURES / "secrets.js").read_text(encoding="utf-8")
        findings = analyze(SecretsAnalyzer(), source)
        assert any(f.finding_type == "hardcoded_secret" for f in findings)


class TestRefactoredAnalyzers:
    def test_url_analyzer(self):
        findings = analyze(URLAnalyzer(), "var u = 'https://example.com/path';")
        assert any(f.url == "https://example.com/path" for f in findings)

    def test_url_analyzer_ignores_comments(self):
        findings = analyze(URLAnalyzer(), "// https://comment.example.com/ignored")
        assert not any("comment.example.com" in f.url for f in findings)

    def test_endpoint_analyzer(self):
        findings = analyze(EndpointAnalyzer(), "fetch('/api/v1/users');")
        assert any(f.endpoint == "/api/v1/users" for f in findings)

    def test_import_analyzer(self):
        findings = analyze(ImportAnalyzer(), 'import React from "react"; const a = require("axios");')
        modules = {f.module for f in findings}
        assert "react" in modules
        assert "axios" in modules

    def test_framework_analyzer(self):
        findings = analyze(FrameworkAnalyzer(), "createApp({});")
        assert any(f.technology == "Vue" for f in findings)

    def test_websocket_analyzer(self):
        findings = analyze(WebSocketAnalyzer(), "new WebSocket('wss://example.com/socket');")
        assert any(f.url == "wss://example.com/socket" for f in findings)


class TestExportsAnalyzer:
    def test_named_export(self):
        findings = analyze(ExportsAnalyzer(), "export function foo() {}")
        assert any(f.finding_type == "export" and "foo" in f.value for f in findings)

    def test_default_export(self):
        findings = analyze(ExportsAnalyzer(), "export default class Bar {}")
        assert any(f.finding_type == "export" and "Bar" in f.value for f in findings)


class TestClassesAnalyzer:
    def test_class_declaration(self):
        findings = analyze(ClassesAnalyzer(), "class UserService {}")
        assert any(f.finding_type == "class" and "UserService" in f.value for f in findings)


class TestTypesAnalyzer:
    def test_api_interface(self):
        findings = analyze(TypesAnalyzer(), "interface UserRequest { id: number; }", asset_type="typescript")
        assert any(f.finding_type == "api_type" and "UserRequest" in f.value for f in findings)

    def test_plain_type_alias(self):
        findings = analyze(TypesAnalyzer(), "type Name = string;", asset_type="typescript")
        assert any(f.finding_type == "type_definition" and "Name" in f.value for f in findings)


class TestCrossAssetAnalyzer:
    def _feed(self, analyzer, url, source, asset_type="javascript"):
        asset = make_asset(url, asset_type=asset_type)
        tree = parse_js(source) if asset_type in ("javascript", "jsx") else parse_typescript(source)
        if tree is not None:
            asset = Asset(
                url=asset.url,
                asset_type=asset.asset_type,
                local_path=asset.local_path,
                status=asset.status,
                _tree=tree,
            )
        list(analyzer.analyze(asset, source))

    def test_cross_asset_dependency(self):
        analyzer = CrossAssetAnalyzer()
        analyzer.initialize()
        self._feed(analyzer, "https://app.example.test/main.js", 'import helper from "./helper.js";')
        self._feed(analyzer, "https://app.example.test/helper.js", "export function helper() {}")
        findings = list(analyzer.finalize())
        assert any(f.finding_type == "cross_asset_dependency" for f in findings)

    def test_cross_asset_call(self):
        analyzer = CrossAssetAnalyzer()
        analyzer.initialize()
        self._feed(analyzer, "https://app.example.test/main.js", 'import { helper } from "./helper.js"; helper();')
        self._feed(analyzer, "https://app.example.test/helper.js", "export function helper() {}")
        findings = list(analyzer.finalize())
        assert any(f.finding_type == "cross_asset_call" for f in findings)
