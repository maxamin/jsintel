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
    def test_openai_legacy_key(self):
        # `sk-` + 48 chars is OpenAI's legacy secret-key shape.
        tok = "sk-" + "a" * 48
        findings = analyze(SecretsAnalyzer(), f"var key = '{tok}';")
        assert any(
            f.finding_type == "hardcoded_secret" and f.value.startswith("openai-api-key-legacy:")
            for f in findings
        )

    def test_masked_value(self):
        tok = "ghp_" + "A" * 36
        findings = analyze(SecretsAnalyzer(), f"var key = '{tok}';")
        finding = next(f for f in findings if f.finding_type == "hardcoded_secret")
        # First/last few chars shown, middle hidden.
        assert finding.value.endswith("...AAAA")
        assert tok not in finding.value

    def test_high_entropy_requires_nearby_secret_name(self):
        # A high-entropy literal adjacent to a secret-like variable name fires.
        src = "var token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef';"
        findings = analyze(SecretsAnalyzer(), src)
        assert any("high_entropy_secret" in f.value for f in findings)

    def test_minified_line_does_not_leak_secret_context(self):
        # Regression: in a minified single-line bundle the whole file is one
        # physical line. The proximity guard must not treat a secret-like word
        # elsewhere on that line as "near" an unrelated high-entropy literal.
        filler = "x" * 200
        src = f"var token=1;var pad={filler};var q='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef';"
        findings = analyze(SecretsAnalyzer(), src)
        assert not any("high_entropy_secret" in f.value for f in findings)


# Realistic-shaped (but fake) credentials, keyed by the pattern id (label) they
# must be detected under. Spans every category and every structural shape in the
# vendored token set, including the tricky ones (OpenAI infix, Slack variants,
# Discord, Telegram, keyword-gated cloud creds, GCP service-account marker).
_POSITIVE_SECRETS = [
    ("private-key-block", "-----BEGIN RSA PRIVATE KEY-----"),
    ("private-key-block", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJ" + "a" * 18 + "." + "b" * 20),
    ("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
    ("aws-access-key-id", "ASIAY34FZKBOKMUTVV7A"),
    ("google-api-key", "AIza" + "a" * 35),
    ("google-oauth-client-id", "123456789012-" + "a" * 32 + ".apps.googleusercontent.com"),
    ("google-oauth-client-secret", "GOCSPX-" + "a" * 28),
    ("google-oauth-access-token", "ya29." + "a" * 40),
    ("google-oauth-refresh-token", "1//" + "a" * 50),
    ("github-pat-classic", "ghp_" + "a" * 36),
    ("github-pat-fine-grained", "github_pat_" + "a" * 82),
    ("github-oauth-token", "gho_" + "a" * 36),
    ("gitlab-pat", "glpat-" + "a" * 20),
    ("gitlab-oauth-app-secret", "gloas-" + "a" * 64),
    ("gitlab-pipeline-trigger-token", "glptt-" + "a" * 40),
    ("openai-api-key", "sk-proj-" + "a" * 20 + "T3BlbkFJ" + "b" * 20),
    ("openai-api-key-legacy", "sk-" + "a" * 48),
    ("anthropic-api-key", "sk-ant-api03-" + "a" * 93 + "AA"),
    ("anthropic-admin-key", "sk-ant-admin01-" + "a" * 93 + "AA"),
    ("huggingface-token", "hf_" + "a" * 34),
    ("npm-token", "npm_" + "a" * 36),
    ("pypi-token", "pypi-AgEIcHlwaS5vcmc" + "a" * 60),
    ("stripe-secret-key", "sk_live_" + "a" * 24),
    ("stripe-publishable-key", "pk_live_" + "a" * 24),
    ("stripe-webhook-secret", "whsec_" + "a" * 40),
    ("square-access-token", "EAAA" + "a" * 60),
    ("shopify-access-token", "shpat_" + "a" * 32),
    ("slack-bot-token", "xoxb-" + "1" * 12 + "-" + "2" * 12 + "-" + "a" * 30),
    ("slack-user-token", "xoxp-" + "111111111111-" * 3 + "a" * 30),
    ("slack-app-token", "xapp-1-ABC123-1234567890-" + "a" * 60),
    ("slack-webhook-url", "https://hooks.slack.com/services/T00000000/B00000000/" + "a" * 24),
    ("twilio-account-sid", "AC" + "0" * 32),
    ("twilio-api-key-sid", "SK" + "0" * 32),
    ("sendgrid-api-key", "SG." + "a" * 22 + "." + "b" * 43),
    ("mailgun-private-key", "key-" + "0" * 32),
    ("discord-bot-token", "M" + "a" * 24 + "." + "aaaaaa" + "." + "a" * 30),
    ("telegram-bot-token", "12345678:AA" + "a" * 33),
    ("facebook-access-token", "EAA" + "a" * 90),
    ("linear-api-key", "lin_api_" + "a" * 40),
    ("databricks-token", "dapi" + "0" * 32),
    ("digitalocean-pat", "dop_v1_" + "0" * 64),
    ("vercel-access-token", "vcp_" + "a" * 24),
    ("cloudflare-origin-ca-key", "v1.0-" + "0" * 24 + "-" + "0" * 146),
    ("vault-service-token", "hvs." + "a" * 30),
    ("docker-hub-pat", "dckr_pat_" + "a" * 30),
    ("sentry-user-token", "sntryu_" + "0" * 64),
    ("netlify-pat", "nfp_" + "a" * 36),
    ("groq-api-key", "gsk_" + "a" * 40),
    ("openrouter-api-key", "sk-or-v1-" + "a" * 40),
    ("xai-api-key", "xai-" + "a" * 70),
    ("perplexity-api-key", "pplx-" + "a" * 40),
    ("atlassian-api-token", "ATATT3" + "a" * 110),
    ("notion-integration-token", "ntn_" + "a" * 50),
    ("postman-api-key", "PMAK-" + "0" * 24 + "-" + "0" * 34),
    ("rubygems-api-key", "rubygems_" + "0" * 48),
    ("dropbox-access-token", "sl." + "a" * 135),
    ("age-secret-key", "AGE-SECRET-KEY-1" + "Q" * 58),
    ("gcp-service-account-key", '{"type": "service_account", "project_id": "x"}'),
    # keyword-gated (secret sits in a capture group next to the keyword)
    ("aws-secret-access-key", "aws_secret = " + "A" * 40),
    ("heroku-api-key", "heroku apikey 12345678-1234-1234-1234-123456789012"),
    ("cloudflare-api-token", "cloudflare_token=" + "a" * 40),
    ("datadog-api-key", "datadog key " + "0" * 32),
    ("okta-api-token", "okta SSWS 00" + "a" * 40),
    ("mistral-api-key", "mistral key " + "a" * 32),
    ("deepseek-api-key", "deepseek key sk-" + "a" * 30),
    # hand-written extra (not in the vendored set)
    ("credentials-in-url", "https://admin:s3cr3tPass@internal.example.com/api"),
]


class TestSecretPatterns:
    def test_pattern_set_loaded(self):
        # The vendored set (109) minus identifier/encoding (3) plus the one
        # hand-written credentials-in-url pattern.
        from modules.extractor.analyzers.secrets_analyzer import _SECRET_PATTERNS
        assert len(_SECRET_PATTERNS) == 107
        labels = {name for _, name, _, _ in _SECRET_PATTERNS}
        assert "credentials-in-url" in labels
        # identifier/encoding strategies must be excluded.
        assert "twitter-username" not in labels
        assert "base64-string" not in labels

    @pytest.mark.parametrize("label,token", _POSITIVE_SECRETS, ids=[l for l, _ in _POSITIVE_SECRETS])
    def test_pattern_detects(self, label, token):
        findings = analyze(SecretsAnalyzer(), f"var x = 'lead {token} tail';")
        assert any(
            f.finding_type == "hardcoded_secret" and f.value.startswith(f"{label}:")
            for f in findings
        ), f"{label} not detected; got {[f.value for f in findings]}"

    @pytest.mark.parametrize("label,token", _POSITIVE_SECRETS, ids=[l for l, _ in _POSITIVE_SECRETS])
    def test_pattern_masks_secret(self, label, token):
        # The reported value must not contain the full secret body. Structural
        # markers (PEM header, service-account type) carry no key material and
        # are shown intact by design. Keyword-gated patterns embed the secret in
        # a longer literal, so only the captured secret is checked separately.
        markers = {"private-key-block", "gcp-service-account-key"}
        if label in markers:
            return
        findings = analyze(SecretsAnalyzer(), f"var x = '{token}';")
        finding = next(f for f in findings if f.value.startswith(f"{label}:"))
        if len(token) > 12:
            assert token not in finding.value

    def test_all_severities_are_known_levels(self):
        known = {"critical", "high", "medium", "low", "info"}
        src = "; ".join(f"var v{i} = '{tok}'" for i, (_, tok) in enumerate(_POSITIVE_SECRETS))
        findings = analyze(SecretsAnalyzer(), src)
        assert findings
        assert all(f.severity in known for f in findings)

    def test_every_loaded_pattern_is_redos_safe(self):
        # Each pattern must scan large adversarial input in ~linear time. This
        # is the core "valid even in extreme cases" guarantee and runs over the
        # entire ruleset, not a sample.
        import time
        from modules.extractor.analyzers.secrets_analyzer import _SECRET_PATTERNS
        blobs = [
            "A" * 100000,
            "a" * 100000,
            "0" * 100000,
            ("sk-" + "a" * 5) * 10000,
            ("https://" + "a" * 50) * 2000,
            ("eyJ" + "a" * 20 + "." + "b" * 20 + ".") * 3000,
        ]
        for pattern, name, _sev, _grp in _SECRET_PATTERNS:
            for blob in blobs:
                start = time.perf_counter()
                pattern.search(blob)
                elapsed = time.perf_counter() - start
                assert elapsed < 1.0, f"{name} slow ({elapsed:.2f}s): possible ReDoS"

    # --- Boundary / adversarial negatives ---------------------------------

    def test_aws_key_glued_to_more_chars_not_matched(self):
        findings = analyze(SecretsAnalyzer(), "var x = 'AKIAIOSFODNN7EXAMPLE123';")
        assert not any(f.value.startswith("aws-access-key-id:") for f in findings)

    def test_gcp_key_wrong_length_not_matched(self):
        findings = analyze(SecretsAnalyzer(), "var x = 'AIza" + "a" * 36 + "';")
        assert not any(f.value.startswith("google-api-key:") for f in findings)

    def test_short_github_token_not_matched(self):
        findings = analyze(SecretsAnalyzer(), "var x = 'ghp_tooshort';")
        assert not any("github-pat-classic" in f.value for f in findings)

    @pytest.mark.parametrize("bad_jwt", ["eyJ.", "eyJabc.d", "eyJshort.tiny"])
    def test_malformed_jwt_not_matched(self, bad_jwt):
        findings = analyze(SecretsAnalyzer(), f"var x = '{bad_jwt}';")
        assert not any(f.value.startswith("jwt:") for f in findings)

    def test_plain_url_with_port_is_not_credentials(self):
        findings = analyze(SecretsAnalyzer(), "var x = 'https://localhost:8080/path';")
        assert not any("credentials-in-url" in f.value for f in findings)

    def test_bare_hex_without_context_not_flagged(self):
        findings = analyze(SecretsAnalyzer(), "var x = 'd41d8cd98f00b204e9800998ecf8427e';")
        assert not findings

    def test_duplicate_secret_reported_once(self):
        tok = "ghp_" + "a" * 36
        findings = analyze(SecretsAnalyzer(), f"var a = '{tok}'; var b = '{tok}';")
        hits = [f for f in findings if f.value.startswith("github-pat-classic:")]
        assert len(hits) == 1

    def test_unicode_literal_does_not_crash_and_still_matches(self):
        tok = "ghp_" + "a" * 36
        src = f"var x = 'café ☕ {tok}';"
        findings = analyze(SecretsAnalyzer(), src)
        assert any(f.value.startswith("github-pat-classic:") for f in findings)

    def test_no_catastrophic_backtracking_on_large_input(self):
        import time
        blob = ("SG." + "a" * 22 + "." + "b" * 10) * 30000  # ~1.1 MB, no ':'
        src = f"var x = '{blob}';"
        start = time.perf_counter()
        findings = analyze(SecretsAnalyzer(), src)
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"secret scan took {elapsed:.2f}s (possible ReDoS)"
        assert isinstance(findings, list)


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

    def test_endpoint_analyzer_normalizes_template_placeholders(self):
        # Real minified code (e.g. Juice Shop) yields template-literal paths; the
        # ${...} placeholders must collapse to a stable {} token, not leak raw.
        src = "fetch(`/rest/basket/${id}/checkout`); fetch(`/api?module=${a}${b}${c}`);"
        eps = {f.endpoint for f in analyze(EndpointAnalyzer(), src)}
        assert "/rest/basket/{}/checkout" in eps
        assert "/api?module={}" in eps  # consecutive placeholders collapsed
        assert not any("${" in e for e in eps)

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
