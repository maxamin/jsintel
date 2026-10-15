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


def _fill(n: int, alphabet: str = "0123456789abcdef", seed: int = 7) -> str:
    """Deterministic random-looking filler. Real credentials are random; a body of
    one repeated character is rejected as a data-blob slice by the analyzer."""
    import random
    rng = random.Random(seed * 1000 + n)
    return "".join(rng.choice(alphabet) for _ in range(n))



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

    def test_minified_name_reuse_does_not_cross_functions(self):
        # Regression: a name-only taint map let one function's `t = location.hash`
        # taint every other function's unrelated `t` in a minified bundle.
        src = "function a(){var t=location.hash;return t} function b(t){document.body.innerHTML=t}"
        assert analyze(TaintAnalyzer(), src) == []

    def test_shadowed_parameter_is_not_tainted(self):
        src = "var t = location.search; function f(t){ eval(t); }"
        assert analyze(TaintAnalyzer(), src) == []

    def test_closure_capture_is_tainted(self):
        src = "function f(){ var t = location.hash; return function(){ document.body.innerHTML = t; }; }"
        findings = analyze(TaintAnalyzer(), src)
        assert any(f.sink == "innerHTML" and f.source == "location.hash" for f in findings)

    def test_window_qualified_source(self):
        findings = analyze(TaintAnalyzer(), "var x = window.location.hash; eval(x);")
        assert any(f.source == "window.location.hash" and f.severity == "critical" for f in findings)

    def test_url_property_of_source_is_not_a_source(self):
        assert analyze(TaintAnalyzer(), "var n = location.href.length; eval(n);") == []

    @pytest.mark.parametrize("src", ["var u = location.href; fetch(u);",
                                     "var u = document.URL; a.href = u;",
                                     "var u = location.href; window.open(u);"])
    def test_whole_url_to_navigation_sink_not_flagged(self, src):
        assert analyze(TaintAnalyzer(), src) == []

    def test_local_storage_source_is_second_order(self):
        findings = analyze(TaintAnalyzer(), "var v = localStorage.getItem('k'); el.innerHTML = v;")
        assert [f.severity for f in findings] == ["medium"]
        findings = analyze(TaintAnalyzer(), "var v = localStorage.getItem('k'); fetch(v);")
        assert [f.severity for f in findings] == ["low"]

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
        # The deep-merge / set-path shape: two computed, non-literal hops.
        src = "function merge(t, s) { for (var k in s) for (var j in s[k]) t[k][j] = s[k][j]; }"
        findings = analyze(SecurityAnalyzer(), src)
        assert any(f.finding_type == "prototype_pollution" and f.severity == "low" for f in findings)

    @pytest.mark.parametrize("src", [
        "function f(o, k, v) { o[k] = v; }",                       # single hop: plain map write
        "function f(a, i) { a[i][0] = 1; }",                       # literal inner index
        "function f(m, r, c) { m[r][c] = 0; }".replace("m[r][c] = 0", "m[r][c] = 0; if (r === '__proto__') return"),
        "function f(t, k, j, v) { if (!Object.hasOwn(t, k)) return; t[k][j] = v; }",
        "a[b][c] = d;",                                            # top-level data setup
    ])
    def test_prototype_pollution_negatives(self, src):
        findings = analyze(SecurityAnalyzer(), src)
        assert not any(f.finding_type == "prototype_pollution" for f in findings)

    @pytest.mark.parametrize("src", [
        'Function("return this")();',                 # webpack/core-js globalThis shim
        'var g = Function("r", "regeneratorRuntime = r");',
        'eval("1+1");',
        "eval(`static`);",
        "math.eval(expr);",                            # unrelated method named eval
        "redis.eval(script, 0);",
    ])
    def test_eval_constant_or_method_not_flagged(self, src):
        findings = analyze(SecurityAnalyzer(), src)
        assert not any(f.finding_type == "dangerous_eval" for f in findings)

    @pytest.mark.parametrize("src", ["eval(code);", "window.eval(x);", "Function('a', body);",
                                     "eval(`${x}`);", "new Function(x); Function(x)();"])
    def test_eval_dynamic_flagged_high(self, src):
        findings = analyze(SecurityAnalyzer(), src)
        assert any(f.finding_type == "dangerous_eval" and f.severity == "high" for f in findings)

    def test_postmessage_named_handler_resolved(self):
        src = "function h(e){ document.body.innerHTML = e.data; } window.addEventListener('message', h);"
        findings = analyze(SecurityAnalyzer(), src)
        assert any(f.finding_type == "postmessage_missing_origin" for f in findings)

    @pytest.mark.parametrize("src", [
        "window.addEventListener('message', h);",                                   # unresolvable reference
        "window.addEventListener('message', function(){ ready = true; });",        # never reads the event
        "window.addEventListener('message', function(e){ console.log(e.type); });",  # no payload read
        "window.addEventListener('message', function(e){ if (e.source !== window) return; go(e.data); });",
        "window.addEventListener('message', ({data, origin}) => { if (origin === o) go(data); });",
        "var h = function(e){ if (e.origin !== 'https://a') return; run(e.data); }; window.addEventListener('message', h);",
    ])
    def test_postmessage_negatives(self, src):
        findings = analyze(SecurityAnalyzer(), src)
        assert not any(f.finding_type == "postmessage_missing_origin" for f in findings)


class TestSecretsAnalyzer:
    def test_openai_legacy_key(self):
        # `sk-` + 48 chars is OpenAI's legacy secret-key shape.
        tok = "sk-" + _fill(48)
        findings = analyze(SecretsAnalyzer(), f"var key = '{tok}';")
        assert any(
            f.finding_type == "hardcoded_secret" and f.value.startswith("openai-api-key-legacy:")
            for f in findings
        )

    def test_masked_value(self):
        tok = "ghp_" + _fill(36, "0123456789ABCDEF")
        findings = analyze(SecretsAnalyzer(), f"var key = '{tok}';")
        finding = next(f for f in findings if f.finding_type == "hardcoded_secret")
        # First/last few chars shown, middle hidden.
        assert finding.value.endswith("..." + tok[-4:])
        assert tok not in finding.value

    def test_high_entropy_requires_nearby_secret_name(self):
        # A high-entropy literal adjacent to a secret-like variable name fires.
        src = "var token = 'AB3DEFGH1JKLMN0PQRS7UVWXYZabc9ef';"
        findings = analyze(SecretsAnalyzer(), src)
        assert any("high_entropy_secret" in f.value for f in findings)

    @pytest.mark.parametrize("literal", [
        "w-[200px] h-[10%] md:w-[50%]",                 # tailwind classes
        "${t}/static/[name].[contenthash].js${n}",     # template / path
        "/images/backgrounds/token-hero-2x.svg",       # asset path
        "[[\"auth\",\"secret\"],[\"all\",null]]",        # serialized data
        "https://cdn.example.com/token/abc123def456",  # URL
    ])
    def test_high_entropy_ignores_non_token_shapes(self, literal):
        src = "var token = " + repr(literal) + ";"
        findings = analyze(SecretsAnalyzer(), src)
        assert not any("high_entropy_secret" in f.value for f in findings)

    def test_minified_line_does_not_leak_secret_context(self):
        # Regression: in a minified single-line bundle the whole file is one
        # physical line. The proximity guard must not treat a secret-like word
        # elsewhere on that line as "near" an unrelated high-entropy literal.
        filler = "x" * 200
        src = f"var token=1;var pad={filler};var q='AB3DEFGH1JKLMN0PQRS7UVWXYZabc9ef';"
        findings = analyze(SecretsAnalyzer(), src)
        assert not any("high_entropy_secret" in f.value for f in findings)


# Realistic-shaped (but fake) credentials, keyed by the pattern id (label) they
# must be detected under. Spans every category and every structural shape in the
# vendored token set, including the tricky ones (OpenAI infix, Slack variants,
# Discord, Telegram, keyword-gated cloud creds, GCP service-account marker).
_POSITIVE_SECRETS = [
    ("private-key-block", "-----BEGIN RSA PRIVATE KEY-----"),
    ("private-key-block", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJ" + _fill(18) + "." + _fill(20)),
    ("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
    ("aws-access-key-id", "ASIAY34FZKBOKMUTVV7A"),
    ("google-api-key", "AIza" + _fill(35)),
    ("google-oauth-client-id", "123456789012-" + _fill(32) + ".apps.googleusercontent.com"),
    ("google-oauth-client-secret", "GOCSPX-" + _fill(28)),
    ("google-oauth-access-token", "ya29." + _fill(40)),
    ("google-oauth-refresh-token", "1//" + _fill(50)),
    ("github-pat-classic", "ghp_" + _fill(36)),
    ("github-pat-fine-grained", "github_pat_" + _fill(82)),
    ("github-oauth-token", "gho_" + _fill(36)),
    ("gitlab-pat", "glpat-" + _fill(20)),
    ("gitlab-oauth-app-secret", "gloas-" + _fill(64)),
    ("gitlab-pipeline-trigger-token", "glptt-" + _fill(40)),
    ("openai-api-key", "sk-proj-" + _fill(20) + "T3BlbkFJ" + _fill(20)),
    ("openai-api-key-legacy", "sk-" + _fill(48)),
    ("anthropic-api-key", "sk-ant-api03-" + _fill(93) + "AA"),
    ("anthropic-admin-key", "sk-ant-admin01-" + _fill(93) + "AA"),
    ("huggingface-token", "hf_" + _fill(34)),
    ("npm-token", "npm_" + _fill(36)),
    ("pypi-token", "pypi-AgEIcHlwaS5vcmc" + _fill(60)),
    ("stripe-secret-key", "sk_live_" + _fill(24)),
    ("stripe-publishable-key", "pk_live_" + _fill(24)),
    ("stripe-webhook-secret", "whsec_" + _fill(40)),
    ("square-access-token", "EAAA" + _fill(60)),
    ("shopify-access-token", "shpat_" + _fill(32)),
    ("slack-bot-token", "xoxb-" + _fill(12, "0123456789") + "-" + _fill(12, "0123456789") + "-" + _fill(30)),
    ("slack-user-token", "xoxp-" + (_fill(12, "0123456789") + "-") * 3 + _fill(30)),
    ("slack-app-token", "xapp-1-ABC123-1234567890-" + _fill(60)),
    ("slack-webhook-url", "https://hooks.slack.com/services/T" + _fill(10, "0123456789ABCDEF") + "/B" + _fill(10, "0123456789ABCDEF", 3) + "/" + _fill(24)),
    ("twilio-account-sid", "AC" + _fill(32, "0123456789")),
    ("twilio-api-key-sid", "SK" + _fill(32, "0123456789")),
    ("sendgrid-api-key", "SG." + _fill(22) + "." + _fill(43)),
    ("mailgun-private-key", "key-" + _fill(32, "0123456789")),
    ("discord-bot-token", "M" + _fill(24) + "." + "aaaaaa" + "." + _fill(30)),
    ("telegram-bot-token", "12345678:AA" + _fill(33)),
    ("facebook-access-token", "EAA" + _fill(90)),
    ("linear-api-key", "lin_api_" + _fill(40)),
    ("databricks-token", "dapi" + _fill(32, "0123456789")),
    ("digitalocean-pat", "dop_v1_" + _fill(64, "0123456789")),
    ("vercel-access-token", "vcp_" + _fill(24)),
    ("cloudflare-origin-ca-key", "v1.0-" + _fill(24, "0123456789") + "-" + _fill(146, "0123456789")),
    ("vault-service-token", "hvs." + _fill(30)),
    ("docker-hub-pat", "dckr_pat_" + _fill(30)),
    ("sentry-user-token", "sntryu_" + _fill(64, "0123456789")),
    ("netlify-pat", "nfp_" + _fill(36)),
    ("groq-api-key", "gsk_" + _fill(40)),
    ("openrouter-api-key", "sk-or-v1-" + _fill(40)),
    ("xai-api-key", "xai-" + _fill(70)),
    ("perplexity-api-key", "pplx-" + _fill(40)),
    ("atlassian-api-token", "ATATT3" + _fill(110)),
    ("notion-integration-token", "ntn_" + _fill(50)),
    ("postman-api-key", "PMAK-" + _fill(24, "0123456789") + "-" + _fill(34, "0123456789")),
    ("rubygems-api-key", "rubygems_" + _fill(48, "0123456789")),
    ("dropbox-access-token", "sl." + _fill(135)),
    ("age-secret-key", "AGE-SECRET-KEY-1" + "Q" * 58),
    ("gcp-service-account-key", '{"type": "service_account", "project_id": "x"}'),
    # keyword-gated (secret sits in a capture group next to the keyword)
    # (keyword-gated bodies must be non-degenerate random tokens; see _token_from)
    ("aws-secret-access-key", "aws_secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("heroku-api-key", "heroku apikey 3f9c2a71-8b4e-4d0a-9c6f-1e2d3b4a5c6d"),
    ("cloudflare-api-token", "cloudflare_token=" + "x9Kq2Lm7Vb4Np8Rt1Ws6Yz3Ac5De0Fg_Hj-Ik2Lo"),
    ("datadog-api-key", "datadog key " + "4f8a1c9e2b7d3a6f0e5c8b1d9a2f7e3c"),
    ("okta-api-token", "okta SSWS 00" + "Xk9Lq2Mv7Bn4Rp8Ts1Wd6Yf3Ag5Ch0Ej_Gi-Kl2N"),
    ("mistral-api-key", "mistral key " + "Q7wE2rT9yU4iO1pA6sD3fG8hJ5kL0zXc"),
    ("deepseek-api-key", "deepseek key sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4"),
    # hand-written extra (not in the vendored set)
    ("credentials-in-url", "https://admin:s3cr3tPass@internal.acme-corp.io/api"),
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
        tok = "ghp_" + _fill(36)
        findings = analyze(SecretsAnalyzer(), f"var a = '{tok}'; var b = '{tok}';")
        hits = [f for f in findings if f.value.startswith("github-pat-classic:")]
        assert len(hits) == 1

    def test_unicode_literal_does_not_crash_and_still_matches(self):
        tok = "ghp_" + _fill(36)
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


class TestSecretFalsePositiveRegressions:
    """Regressions from the 2026-10-09 mass sweep, where keyword-gated patterns
    matched slices of identifiers, word lists and base64 blobs."""

    @pytest.mark.parametrize("src", [
        # BIP39 English word list (bundled by every wallet SDK): "Laws" + 40 letters.
        'var w="LatinLaughLaundryLavaLawLawnLawsuitLayerLazyLeaderLeafLearnLeaveLectureLeftLegLegalLegend";',
        # Base64 blob (fonts/wasm) that happens to contain "aws".
        'var b="IcGSkCBAgXOhG7AqMZ4M7awsM0UAPDNAWsC+mcJDe8AAQA99zkEXLICyQozAo6lAobcP5JvjQLFzwKD9gU/OD";',
        # AWS SDK identifiers.
        'var n="AwsQueryProtocolSerializerDeserializerMiddlewareStackResolver";',
        # Degenerate placeholder body.
        'var k="aws_secret_access_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";',
    ])
    def test_aws_secret_not_matched_inside_longer_runs(self, src):
        findings = analyze(SecretsAnalyzer(), src)
        assert not any(f.value.startswith("aws-secret-access-key") for f in findings), findings

    @pytest.mark.parametrize("src", [
        "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_REGION=us-east-1",
    ])
    def test_aws_secret_true_positive(self, src):
        findings = analyze(SecretsAnalyzer(), f"var s = {src!r};")
        assert any(f.value.startswith("aws-secret-access-key") and f.severity == "high" for f in findings)

    def test_public_keys_are_info(self):
        src = "var k='pk_live_" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7" + "';"
        findings = analyze(SecretsAnalyzer(), src)
        assert [f.severity for f in findings if f.value.startswith("stripe-publishable-key")] == ["info"]

    def test_fallback_does_not_scan_code_between_literals(self):
        # No tree: the regex fallback (used for source-map sources and pages)
        # must not treat `" + awsSdkClientIdentityResolverFactoryProvider + "`
        # (the gap between two literals) as a string.
        src = 'x = "a" + awsSdkClientIdentityResolverFactoryProviderRegistry + "bcdef";'
        asset = make_asset(asset_type="source_map")
        findings = list(SecretsAnalyzer().analyze(asset, src))
        assert findings == []

    def test_fallback_still_scans_real_literals(self):
        src = "const a = 'x'; const key = \"ghp_" + "Zx9" * 12 + "\";"
        findings = list(SecretsAnalyzer().analyze(make_asset(asset_type="source_map"), src))
        assert any(f.value.startswith("github") for f in findings)

    @pytest.mark.parametrize("src", [
        # wasm data segment inlined as base64 (checkout.zksync.io): "EAAAA..." + blob
        'c(f,1053444,"EAAAAAMAAAAAAAAAHrLs575K5DXETvj1rGxkdI8Vqj8g33LkqFC68SS1RQTxJiE53JdyZwruIDm47T6rCysw0LYICjcFNCZczokMBi9ob21lL2FubmllLy5jYXJnby9naXQ=");',
        # Flutter/dart2js lookup table (main.dart.js)
        'x._codeUnitAt$1("' + "A" * 130 + "FFFFFFFFFFFFFFFFGGGGGGGGGGGGGGGGHHHHHHHHHHHHHHHHHHHHHHHHHHHIHH" + '");',
        # base64-encoded source that happens to contain IGQ
        '"BdO1xyXG4gICAgbWQgPSAhbWQgIGQinputIGQgZXhwIDSAhbWQgfHwgbi5jb21wYXJlZFRvKGQpID4gMCA/IChlID4gMCA/IGQgOiBuMSkgOiBuO1xyXG5cclxuICAgIGV4cCA9IE1BWF9FWFA7XHJcbiAgICBNQVhfRVhQID0gMSAvIDA7XHJcbiAgICBuID0gbmV3IEJpZ051bWJlcihzKTtcr"',
    ])
    def test_base64_blob_slices_are_not_tokens(self, src):
        findings = analyze(SecretsAnalyzer(), src)
        assert not any(f.finding_type == "hardcoded_secret" and "high_entropy" not in f.value for f in findings), findings

    def test_real_facebook_token_still_detected(self):
        tok = "EAA" + _fill(120, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        findings = analyze(SecretsAnalyzer(), f'var t = "{tok}";')
        assert any(f.value.startswith("facebook-access-token") for f in findings)

    @pytest.mark.parametrize("url", [
        "amqp://user:password@localhost:5672",
        "postgres://app:changeme@db.example.com/x",
        "https://u:${PASSWORD}@registry.acme.io",
        "redis://default:<password>@cache.acme.io:6379",
    ])
    def test_documentation_placeholder_credentials_ignored(self, url):
        findings = analyze(SecretsAnalyzer(), f"var u = '{url}';")
        assert not any(f.value.startswith("credentials-in-url") for f in findings)

    def test_braintree_tokenization_key_is_public(self):
        findings = analyze(SecretsAnalyzer(), "var k='production_ktzp8hfp_49pp2rp4phym7387';")
        assert [f.severity for f in findings if f.value.startswith("braintree")] == ["info"]

    @pytest.mark.parametrize("blob", ['"' + "a" * 2_000_000, "`" + "a\\" * 1_000_000,
                                      '"' + "\\" * 2_000_000, "'\"`" * 300_000])
    def test_fallback_literal_scan_is_bounded(self, blob):
        import time
        start = time.perf_counter()
        list(SecretsAnalyzer().analyze(make_asset(asset_type="source_map"), blob))
        assert time.perf_counter() - start < 10.0
