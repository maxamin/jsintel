"""Live web-service analyzers: security headers, GraphQL introspection, JWT."""
import base64
import json

from modules import liveanalysis as la


def _types(finding_types):
    return {f["finding_type"] for f in finding_types}


def test_missing_security_headers_flagged():
    out = la.analyze_security_headers("http://h.test/", "http", {}, [])
    t = _types(out)
    assert "missing_security_header" in t   # CSP, XCTO, referrer, permissions
    assert "clickjacking" in t              # no XFO / frame-ancestors
    # Plain HTTP must NOT demand HSTS.
    assert not any("Strict-Transport-Security" in f["sink"] for f in out)


def test_full_headers_are_clean():
    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Strict-Transport-Security": "max-age=63072000",
    }
    out = la.analyze_security_headers("https://h.test/", "https", headers, [])
    # HTTPS with all headers present and no cookies → no findings.
    assert out == []


def test_https_without_hsts_is_flagged_and_banner_disclosure():
    out = la.analyze_security_headers(
        "https://h.test/", "https",
        {"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
         "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
         "Permissions-Policy": "geolocation=()", "Server": "nginx/1.25.3"},
        [],
    )
    assert any(f["sink"] == "Strict-Transport-Security" for f in out)
    assert any(f["finding_type"] == "information_disclosure" and "nginx/1.25.3" in f["value"] for f in out)


def test_insecure_cookie_flags():
    out = la.analyze_security_headers("https://h.test/", "https",
                                      {"Content-Security-Policy": "x", "X-Frame-Options": "DENY",
                                       "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                                       "Permissions-Policy": "x", "Strict-Transport-Security": "max-age=1"},
                                      ["SESSION=abc; Path=/"])
    reasons = {f["value"] for f in out if f["finding_type"] == "insecure_cookie"}
    assert any("HttpOnly" in r for r in reasons)
    assert any("Secure" in r for r in reasons)
    assert any("SameSite" in r for r in reasons)


def test_graphql_introspection_detected():
    body = {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "Mutation"}]}}}
    out = la.analyze_introspection("http://h.test/graphql", body)
    assert len(out) == 1 and out[0]["finding_type"] == "graphql_introspection_enabled"
    assert out[0]["severity"] == "high" and "2 schema types" in out[0]["value"]


def test_graphql_introspection_disabled_or_error_is_silent():
    assert la.analyze_introspection("http://h.test/graphql", {"errors": [{"message": "disabled"}]}) == []
    assert la.analyze_introspection("http://h.test/graphql", {}) == []


def _jwt(alg):
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_jwt_alg_none_is_critical():
    out = la.analyze_jwt("http://h.test/", _jwt("none"))
    assert out and out[0]["finding_type"] == "jwt_alg_none" and out[0]["severity"] == "critical"


def test_jwt_symmetric_alg_is_low():
    out = la.analyze_jwt("http://h.test/", _jwt("HS256"))
    assert out and out[0]["finding_type"] == "jwt_weak_alg" and out[0]["severity"] == "low"


def test_jwt_asymmetric_alg_is_info():
    out = la.analyze_jwt("http://h.test/", _jwt("RS256"))
    assert out and out[0]["finding_type"] == "jwt_exposed" and out[0]["severity"] == "info"


def test_jwt_regex_matches_real_token_shape():
    assert la.JWT_RE.search("cookie=" + _jwt("HS256") + "; Path=/")


def test_run_writes_security_json_and_tolerates_no_ports(tmp_path):
    (tmp_path / "reports").mkdir()
    # No ports.json → no services → empty findings, but the file is written.
    findings = la.run(tmp_path)
    assert findings == []
    assert (tmp_path / "reports" / "security.json").exists()


def test_exposed_openapi_spec_flagged():
    body = '{"openapi":"3.0.0","paths":{"/users":{}}}'
    out = la.analyze_api_doc("http://h/", "http://h/openapi.json", 200, body)
    assert out and out[0]["finding_type"] == "exposed_api_spec" and out[0]["severity"] == "medium"


def test_exposed_swagger_ui_flagged():
    out = la.analyze_api_doc("http://h/", "http://h/ui/", 200, "<html><div id='swagger-ui'></div></html>")
    assert out and out[0]["finding_type"] == "exposed_api_docs"


def test_api_doc_404_or_plain_is_silent():
    assert la.analyze_api_doc("http://h/", "http://h/docs", 404, "openapi") == []
    assert la.analyze_api_doc("http://h/", "http://h/x", 200, "<html>hello</html>") == []


def test_parse_spec_paths_openapi3():
    spec = '{"openapi":"3.0.0","paths":{"/users":{},"/users/{id}":{},"bad":{}}}'
    eps = la.parse_spec_paths(spec, "http://h/")
    got = {e["endpoint"] for e in eps}
    assert "/users" in got and "/users/{id}" in got and "bad" not in got
    assert all(e["asset_url"] == "http://h/" and e["kind"] == "api" for e in eps)


def test_parse_spec_paths_swagger2_basepath():
    spec = '{"swagger":"2.0","basePath":"/api/v1","paths":{"/pets":{}}}'
    assert {e["endpoint"] for e in la.parse_spec_paths(spec, "http://h/")} == {"/api/v1/pets"}


def test_parse_spec_paths_ignores_non_spec():
    assert la.parse_spec_paths("<html>", "http://h/") == []
    assert la.parse_spec_paths('{"no":"paths"}', "http://h/") == []


def test_debug_page_detection():
    for body, ok in [("<h1>Werkzeug Debugger</h1>", True),
                     ("Traceback (most recent call last):", True),
                     ("<html>normal page</html>", False)]:
        out = la.analyze_debug_page("http://h/", 500, body)
        assert bool(out) is ok
        if ok:
            assert out[0]["finding_type"] == "debug_page_exposed" and out[0]["severity"] == "high"


def test_sensitive_file_requires_marker():
    # 200 with the expected marker -> flagged.
    assert la.analyze_sensitive_file("http://h/", "http://h/.git/config", 200, "[core]\n", "high", "[core]")
    # 200 without the marker (soft-404 HTML) -> not flagged.
    assert la.analyze_sensitive_file("http://h/", "http://h/.git/config", 200, "<html>404</html>", "high", "[core]") == []
    # 404 -> not flagged.
    assert la.analyze_sensitive_file("http://h/", "http://h/.env", 404, "", "high", "=") == []


def test_sensitive_file_rejects_html_catchall():
    # A soft-404 that returns a 200 HTML index for a plaintext secret must NOT match,
    # even with an empty marker (the DVWA catch-all case).
    html = "<html><body><div>DVWA</div></body></html>"
    assert la.analyze_sensitive_file("http://h/", "http://h/.env", 200, html, "high", "") == []
    assert la.analyze_sensitive_file("http://h/", "http://h/.svn/entries", 200, html, "high", "") == []
    # A genuine plaintext hit is still flagged.
    assert la.analyze_sensitive_file("http://h/", "http://h/.git/config", 200, "[core]\n\trepo", "high", "[core]")
    # phpinfo IS html, so html_ok=True with a distinctive marker still fires.
    assert la.analyze_sensitive_file("http://h/", "http://h/phpinfo.php", 200,
                                     "<html>phpinfo()</html>", "medium", "phpinfo()", html_ok=True)


def test_debug_page_django_technical_404_marker():
    body = "<h1>Page not found</h1><p>Using the URLconf defined in app.urls</p><p>DEBUG = True</p>"
    out = la.analyze_debug_page("http://h/", 404, body)
    assert out and out[0]["finding_type"] == "debug_page_exposed" and out[0]["severity"] == "high"
