"""Server-rendered page + tech-fingerprint analyzer layers."""
from modules.extractor.models import Asset
from modules.extractor.analyzers.page_analyzer import PageAnalyzer
from modules.extractor.analyzers.tech_fingerprint import TechFingerprintAnalyzer
from modules.extractor.analyzers.secrets_analyzer import SecretsAnalyzer
from modules.extractor.registry import discover, select

PHP_PAGE = """<html><head><meta name="generator" content="Joomla! 4.2"></head><body>
<a href="/vulnerabilities/sqli/">SQLi</a>
<a href="https://cdn.example.test/lib.js">lib</a>
<a href="mailto:x@y.z">mail</a>
<script>const base="/api/v2/account"; fetch("https://api.example.test/rest/admin");</script>
<form action="/login.php" method="POST"><input name="user"><input name="pass"></form>
<!-- FIXME hardcoded /backup/db.sql -->
</body></html>"""


def _page(url="http://t.test/index.php"):
    return Asset(url=url, asset_type="page", local_path="x", status="downloaded")


def test_page_analyzer_registered_for_page_type():
    ids = [a.id for a in select(discover(), "page")]
    assert "pages" in ids and "tech_fingerprint" in ids and "secrets" in ids


def test_page_extracts_urls_endpoints_forms_comments():
    out = list(PageAnalyzer().analyze(_page(), PHP_PAGE))
    urls = {f.to_record()["url"] for f in out if f.report == "urls"}
    eps = {f.to_record()["endpoint"] for f in out if f.report == "endpoints"}
    finds = {(f.to_record()["finding_type"], f.to_record()["value"]) for f in out if f.report == "findings"}

    assert "https://cdn.example.test/lib.js" in urls
    assert "https://api.example.test/rest/admin" in urls
    assert "/vulnerabilities/sqli/" in eps
    assert "/api/v2/account" in eps
    assert any(k == "form" for f in out if f.report == "endpoints" for k in [f.to_record()["kind"]])
    # mailto: is skipped
    assert not any("mailto" in u for u in urls)
    # form fields and the FIXME comment are captured as informational findings
    assert any(t == "html_form" and "user" in v and "pass" in v for t, v in finds)
    assert any(t == "html_comment" and "backup/db.sql" in v for t, v in finds)


def test_tech_fingerprint_from_extension_and_body():
    php = list(TechFingerprintAnalyzer().analyze(_page("http://t.test/login.php"), PHP_PAGE))
    techs = {f.to_record()["technology"] for f in php}
    assert "PHP" in techs
    assert "Joomla! 4.2" in techs  # meta generator


def test_tech_fingerprint_java_and_aspnet_and_python():
    for url, want in [("http://t/x.jsp", "Java (JSP)"), ("http://t/x.aspx", "ASP.NET"),
                      ("http://t/x.cgi", "CGI"), ("http://t/x.py", "Python (CGI)"),
                      ("http://t/do/thing.do", "Java (Servlet/Struts)")]:
        techs = {f.to_record()["technology"] for f in TechFingerprintAnalyzer().analyze(_page(url), "<html></html>")}
        assert want in techs, (url, techs)


def test_tech_fingerprint_body_markers():
    django = "<input name='csrfmiddlewaretoken' value='x'>"
    techs = {f.to_record()["technology"] for f in TechFingerprintAnalyzer().analyze(_page(), django)}
    assert "Django" in techs


def test_secrets_analyzer_scans_page_bodies():
    # SecretsAnalyzer now supports 'page'; its regex fallback runs when tree is None.
    assert "page" in SecretsAnalyzer.supported_asset_types
    body = '<script>var k="AKIAIOSFODNN7EXAMPLE"; var google="AIzaSyA1234567890abcdefghijklmnopqrstuv";</script>'
    out = list(SecretsAnalyzer().analyze(_page(), body))
    assert any(f.report == "findings" for f in out)
