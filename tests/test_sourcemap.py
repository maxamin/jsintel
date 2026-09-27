"""Source map un-minification: recover + re-scan original sources."""
import json

from modules.extractor.models import Asset
from modules.extractor.analyzers.sourcemap_analyzer import SourceMapAnalyzer


def _map(sources, contents=None, file="app.min.js"):
    d = {"version": 3, "sources": sources, "names": [], "mappings": "", "file": file}
    if contents is not None:
        d["sourcesContent"] = contents
    return json.dumps(d)


def _asset():
    return Asset(url="http://h.test/app.min.js.map", asset_type="source_map",
                 local_path="x", status="downloaded")


def test_lists_source_filenames_even_without_content():
    out = list(SourceMapAnalyzer().analyze(_asset(), _map(["src/a.js", "src/b.js"])))
    vals = {f.to_record().get("value") for f in out}
    assert "source: src/a.js" in vals and "source: src/b.js" in vals


def test_recovers_secret_hidden_by_minification():
    # The key exists only in sourcesContent, not in any shipped bundle.
    content = 'const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";\n'
    out = [f.to_record() for f in SourceMapAnalyzer().analyze(_asset(), _map(["src/config.js"], [content]))]
    secrets = [r for r in out if r.get("finding_type") == "hardcoded_secret"]
    assert secrets, "expected the AWS key recovered from sourcesContent"
    assert any("src/config.js" in (r.get("value") or "") for r in secrets)


def test_recovers_urls_and_endpoints_from_original_source():
    content = 'fetch("https://api.internal.example.test/api/v2/users/1/secrets");\n'
    out = list(SourceMapAnalyzer().analyze(_asset(), _map(["src/api.js"], [content])))
    urls = {f.to_record().get("url") for f in out if f.report == "urls"}
    assert any("api.internal.example.test" in (u or "") for u in urls)


def test_no_sources_content_still_safe():
    out = list(SourceMapAnalyzer().analyze(_asset(), _map(["src/a.js"])))
    # Only the filename finding, no crash, no recovered secrets.
    assert all(f.to_record().get("finding_type") != "hardcoded_secret" for f in out)


def test_malformed_map_is_ignored():
    assert list(SourceMapAnalyzer().analyze(_asset(), "{not json")) == []
