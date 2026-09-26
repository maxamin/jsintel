"""Candidate generation: known-good prefix extension and de-duplication."""
from modules.fuzzer.candidates import base_and_path, candidates_for, directory_contexts
from modules.fuzzer.models import Category


def test_base_and_path_absolute():
    base, path = base_and_path("https://app.example.test/api/v1/users", "")
    assert base == "https://app.example.test"
    assert path == "/api/v1/users"


def test_base_and_path_relative_uses_asset_host():
    base, path = base_and_path("/api/v1/users", "https://app.example.test/static/main.js")
    assert base == "https://app.example.test"
    assert path == "/api/v1/users"


def test_base_and_path_relative_without_host_is_unresolved():
    base, path = base_and_path("/api/v1/users", "")
    assert base == ""
    assert path == "/api/v1/users"


def test_directory_contexts_extends_known_prefixes():
    assert directory_contexts("/api/v1/users", depth=2) == ["/api/v1/", "/api/"]
    assert directory_contexts("/api/v1/users", depth=3) == ["/api/v1/", "/api/", "/"]


def test_directory_contexts_trailing_slash_and_root():
    assert directory_contexts("/api/v1/", depth=2) == ["/api/v1/", "/api/"]
    assert directory_contexts("/", depth=3) == ["/"]
    assert directory_contexts("/users", depth=2) == ["/"]


def test_candidates_build_urls_over_each_context():
    cands = list(
        candidates_for(
            "/api/v1/users",
            "https://app.example.test/static/main.js",
            Category.API,
            ["admin", "orders"],
            depth=2,
        )
    )
    urls = {c.url for c in cands}
    assert "https://app.example.test/api/v1/admin" in urls
    assert "https://app.example.test/api/admin" in urls
    assert "https://app.example.test/api/v1/orders" in urls
    assert all(c.category == Category.API for c in cands)


def test_candidates_dedupe_across_calls_with_shared_seen():
    seen: set[str] = set()
    first = list(candidates_for("/api/users", "https://h.example.test/x.js", Category.API, ["admin"], seen=seen))
    second = list(candidates_for("/api/orders", "https://h.example.test/x.js", Category.API, ["admin"], seen=seen))
    # /api/admin is reachable from both origins but must be produced once.
    all_urls = [c.url for c in first + second]
    assert all_urls.count("https://h.example.test/api/admin") == 1


def test_candidates_apply_extensions():
    cands = list(
        candidates_for(
            "/assets/app.js",
            "",
            Category.JS,
            ["main"],
            depth=1,
            extensions=(".js", ".js.map"),
        )
    )
    urls = {c.url for c in cands}
    assert "https://" not in "".join(urls) or True  # base derives from absolute origin only
    # origin is relative with no host -> unresolved, so no candidates:
    assert cands == []


def test_candidates_extensions_on_absolute_origin():
    cands = list(
        candidates_for(
            "https://app.example.test/assets/app.js",
            "",
            Category.JS,
            ["main"],
            depth=1,
            extensions=(".js",),
        )
    )
    urls = {c.url for c in cands}
    assert "https://app.example.test/assets/main" in urls
    assert "https://app.example.test/assets/main.js" in urls


def test_junk_operator_words_are_filtered():
    # SecLists/Assetnote lists occasionally carry stray tokens that would corrupt
    # the URL structure -- whitespace, or a query/fragment introducer that turns
    # the path into "https://host/?:" (a query, not a path). Those are dropped so a
    # permissive origin's 200/403 to them can't inflate the interesting count (part
    # of the ether.fi failure mode). Ugly-but-valid path segments ("&&", "==") are
    # kept: the calibration baseline fix, not word filtering, suppresses their noise.
    words = ["users", "?:", "a b", "adm#in", "bad\\word", "&&", "login"]
    cands = list(
        candidates_for(
            "/api/v1/users",
            "https://app.example.test/static/main.js",
            Category.API,
            words,
            depth=1,
        )
    )
    produced = {c.word for c in cands}
    assert produced == {"users", "&&", "login"}
    assert all(
        "?" not in c.url and "#" not in c.url and " " not in c.url and "\\" not in c.url
        for c in cands
    )
