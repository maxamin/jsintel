"""Locally installed (SecLists) wordlist source and its precedence."""
from pathlib import Path

from modules.fuzzer.local import LocalWordlistSource
from modules.fuzzer.models import Category
from modules.fuzzer.wordlists import WordlistProvider


def _fake_seclists(root: Path) -> Path:
    """Create a minimal SecLists Web-Content tree and return its path."""
    web = root / "Discovery" / "Web-Content"
    (web / "api").mkdir(parents=True)
    (web / "raft-large-directories.txt").write_text("admin\ndashboard\ninternal\n", encoding="utf-8")
    (web / "graphql.txt").write_text("graphql\ngraphiql\n", encoding="utf-8")
    (web / "api" / "api-endpoints.txt").write_text("users\norders\npayments\n", encoding="utf-8")
    return web


def test_resolve_returns_existing_file(tmp_path: Path):
    web = _fake_seclists(tmp_path)
    source = LocalWordlistSource(roots=(web,))
    assert source.resolve(Category.DIRECTORY) == web / "raft-large-directories.txt"
    assert source.resolve(Category.GRAPHQL) == web / "graphql.txt"
    assert source.resolve(Category.API) == web / "api" / "api-endpoints.txt"


def test_resolve_none_when_missing(tmp_path: Path):
    source = LocalWordlistSource(roots=(tmp_path / "empty",))
    assert not source.available
    assert source.resolve(Category.API) is None


def test_autodetect_accepts_root_or_web_content(tmp_path: Path):
    _fake_seclists(tmp_path)
    # Pointing at the SecLists root should locate its Web-Content dir.
    source = LocalWordlistSource.autodetect(tmp_path)
    assert source is not None
    assert source.resolve(Category.DIRECTORY) is not None


def test_autodetect_missing_returns_none(tmp_path: Path, monkeypatch):
    # Neutralize the system default so the result does not depend on whether
    # SecLists happens to be installed on the machine running the tests.
    monkeypatch.setattr(
        "modules.fuzzer.local.SECLISTS_WEB_CONTENT", tmp_path / "no-seclists-here"
    )
    assert LocalWordlistSource.autodetect(tmp_path / "nope") is None


def test_overrides_take_precedence(tmp_path: Path):
    web = _fake_seclists(tmp_path)
    custom = tmp_path / "my-api.txt"
    custom.write_text("customendpoint\n", encoding="utf-8")
    source = LocalWordlistSource(roots=(web,), overrides={Category.API: custom})
    assert source.resolve(Category.API) == custom


def test_provider_prefers_local_over_download_and_offline(tmp_path: Path):
    web = _fake_seclists(tmp_path)
    source = LocalWordlistSource(roots=(web,))

    def fail_fetch(url: str) -> bytes:
        raise AssertionError("must not download when local wordlist is present")

    provider = WordlistProvider(
        cache_dir=tmp_path / "cache",
        fetcher=fail_fetch,
        offline=False,
        local=source,
    )
    words = provider.words_for(Category.DIRECTORY, limit=50)
    assert words == ["admin", "dashboard", "internal"]
    assert provider.sources[Category.DIRECTORY].startswith("local:")


def test_provider_falls_back_to_seed_when_local_missing_category(tmp_path: Path):
    web = _fake_seclists(tmp_path)  # has no PARAMETER file
    source = LocalWordlistSource(roots=(web,))
    provider = WordlistProvider(cache_dir=tmp_path / "cache", offline=True, local=source)
    words = provider.words_for(Category.PARAMETER, limit=50)
    assert words  # bundled seed used
    assert provider.sources[Category.PARAMETER] == "seed"


def test_cache_still_wins_over_local(tmp_path: Path):
    web = _fake_seclists(tmp_path)
    cache = tmp_path / "cache"
    cache.mkdir()
    # Pre-seed the cache for the directory category's spec name.
    (cache / "assetnote-raft-directories.txt").write_text("cachedword\n", encoding="utf-8")
    provider = WordlistProvider(cache_dir=cache, offline=True, local=LocalWordlistSource(roots=(web,)))
    assert provider.words_for(Category.DIRECTORY, limit=50) == ["cachedword"]
    assert provider.sources[Category.DIRECTORY].startswith("cache:")
