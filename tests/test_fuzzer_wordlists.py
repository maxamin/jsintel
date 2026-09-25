"""Wordlist resolution: cache -> download -> bundled seed, all offline-safe."""
from pathlib import Path

from modules.fuzzer.models import Category
from modules.fuzzer.wordlists import WordlistProvider, _clean_lines


def test_clean_lines_drops_comments_blanks_and_dupes():
    text = "# comment\n\nadmin\n/admin\nadmin\napi users\nvalid\n"
    words = _clean_lines(text, limit=100)
    # "/admin" normalizes to "admin" (dup), "api users" has whitespace (dropped).
    assert words == ["admin", "valid"]


def test_limit_is_respected():
    text = "\n".join(f"w{i}" for i in range(100))
    assert len(_clean_lines(text, limit=10)) == 10


def test_offline_uses_seed(tmp_path: Path):
    provider = WordlistProvider(cache_dir=tmp_path / "cache", offline=True)
    words = provider.words_for(Category.API, limit=50)
    assert "api" in words
    assert "users" in words
    assert not (tmp_path / "cache").exists()  # nothing downloaded or cached


def test_download_is_used_and_cached(tmp_path: Path):
    calls: list[str] = []

    def fake_fetch(url: str) -> bytes:
        calls.append(url)
        return b"downloaded1\ndownloaded2\n"

    cache = tmp_path / "cache"
    provider = WordlistProvider(cache_dir=cache, fetcher=fake_fetch)
    words = provider.words_for(Category.DIRECTORY, limit=50)
    assert words == ["downloaded1", "downloaded2"]
    assert len(calls) == 1
    cached = cache / "assetnote-raft-directories.txt"
    assert cached.is_file()

    # A second provider reads the cache instead of downloading again.
    again = WordlistProvider(cache_dir=cache, fetcher=lambda u: (_ for _ in ()).throw(AssertionError("no download")))
    assert again.words_for(Category.DIRECTORY, limit=50) == ["downloaded1", "downloaded2"]


def test_download_failure_falls_back_to_seed(tmp_path: Path):
    def broken_fetch(url: str) -> bytes:
        raise OSError("network down")

    provider = WordlistProvider(cache_dir=tmp_path / "cache", fetcher=broken_fetch)
    words = provider.words_for(Category.GRAPHQL, limit=50)
    assert "graphql" in words  # seed fallback


def test_memoized_across_calls(tmp_path: Path):
    calls: list[str] = []

    def fake_fetch(url: str) -> bytes:
        calls.append(url)
        return b"a\nb\nc\n"

    provider = WordlistProvider(cache_dir=tmp_path / "cache", fetcher=fake_fetch)
    provider.words_for(Category.API, limit=50)
    provider.words_for(Category.API, limit=50)
    assert len(calls) == 1  # second call served from memo
