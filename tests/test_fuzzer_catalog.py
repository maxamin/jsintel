"""The catalog wiring: every category resolves to a real, seeded wordlist."""
from pathlib import Path

from modules.fuzzer.catalog import CATALOG, spec_for
from modules.fuzzer.models import Category

SEED_DIR = Path(__file__).resolve().parents[1] / "modules" / "fuzzer" / "seeds"


def test_every_category_has_a_spec():
    for category in Category:
        spec = spec_for(category)
        assert spec.category == category
        assert spec.name
        assert spec.seed


def test_every_seed_file_exists_and_has_words():
    for spec in CATALOG.values():
        seed = SEED_DIR / spec.seed
        assert seed.is_file(), f"missing seed for {spec.name}"
        words = [
            line.strip()
            for line in seed.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert words, f"empty seed for {spec.name}"


def test_remote_urls_point_at_assetnote():
    for spec in CATALOG.values():
        for url in spec.urls:
            assert url.startswith("https://wordlists-cdn.assetnote.io/data/")


def test_api_and_graphql_use_dedicated_lists():
    assert "apiroutes" in spec_for(Category.API).urls[0]
    assert spec_for(Category.GRAPHQL).urls[0].endswith("graphql.txt")


def test_unknown_category_falls_back_to_generic():
    # spec_for is total over the enum; the fallback guards future additions.
    assert spec_for(Category.GENERIC).category == Category.GENERIC
