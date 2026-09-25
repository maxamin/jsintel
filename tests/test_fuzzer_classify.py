"""Path -> wordlist-category classification.

These tests pin the "right wordlist for the right find" mapping, including the
ordering rules where cues could overlap (a ``.js`` file under ``/api`` is JS, a
GraphQL path wins over API markers).
"""
import pytest
from modules.fuzzer.classify import classify_path
from modules.fuzzer.models import Category


@pytest.mark.parametrize(
    "value,expected",
    [
        ("/api/v1/users", Category.API),
        ("/api", Category.API),
        ("/rest/orders", Category.API),
        ("https://app.example.test/v2/accounts", Category.API),
        ("/internal/service/health", Category.API),
        ("/graphql", Category.GRAPHQL),
        ("/api/graphql", Category.GRAPHQL),
        ("/graphiql", Category.GRAPHQL),
        ("/static/main.js", Category.JS),
        ("/assets/app.bundle.mjs", Category.JS),
        ("/vendor.js.map", Category.JS),
        ("/config.json", Category.FILE),
        ("/backup.zip", Category.FILE),
        ("/.env", Category.FILE),
        ("/search?q=test", Category.PARAMETER),
        ("https://app.example.test/list?page=2&sort=asc", Category.PARAMETER),
        ("/admin/", Category.DIRECTORY),
        ("/dashboard", Category.DIRECTORY),
    ],
)
def test_classify(value, expected):
    assert classify_path(value) == expected


def test_js_extension_wins_over_api_marker():
    # A JavaScript bundle that happens to sit under /api is still JS.
    assert classify_path("/api/v1/app.bundle.js") == Category.JS


def test_graphql_wins_over_api_marker():
    assert classify_path("/api/v1/graphql") == Category.GRAPHQL


def test_protocol_relative_and_absolute_agree():
    assert classify_path("//host.example/api/users") == Category.API
    assert classify_path("https://host.example/api/users") == Category.API


def test_empty_is_generic_and_root_is_directory():
    assert classify_path("") == Category.GENERIC
    assert classify_path("/") == Category.DIRECTORY  # root is a directory to fuzz
