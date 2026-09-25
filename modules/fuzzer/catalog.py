"""Mapping from discovered-path category to an Assetnote wordlist.

This is the intelligence the operator asked for: an API endpoint is fuzzed with
an API-route wordlist, a GraphQL endpoint with a GraphQL wordlist, a ``.js`` file
with a JavaScript-filename wordlist, and so on. The lists come from the public
Assetnote collection at https://wordlists.assetnote.io/ (served from the CDN host
below), which ranks entries by how often they occur across the web -- so the
right list for the right find is what makes a hit likely rather than lucky.

Dateless ``manual/`` lists are preferred as defaults because their URLs are
stable. The dated ``automated/`` httparchive lists are richer but their filenames
rotate; a few known snapshots are listed and, if all of them 404, the fuzzer
falls back to the bundled seed for that category. Every URL and filename here can
be overridden by the operator, and nothing is downloaded unless a run actually
uses that category.
"""
from __future__ import annotations

from .models import Category, WordlistSpec

#: Base URL for raw Assetnote wordlist files.
CDN = "https://wordlists-cdn.assetnote.io/data"


def _automated(*names: str) -> tuple[str, ...]:
    return tuple(f"{CDN}/automated/{name}" for name in names)


def _manual(*names: str) -> tuple[str, ...]:
    return tuple(f"{CDN}/manual/{name}" for name in names)


CATALOG: dict[Category, WordlistSpec] = {
    Category.API: WordlistSpec(
        category=Category.API,
        name="assetnote-apiroutes",
        seed="api.txt",
        urls=_automated(
            "httparchive_apiroutes_2024_05_28.txt",
            "httparchive_apiroutes_2023_11_20.txt",
        )
        + _manual("api/api_endpoints.txt"),
        description="High-frequency REST/versioned API route names.",
    ),
    Category.GRAPHQL: WordlistSpec(
        category=Category.GRAPHQL,
        name="assetnote-graphql",
        seed="graphql.txt",
        urls=_manual("graphql.txt"),
        description="Known GraphQL endpoint and tooling paths.",
    ),
    Category.JS: WordlistSpec(
        category=Category.JS,
        name="assetnote-js",
        seed="js.txt",
        urls=_automated(
            "httparchive_js_2024_05_28.txt",
            "httparchive_js_2023_11_20.txt",
        ),
        description="Common JavaScript bundle and source filenames.",
    ),
    Category.FILE: WordlistSpec(
        category=Category.FILE,
        name="assetnote-raft-files",
        seed="files.txt",
        urls=_manual("raft-large-files.txt", "raft-medium-files.txt"),
        description="Interesting file names (config, backup, metadata).",
    ),
    Category.PARAMETER: WordlistSpec(
        category=Category.PARAMETER,
        name="assetnote-parameters",
        seed="parameters.txt",
        urls=_automated(
            "httparchive_parameters_top_1m_2024_05_28.txt",
            "httparchive_parameters_top_1m_2023_11_20.txt",
        ),
        description="High-frequency query parameter names.",
    ),
    Category.DIRECTORY: WordlistSpec(
        category=Category.DIRECTORY,
        name="assetnote-raft-directories",
        seed="directories.txt",
        urls=_manual("raft-large-directories.txt", "raft-medium-directories.txt"),
        description="Common directory names.",
    ),
    Category.GENERIC: WordlistSpec(
        category=Category.GENERIC,
        name="assetnote-raft-words",
        seed="generic.txt",
        urls=_manual("raft-large-words.txt", "raft-medium-words.txt"),
        description="General-purpose content-discovery words.",
    ),
}


def spec_for(category: Category) -> WordlistSpec:
    """Return the wordlist specification for a category (never ``None``)."""
    return CATALOG.get(category, CATALOG[Category.GENERIC])
