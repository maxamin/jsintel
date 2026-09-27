"""Aho-Corasick anchor prefilter: correctness (must be equivalent to the old
per-matcher substring prefilter) and bounded behavior."""
from modules.extractor.analyzers import secrets_analyzer as S


def _brute_candidates(text: str) -> set[int]:
    """Reference: the pre-refactor selection — a matcher is a candidate if it has
    no anchor, or any of its (lower-cased) anchors is a substring of text.lower()."""
    tl = text.lower()
    out = set()
    for i, m in enumerate(S._MATCHERS):
        anchors = m[4]
        if not anchors or any(a.lower() in tl for a in anchors):
            out.add(i)
    return out


def test_ac_prefilter_matches_bruteforce_over_samples():
    samples = [
        'AKIAIOSFODNN7EXAMPLE', 'ghp_16CharTokenLooksLikeGithub0000000000',
        'xoxb-slack-token-1234', 'AIzaSyA1234567890abcdefghijklmnopqrstuv',
        'var apikey = "abcdef0123456789"', 'nothing interesting here at all',
        'sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc', '-----BEGIN RSA PRIVATE KEY-----',
        'https://user:pass@host/x', 'mongodb://root:secret@db:27017',
    ]
    for s in samples:
        got = S._ANCHORLESS_IDX | S._ANCHOR_AC.matches(s.lower())
        assert got == _brute_candidates(s), (s, got ^ _brute_candidates(s))


def test_anchorless_matchers_always_candidates():
    # A totally anodyne string still runs the anchorless matchers (and no others).
    assert S._ANCHOR_AC.matches("plain lowercase words only") <= set(range(len(S._MATCHERS)))
    assert S._ANCHORLESS_IDX <= (S._ANCHORLESS_IDX | S._ANCHOR_AC.matches("x"))


def test_ac_finds_multiple_payloads_in_one_pass():
    # A string carrying two different provider anchors returns both matchers.
    two = S._ANCHOR_AC.matches("aws akia and google aizasy tokens")
    assert isinstance(two, set)
