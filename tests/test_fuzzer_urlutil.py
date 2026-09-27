"""fuzzer.urlutil.safe_urlsplit — must parse valid URLs and never raise on the
malformed 'URL-like' junk recon pulls out of JavaScript."""
from modules.fuzzer.urlutil import safe_urlsplit


def test_valid_url_parses_normally():
    r = safe_urlsplit("https://host.test:8080/a/b?q=1#f")
    assert r.scheme == "https" and r.hostname == "host.test"
    assert r.port == 8080 and r.path == "/a/b" and r.query == "q=1"


def test_malformed_ipv6_returns_empty_instead_of_raising():
    # urlsplit() raises ValueError('Invalid IPv6 URL') on an unterminated bracket;
    # safe_urlsplit must swallow it and return an empty result.
    r = safe_urlsplit("http://[oops")
    assert r.scheme == "" and r.netloc == "" and r.path == ""


def test_regex_fragment_does_not_raise():
    # A minifier/regex artifact that is not a URL at all.
    for junk in ("https://(?:[A-Za-z0-9-]+", "//i],[[d,", "${API}/x"):
        r = safe_urlsplit(junk)
        assert isinstance(r.path, str)   # returned a SplitResult, no exception


def test_empty_input():
    r = safe_urlsplit("")
    assert r.scheme == "" and r.netloc == "" and r.path == ""
