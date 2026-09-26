"""The authorization scope -- the gate that keeps requests on authorized hosts."""
from modules.fuzzer.scope import Scope


def test_empty_scope_allows_nothing():
    scope = Scope()
    assert not scope
    assert not scope.allows("https://example.test/x")


def test_exact_host_match():
    scope = Scope(["app.example.test"])
    assert scope.allows("https://app.example.test/api/users")
    assert not scope.allows("https://other.test/api")


def test_subdomains_of_scoped_domain_are_allowed():
    scope = Scope(["example.test"])
    assert scope.allows("https://app.example.test/x")
    assert scope.allows("https://api.dev.example.test/x")
    assert scope.allows("https://example.test/x")


def test_sibling_domain_not_allowed():
    scope = Scope(["example.test"])
    # notexample.test must not be treated as a subdomain of example.test.
    assert not scope.allows("https://notexample.test/x")
    assert not scope.allows("https://example.test.evil.com/x")


def test_parse_accepts_mixed_separators_and_urls():
    scope = Scope.parse("app.example.test, https://api.example.test:8443/base other.test")
    assert scope.hosts == frozenset({"app.example.test", "api.example.test", "other.test"})


def test_port_and_userinfo_are_ignored():
    scope = Scope(["example.test"])
    assert scope.allows("https://user:pass@app.example.test:8443/x")


def test_protocol_relative_urls():
    scope = Scope(["example.test"])
    assert scope.allows("//app.example.test/x")


def test_bare_tld_entry_is_refused():
    # A stray ".com" line strips to "com"; treating it as scope would authorize
    # every .com host, so it must be dropped rather than trusted.
    scope = Scope.parse(".com\n.uk\nexample.test")
    assert scope.hosts == frozenset({"example.test"})
    assert not scope.allows("https://anything.com/x")
    assert not scope.allows("https://foo.uk/x")


def test_leading_dot_domain_is_kept_as_domain():
    # ".example.test" is common "all subdomains" notation and must survive.
    scope = Scope.parse(".example.test")
    assert scope.hosts == frozenset({"example.test"})
    assert scope.allows("https://api.example.test/x")


def test_multi_label_public_suffix_domain_matches_subdomains():
    scope = Scope(["clearpay.co.uk"])
    assert scope.allows("https://portal.clearpay.co.uk/x")
    assert not scope.allows("https://other.co.uk/x")
