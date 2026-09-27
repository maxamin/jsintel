"""Prober behaviour: scope enforcement, calibration, auto-filter, dry-run."""
from modules.fuzzer.models import Candidate, Category, FuzzConfig
from modules.fuzzer.prober import Prober
from modules.fuzzer.scope import Scope
from modules.fuzzer.transport import Response


class FakeTransport:
    """Deterministic transport: first substring match in ``table`` wins."""

    def __init__(self, table: dict[str, Response], default: Response | None = None):
        self.table = table
        self.default = default or Response(status=404, length=20, words=3)
        self.calls: list[str] = []

    def fetch(self, url, method, timeout, headers, follow_redirects):
        self.calls.append(url)
        for needle, response in self.table.items():
            if needle in url:
                return response
        return self.default


def _candidate(url: str, category: Category = Category.DIRECTORY) -> Candidate:
    return Candidate(url=url, word=url.rsplit("/", 1)[-1], category=category, origin="/x", base="")


def test_hard_404_baseline_then_200_is_interesting():
    transport = FakeTransport({"/admin": Response(status=200, length=500, words=80)})
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1))
    result = prober.probe_all([_candidate("https://a.example.test/admin")])[0]
    assert result.status == 200
    assert result.interesting
    assert result.note == "match"


def test_soft_404_same_length_is_filtered():
    transport = FakeTransport(
        {
            "jsintel-": Response(status=200, length=300, words=50),
            "/admin": Response(status=200, length=300, words=50),
        }
    )
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1))
    result = prober.probe_all([_candidate("https://a.example.test/admin")])[0]
    assert not result.interesting
    assert result.note == "matches-soft-404-baseline"


def test_soft_404_different_length_is_interesting():
    transport = FakeTransport(
        {
            "jsintel-": Response(status=200, length=300, words=50),
            "/admin": Response(status=200, length=9000, words=1200),
        }
    )
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1))
    result = prober.probe_all([_candidate("https://a.example.test/admin")])[0]
    assert result.interesting


def test_filtered_status_is_not_interesting():
    transport = FakeTransport({"/admin": Response(status=404, length=100, words=9)})
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1))
    result = prober.probe_all([_candidate("https://a.example.test/admin")])[0]
    assert not result.interesting
    assert result.note == "filtered-status"


def test_403_is_matched():
    transport = FakeTransport({"/secret": Response(status=403, length=120, words=10)})
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1))
    result = prober.probe_all([_candidate("https://a.example.test/secret")])[0]
    assert result.interesting and result.status == 403


def test_uniform_403_wall_is_filtered_as_catchall():
    # Regression for an ether.fi run where an edge/WAF answered *every* path with
    # an identical 403: the random calibration probe and the candidate both get
    # the same 403/length, so the candidate must be suppressed as a catch-all --
    # not reported as ~11.9k bogus "interesting" 403s.
    transport = FakeTransport(
        {
            "jsintel-": Response(status=403, length=70, words=3),
            "/admin": Response(status=403, length=70, words=3),
        }
    )
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1))
    result = prober.probe_all([_candidate("https://a.example.test/admin")])[0]
    assert not result.interesting
    assert result.note == "matches-catchall-baseline"


def test_403_differing_from_wall_baseline_is_still_interesting():
    # A protected resource that answers 403 with a *different* body than the
    # directory's catch-all 403 is a real signal and must survive the filter.
    transport = FakeTransport(
        {
            "jsintel-": Response(status=403, length=70, words=3),
            "/admin": Response(status=403, length=5000, words=800),
        }
    )
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1))
    result = prober.probe_all([_candidate("https://a.example.test/admin")])[0]
    assert result.interesting and result.status == 403


def test_out_of_scope_candidate_is_never_sent():
    transport = FakeTransport({})
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1))
    result = prober.probe_all([_candidate("https://evil.other.io/admin")])[0]
    assert result.note == "out-of-scope"
    assert transport.calls == []


def test_dry_run_sends_no_requests():
    transport = FakeTransport({})
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(dry_run=True))
    results = prober.probe_all([_candidate("https://a.example.test/admin")])
    assert results[0].note == "dry-run"
    assert transport.calls == []


def test_transport_error_is_recorded_not_interesting():
    transport = FakeTransport({"/admin": Response(status=0, length=0, words=0, error="timeout")})
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1))
    result = prober.probe_all([_candidate("https://a.example.test/admin")])[0]
    assert result.error == "timeout"
    assert not result.interesting


def test_concurrent_path_processes_all_candidates():
    table = {f"/p{i}": Response(status=200, length=100 + i, words=5) for i in range(10)}
    transport = FakeTransport(table)
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=8))
    candidates = [_candidate(f"https://a.example.test/p{i}") for i in range(10)]
    results = prober.probe_all(candidates)
    assert len(results) == 10
    assert {r.url for r in results} == {c.url for c in candidates}


def test_calibration_can_be_disabled():
    transport = FakeTransport({"/admin": Response(status=200, length=300, words=50)})
    prober = Prober(transport, Scope(["example.test"]), FuzzConfig(concurrency=1, calibrate=False))
    prober.probe_all([_candidate("https://a.example.test/admin")])
    # No calibration probe was sent -- only the candidate itself.
    assert all("jsintel-" not in url for url in transport.calls)
