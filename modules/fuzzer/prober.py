"""Probe candidate URLs and decide which extensions genuinely exist.

Two things turn raw requests into *high-probability* findings:

* **Scope enforcement.** Every candidate is re-checked against the authorization
  scope immediately before a request; out-of-scope URLs are never sent.
* **Per-directory calibration.** Many servers answer unknown paths with a
  "soft" 200/302 page. Before fuzzing a directory the prober requests a random,
  almost-certainly-absent path and records that baseline fingerprint (status and
  body length). A candidate is reported as *interesting* only when its response
  is in the match set *and* differs from the baseline -- the same auto-filter
  idea ffuf/feroxbuster use to suppress false positives.
* **Repeated-response suppression.** A single up-front baseline cannot see a WAF
  or rate limiter that starts answering mid-scan (a Cloudflare challenge 403 whose
  size drifts by a few bytes per path), nor a catch-all whose calibration probe
  happened to differ. After probing, interesting responses that share one shape --
  the same redirect target, or the same status and near-identical size -- across
  many different words on a host are demoted: a real resource does not answer
  identically to dozens of unrelated names.

Requests run on a bounded thread pool (network I/O bound); an optional per-request
delay throttles load. In ``dry_run`` mode nothing is sent: candidates come back as
planned results, which is what previews and the test-suite exercise.
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from .urlutil import safe_urlsplit

from .models import Candidate, FuzzConfig, ProbeResult
from .scope import Scope
from .transport import Response, Transport

LOGGER = logging.getLogger(__name__)

# How many distinct words may share one response shape on a host before that
# shape is treated as a catch-all/WAF wall rather than discovered content.
REPEAT_THRESHOLD = 10


def _length_tolerance(length: int) -> int:
    return max(16, length // 20)


class _Baseline:
    """A directory's "not found" fingerprint learned from a random probe."""

    __slots__ = ("length", "soft", "status")

    def __init__(self, status: int, length: int) -> None:
        self.status = status
        self.length = length
        # A 2xx/3xx answer to a random path means the server soft-404s.
        self.soft = 200 <= status < 400

    def matches(self, response: Response) -> bool:
        if response.status != self.status:
            return False
        return abs(response.length - self.length) <= _length_tolerance(self.length)


class Prober:
    """Send requests for candidates and classify the responses."""

    def __init__(self, transport: Transport, scope: Scope, config: FuzzConfig) -> None:
        self._transport = transport
        self._scope = scope
        self._config = config
        self._baselines: dict[str, _Baseline | None] = {}
        self._request_lock = Lock()

    # -- public API -------------------------------------------------------
    def probe_all(self, candidates: Iterable[Candidate]) -> list[ProbeResult]:
        """Probe every candidate and return one result each, order-independent."""
        items = list(candidates)
        if self._config.dry_run:
            return [self._planned(candidate) for candidate in items]

        in_scope = [c for c in items if self._scope.allows(c.url)]
        skipped = [
            self._out_of_scope(c) for c in items if not self._scope.allows(c.url)
        ]
        if self._config.calibrate:
            self._calibrate(in_scope)

        results: list[ProbeResult] = []
        workers = min(self._config.concurrency, max(1, len(in_scope)))
        if workers <= 1:
            results = [self._probe_one(candidate) for candidate in in_scope]
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(self._probe_one, in_scope))
        return suppress_repeated(results) + skipped

    # -- calibration ------------------------------------------------------
    def _context_key(self, url: str) -> str:
        parts = safe_urlsplit(url)
        directory = parts.path.rsplit("/", 1)[0] + "/"
        return f"{parts.scheme}://{parts.netloc}{directory}"

    def _calibrate(self, candidates: Iterable[Candidate]) -> None:
        directories = {self._context_key(candidate.url) for candidate in candidates}
        for key in directories:
            probe_url = key + "jsintel-" + uuid.uuid4().hex[:16]
            response = self._send(probe_url)
            if response.error:
                self._baselines[key] = None
                continue
            self._baselines[key] = _Baseline(response.status, response.length)

    # -- per-candidate ----------------------------------------------------
    def _probe_one(self, candidate: Candidate) -> ProbeResult:
        response = self._send(candidate.url)
        if response.error:
            return ProbeResult(
                url=candidate.url,
                category=candidate.category.value,
                origin=candidate.origin,
                word=candidate.word,
                error=response.error,
            )
        interesting, note = self._judge(candidate.url, response)
        return ProbeResult(
            url=candidate.url,
            category=candidate.category.value,
            origin=candidate.origin,
            word=candidate.word,
            status=response.status,
            length=response.length,
            words=response.words,
            redirect=response.redirect,
            interesting=interesting,
            note=note,
        )

    def _judge(self, url: str, response: Response) -> tuple[bool, str]:
        if response.status in self._config.filter_status:
            return False, "filtered-status"
        if response.status not in self._config.match_status:
            return False, "unmatched-status"
        baseline = self._baselines.get(self._context_key(url))
        if baseline is not None and baseline.matches(response):
            # A random, near-certainly-absent path in this directory produced the
            # same status and body size, so this response is the directory's
            # catch-all and carries no discovery signal. Two shapes hit this:
            #   * soft-404s (a 2xx/3xx "not found" page), and
            #   * uniform edge/WAF walls -- e.g. an origin that answers *every*
            #     path with an identical 403/401/500. Restricting suppression to
            #     the 2xx/3xx case let those walls through, which is how a single
            #     ether.fi run reported ~11.9k bogus "interesting" 403s.
            return False, "matches-soft-404-baseline" if baseline.soft else "matches-catchall-baseline"
        return True, "match"

    def _send(self, url: str) -> Response:
        headers = {"User-Agent": self._config.user_agent, "Accept": "*/*",
                   **self._config.extra_headers}
        if self._config.delay > 0:
            with self._request_lock:
                time.sleep(self._config.delay)
        return self._transport.fetch(
            url,
            self._config.methods[0],
            self._config.timeout,
            headers,
            self._config.follow_redirects,
        )

    # -- non-request results ---------------------------------------------
    def _planned(self, candidate: Candidate) -> ProbeResult:
        return ProbeResult(
            url=candidate.url,
            category=candidate.category.value,
            origin=candidate.origin,
            word=candidate.word,
            note="dry-run",
        )

    def _out_of_scope(self, candidate: Candidate) -> ProbeResult:
        return ProbeResult(
            url=candidate.url,
            category=candidate.category.value,
            origin=candidate.origin,
            word=candidate.word,
            note="out-of-scope",
        )


def _shape_groups(results: list[ProbeResult]) -> list[list[int]]:
    """Indices of interesting results grouped by (host, response shape)."""
    by_redirect: dict[tuple[str, int, str], list[int]] = defaultdict(list)
    by_status: dict[tuple[str, int], list[int]] = defaultdict(list)
    for i, result in enumerate(results):
        if not result.interesting:
            continue
        parts = safe_urlsplit(result.url)
        host = parts.netloc
        if 300 <= result.status < 400:
            target = result.redirect.split("?", 1)[0]
            if target.rstrip("/") in (result.url.rstrip("/"), parts.path.rstrip("/")) and target.endswith("/"):
                continue  # slash-append: the directory exists (catch-alls are caught by the baseline)
            if result.word:  # case-insensitive: e.g. GitBook 307s /ADMIN -> /admin
                target = re.sub(re.escape(result.word), "{W}", target, flags=re.I)
            by_redirect[(host, result.status, target)].append(i)
        else:
            by_status[(host, result.status)].append(i)
    groups = list(by_redirect.values())
    for indices in by_status.values():
        indices.sort(key=lambda i: results[i].length)
        cluster = [indices[0]]
        for i in indices[1:]:
            previous = results[cluster[-1]].length
            if results[i].length - previous <= _length_tolerance(previous):
                cluster.append(i)
            else:
                groups.append(cluster)
                cluster = [i]
        groups.append(cluster)
    return groups


def suppress_repeated(results: list[ProbeResult]) -> list[ProbeResult]:
    """Demote interesting results whose response shape repeats across many words."""
    out = list(results)
    for group in _shape_groups(results):
        if len({results[i].word for i in group}) < REPEAT_THRESHOLD:
            continue
        sample = results[group[0]]
        LOGGER.info("Suppressing %d repeated %d responses (~%d bytes) on %s",
                    len(group), sample.status, sample.length, safe_urlsplit(sample.url).netloc)
        for i in group:
            out[i] = replace(results[i], interesting=False, note="repeated-response")
    return out
