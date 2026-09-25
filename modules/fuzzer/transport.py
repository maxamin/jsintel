"""HTTP transport boundary for the prober.

The prober depends only on the small :class:`Transport` protocol, so tests inject
a deterministic in-memory transport and never touch the network, while a real run
uses :class:`UrllibTransport` (standard library only -- no new dependency). A
transport never raises for an HTTP status: a 4xx/5xx is a normal, informative
result, and only transport-level failures populate :attr:`Response.error`.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from http.client import HTTPMessage
from typing import IO, Protocol


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    length: int
    words: int
    redirect: str = ""
    error: str = ""


class Transport(Protocol):
    def fetch(
        self,
        url: str,
        method: str,
        timeout: float,
        headers: dict[str, str],
        follow_redirects: bool,
    ) -> Response:
        ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Capture 3xx responses instead of transparently following them."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


_MAX_BODY = 1_048_576  # Read at most 1 MiB of any response body.


class UrllibTransport:
    """Standard-library HTTP client that reports status without raising."""

    def __init__(self) -> None:
        self._follow = urllib.request.build_opener()
        self._nofollow = urllib.request.build_opener(_NoRedirect())

    def fetch(
        self,
        url: str,
        method: str,
        timeout: float,
        headers: dict[str, str],
        follow_redirects: bool,
    ) -> Response:
        opener = self._follow if follow_redirects else self._nofollow
        request = urllib.request.Request(url, method=method, headers=headers)
        try:
            with opener.open(request, timeout=timeout) as response:
                return self._read(response.getcode(), response, dict(response.headers))
        except urllib.error.HTTPError as error:  # 4xx/5xx are results, not failures.
            headers_map = dict(error.headers) if error.headers else {}
            return self._read(error.code, error, headers_map)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
            return Response(status=0, length=0, words=0, error=str(error))

    @staticmethod
    def _read(status: int, stream: object, headers: dict[str, str]) -> Response:
        redirect = headers.get("Location", "") if 300 <= status < 400 else ""
        try:
            body = stream.read(_MAX_BODY)  # type: ignore[attr-defined]
        except Exception:
            body = b""
        text = body.decode("utf-8", errors="ignore")
        return Response(
            status=status,
            length=len(body),
            words=len(text.split()),
            redirect=redirect,
        )
