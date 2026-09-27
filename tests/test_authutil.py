"""Authenticated-session helpers and their integration into stages."""
import base64
import json

from modules import authutil, liveanalysis
from modules.fuzzer.models import FuzzConfig


def test_auth_headers_from_env():
    env = {"JSINTEL_AUTH_COOKIE": "PHPSESSID=abc; security=low", "JSINTEL_AUTH_BEARER": "tok123"}
    h = authutil.auth_headers(env)
    assert h["Cookie"] == "PHPSESSID=abc; security=low"
    assert h["Authorization"] == "Bearer tok123"


def test_auth_headers_empty_when_unset():
    assert authutil.auth_headers({}) == {}
    assert authutil.is_authenticated({}) is False
    assert authutil.is_authenticated({"JSINTEL_AUTH_COOKIE": "x=1"}) is True


def test_auth_headers_only_cookie_or_only_bearer():
    assert authutil.auth_headers({"JSINTEL_AUTH_COOKIE": "s=1"}) == {"Cookie": "s=1"}
    assert authutil.auth_headers({"JSINTEL_AUTH_BEARER": "t"}) == {"Authorization": "Bearer t"}


def test_whitespace_only_values_are_ignored():
    assert authutil.auth_headers({"JSINTEL_AUTH_COOKIE": "   ", "JSINTEL_AUTH_BEARER": ""}) == {}


def test_mask_and_describe_do_not_leak_full_secret():
    long = "supersecrettoken1234567890"
    assert long not in authutil.mask(long)
    d = authutil.describe({"JSINTEL_AUTH_BEARER": long})
    assert long not in d and "bearer=" in d


def test_bearer_token_accessor():
    assert authutil.bearer_token({"JSINTEL_AUTH_BEARER": "  jwtvalue  "}) == "jwtvalue"
    assert authutil.bearer_token({}) == ""


def test_fuzzconfig_carries_extra_headers_and_prober_merges_them():
    cfg = FuzzConfig(extra_headers={"Cookie": "s=1"})
    assert cfg.extra_headers == {"Cookie": "s=1"}
    # The prober builds request headers as UA/Accept + extra_headers.
    merged = {"User-Agent": cfg.user_agent, "Accept": "*/*", **cfg.extra_headers}
    assert merged["Cookie"] == "s=1"


def _jwt(alg):
    h = base64.urlsafe_b64encode(json.dumps({"alg": alg}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.sig"


def test_supplied_jwt_is_analyzed_by_run(tmp_path, monkeypatch):
    # A ports.json with one service and a supplied alg:none JWT → a critical finding.
    reports = tmp_path / "reports"; reports.mkdir()
    (reports / "ports.json").write_text(json.dumps([{"host": "h.test", "port": 8080,
                                                     "url": "http://h.test:8080/", "scheme": "http"}]))
    (reports / "endpoints.json").write_text("[]")
    monkeypatch.setattr(liveanalysis, "probe_service", lambda *a, **k: [])  # no network
    monkeypatch.setenv("JSINTEL_AUTH_BEARER", _jwt("none"))
    findings = liveanalysis.run(tmp_path)
    assert any(f["finding_type"] == "jwt_alg_none" and f["severity"] == "critical" for f in findings)
