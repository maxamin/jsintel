"""Parallel extraction must be output-equivalent to sequential."""
import json, os, collections, multiprocessing
from pathlib import Path
import pytest


def _manifest(tmp, n=16):
    adir = tmp / "assets"; adir.mkdir()
    manifest = []
    for i in range(n):
        p = adir / f"{i:03}_app.js"
        # varied content so multiple analyzers fire (secrets, urls, endpoints, cloud)
        p.write_text(
            f'const k="AKIAIOSFODNN7EXAMPLE"; fetch("/api/v{i%3}/users");'
            f'var u="https://bucket{i}.s3.amazonaws.com/x"; eval("x"+{i});',
            encoding="utf-8")
        manifest.append({"url": f"http://h/{i}.js", "type": "javascript",
                         "local_path": str(p), "status": "downloaded"})
    mpath = tmp / "manifest.json"; mpath.write_text(json.dumps(manifest))
    return mpath


def _reports(d):
    out = {}
    for rep in ("findings", "endpoints", "urls", "frameworks"):
        f = d / f"{rep}.json"
        out[rep] = collections.Counter(
            json.dumps(r, sort_keys=True) for r in json.loads(f.read_text())) if f.exists() else None
    return out


@pytest.mark.skipif("fork" not in multiprocessing.get_all_start_methods(), reason="needs fork")
def test_parallel_equals_sequential(tmp_path, monkeypatch):
    import importlib, modules.extractor.main as m
    manifest = _manifest(tmp_path, 16)
    seq, par = tmp_path / "seq", tmp_path / "par"

    monkeypatch.setenv("JSINTEL_EXTRACT_WORKERS", "1")
    importlib.reload(m); m.run(manifest, seq)          # sequential
    monkeypatch.setenv("JSINTEL_EXTRACT_WORKERS", "4")
    importlib.reload(m); m.run(manifest, par)          # parallel (>=12 assets triggers it)

    assert _reports(seq) == _reports(par)
    importlib.reload(m)  # restore default env-driven state for other tests
