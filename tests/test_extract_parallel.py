"""Parallel extraction with big-bundle analyzer-splitting must produce results IDENTICAL
to the sequential path (only speed differs), and must split a large bundle into multiple
analyzer-group jobs without duplicating findings."""
import json
from pathlib import Path

from modules.extractor import main as em

_SMALL = 'const K="AKIAIOSFODNN7EXAMPLE{i}"; fetch("/api/v1/u{i}"); eval(x{i}); export const a{i}=1;'


def _make_assets(tmp_path, n_small=16, big_kb=600):
    adir = tmp_path / "assets"
    adir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for i in range(n_small):
        p = adir / f"s{i:03d}.js"
        p.write_text(_SMALL.format(i=i))
        manifest.append({"url": f"http://h/s{i}.js", "type": "javascript",
                         "local_path": str(p), "status": "downloaded"})
    big = adir / "big.js"
    # a genuinely large bundle (> the split threshold) with its own findings
    body = ('function f(){fetch("/api/v1/BIG");eval(zz);}\n'
            'const SECRET="AKIAIOSFODNN7BIGKEYX";\n' + ("var pad=1;\n" * 40000))
    big.write_text(body[: big_kb * 1024] if len(body) > big_kb * 1024 else body)
    manifest.append({"url": "http://h/big.js", "type": "javascript",
                     "local_path": str(big), "status": "downloaded"})
    (tmp_path / "m.json").write_text(json.dumps(manifest))
    return tmp_path / "m.json"


def _report_sets(out: Path) -> dict:
    sets = {}
    for f in sorted(out.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        if isinstance(data, list):
            sets[f.name] = sorted(json.dumps(r, sort_keys=True) for r in data)
    return sets


def test_parallel_split_matches_sequential(tmp_path, monkeypatch):
    manifest = _make_assets(tmp_path)
    assets = list(em.iter_assets(manifest))
    seq_out = tmp_path / "seq"
    par_out = tmp_path / "par"
    seq_out.mkdir()
    par_out.mkdir()
    # sequential baseline
    em._run_sequential(assets, seq_out)
    # parallel WITH big-bundle splitting forced (low threshold so big.js splits)
    monkeypatch.setenv("JSINTEL_SPLIT_BYTES", "100000")
    em._run_parallel(list(em.iter_assets(manifest)), par_out, workers=4)
    seq, par = _report_sets(seq_out), _report_sets(par_out)
    assert seq.keys() == par.keys()
    for name in seq:
        assert par[name] == seq[name], f"report {name} differs between sequential and parallel-split"


def test_big_bundle_is_split_into_multiple_jobs(tmp_path, monkeypatch):
    manifest = _make_assets(tmp_path, n_small=4)
    assets = list(em.iter_assets(manifest))
    monkeypatch.setenv("JSINTEL_SPLIT_BYTES", "100000")
    jobs = em._plan_jobs(assets, workers=4, shard_dir=tmp_path)
    # jobs restricting analyzers (analyzer_ids not None) are the big-bundle split groups
    split_jobs = [j for j in jobs if j[3] is not None]
    assert len(split_jobs) >= 2                       # big.js split across >=2 analyzer groups
    # every split job carries only the one big asset
    assert all(len(j[2]) == 1 and j[2][0][1]["url"] == "http://h/big.js" for j in split_jobs)
    # each analyzer id appears in exactly one group (no duplication)
    from itertools import chain
    ids = list(chain.from_iterable(j[3] for j in split_jobs))
    assert len(ids) == len(set(ids))


def test_no_oversplit_when_many_big_bundles(tmp_path, monkeypatch):
    # Splitting re-parses per group, so blanket-splitting many big bundles is SLOWER.
    # The guard: only split when big bundles are <= half the workers (real spare capacity).
    adir = tmp_path / "assets"
    adir.mkdir()
    manifest = []
    for i in range(12):                              # 12 "big" bundles, all over threshold
        p = adir / f"b{i}.js"
        p.write_text("var x=1;\n" * 30000)
        manifest.append({"url": f"http://h/b{i}.js", "type": "javascript",
                         "local_path": str(p), "status": "downloaded"})
    (tmp_path / "m.json").write_text(json.dumps(manifest))
    assets = list(em.iter_assets(tmp_path / "m.json"))
    monkeypatch.setenv("JSINTEL_SPLIT_BYTES", "100000")
    jobs = em._plan_jobs(assets, workers=4, shard_dir=tmp_path)
    assert all(j[3] is None for j in jobs)           # 12 big > 4//2 -> NO splitting (batched whole)


def test_split_disabled_when_threshold_zero(tmp_path, monkeypatch):
    manifest = _make_assets(tmp_path, n_small=6)
    assets = list(em.iter_assets(manifest))
    monkeypatch.setenv("JSINTEL_SPLIT_BYTES", "0")
    jobs = em._plan_jobs(assets, workers=4, shard_dir=tmp_path)
    assert all(j[3] is None for j in jobs)            # no analyzer-splitting; plain batches
