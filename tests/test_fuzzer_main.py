"""CLI-level tests, focused on the authorization safety gate."""
import json
from pathlib import Path

from modules.fuzzer.main import main


def _seed_reports(output: Path) -> None:
    reports = output / "reports"
    reports.mkdir(parents=True)
    reports.joinpath("endpoints.json").write_text(
        json.dumps(
            [{"asset_url": "https://app.example.test/main.js", "endpoint": "/api/v1/users", "kind": "api"}]
        ),
        encoding="utf-8",
    )
    reports.joinpath("urls.json").write_text("[]", encoding="utf-8")


def test_live_run_without_scope_is_refused(tmp_path: Path):
    _seed_reports(tmp_path)
    assert main(["--output", str(tmp_path)]) == 2
    # Nothing was written because the run was refused before any work.
    assert not (tmp_path / "reports" / "fuzz.json").exists()


def test_missing_reports_dir_is_an_error(tmp_path: Path):
    assert main(["--output", str(tmp_path), "--scope", "example.test"]) == 2


def test_dry_run_without_scope_is_allowed(tmp_path: Path):
    _seed_reports(tmp_path)
    assert main(["--output", str(tmp_path), "--dry-run", "--offline", "--max-words", "3"]) == 0
    report = json.loads((tmp_path / "reports" / "fuzz.json").read_text())
    assert report and all(item["note"] == "dry-run" for item in report)


def test_offline_scoped_dry_run_writes_summary(tmp_path: Path):
    _seed_reports(tmp_path)
    rc = main(
        ["--output", str(tmp_path), "--scope", "app.example.test", "--dry-run", "--offline", "--max-words", "5"]
    )
    assert rc == 0
    summary = json.loads((tmp_path / "reports" / "fuzz_summary.json").read_text())
    assert summary["in_scope_origins"] == 1
    assert summary["candidates"] > 0


def test_scope_from_file(tmp_path: Path):
    _seed_reports(tmp_path)
    scope_file = tmp_path / "domains.txt"
    scope_file.write_text("# comment\napp.example.test\nother.test\n", encoding="utf-8")
    rc = main(
        ["--output", str(tmp_path), "--scope", str(scope_file),
         "--dry-run", "--offline", "--max-words", "5"]
    )
    assert rc == 0
    summary = json.loads((tmp_path / "reports" / "fuzz_summary.json").read_text())
    assert summary["in_scope_origins"] == 1
    assert summary["candidates"] > 0


def test_at_file_scope_reference(tmp_path: Path):
    _seed_reports(tmp_path)
    scope_file = tmp_path / "scope.list"
    scope_file.write_text("app.example.test\n", encoding="utf-8")
    rc = main(
        ["--output", str(tmp_path), "--scope", f"@{scope_file}",
         "--dry-run", "--offline", "--max-words", "3"]
    )
    assert rc == 0
    assert json.loads((tmp_path / "reports" / "fuzz_summary.json").read_text())["in_scope_origins"] == 1


def test_comma_separated_single_scope_value(tmp_path: Path):
    _seed_reports(tmp_path)
    rc = main(
        ["--output", str(tmp_path), "--scope", "app.example.test,other.test",
         "--dry-run", "--offline", "--max-words", "3"]
    )
    assert rc == 0
    assert json.loads((tmp_path / "reports" / "fuzz_summary.json").read_text())["in_scope_origins"] == 1
