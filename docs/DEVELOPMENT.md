# Developer guide

## Local setup

Use a virtual environment and install development dependencies:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e '.[dev]'
pytest
ruff check src tests
mypy src
```

The legacy shell pipeline continues to use `requirements.txt` and is tested
separately through integration fixtures as adapters are introduced.

## Change discipline

Keep each change scoped to one subsystem. Add a regression test and update the
relevant documentation in the same commit. Do not change the `jsintel.sh`
arguments without a compatibility plan.

Generated scan data, archives, virtual environments, and test caches are
ignored by Git. The database is migration-driven: add a new ordered SQL file;
never edit an already-released migration.
