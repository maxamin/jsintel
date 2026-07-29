"""SQLite migration and graph persistence layer used by plugins through ModelSink."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from .models import Model, ScanRun


class MigrationManager:
    """Apply ordered, append-only SQL migrations with transactional bookkeeping."""

    def __init__(self, migrations_path: Path) -> None:
        self._migrations_path = migrations_path

    def apply(self, connection: sqlite3.Connection) -> tuple[str, ...]:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        applied = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
        completed: list[str] = []
        for migration in sorted(self._migrations_path.glob("*.sql")):
            if migration.name in applied:
                continue
            script = migration.read_text(encoding="utf-8")
            with connection:
                connection.executescript(script)
                connection.execute("INSERT INTO schema_migrations(version) VALUES (?)", (migration.name,))
            completed.append(migration.name)
        return tuple(completed)


class KnowledgeGraphStore:
    """SQLite-backed ModelSink with explicit graph traversal support."""

    def __init__(self, connection: sqlite3.Connection, scan: ScanRun) -> None:
        self._connection = connection
        self._scan = scan
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute(
            "INSERT OR IGNORE INTO scan_runs(id,target,configuration_hash,status,started_at) VALUES(?,?,?,?,?)",
            (str(scan.id), scan.target, scan.configuration_hash, scan.status, scan.started_at.isoformat()),
        )

    def store(self, model: Model) -> None:
        attributes = json.dumps(model.to_dict(), sort_keys=True, separators=(",", ":"))
        natural_key = self._natural_key(model)
        self._connection.execute(
            "INSERT INTO graph_nodes(id,scan_id,node_type,natural_key,attributes_json) VALUES(?,?,?,?,?) "
            "ON CONFLICT(scan_id,node_type,natural_key) DO UPDATE SET attributes_json=excluded.attributes_json",
            (str(model.id), str(self._scan.id), type(model).__name__, natural_key, attributes),
        )

    def relate(self, source: Model, relation: str, target: Model, evidence: str = "") -> None:
        self.store(source)
        self.store(target)
        source_id = self._node_id(source)
        target_id = self._node_id(target)
        self._connection.execute(
            "INSERT OR IGNORE INTO graph_edges(scan_id,source_id,relationship,target_id,evidence) VALUES(?,?,?,?,?)",
            (str(self._scan.id), source_id, relation, target_id, evidence),
        )

    def traverse(self, source: Model, max_depth: int = 1) -> tuple[dict[str, str], ...]:
        """Return outbound edges up to max_depth, preserving graph provenance."""
        if max_depth < 1:
            raise ValueError("max_depth must be at least one")
        source_id = self._node_id(source)
        rows = self._connection.execute(
            "WITH RECURSIVE walk(source_id, relationship, target_id, evidence, depth) AS ("
            " SELECT source_id, relationship, target_id, evidence, 1 FROM graph_edges"
            " WHERE scan_id = ? AND source_id = ?"
            " UNION ALL"
            " SELECT edge.source_id, edge.relationship, edge.target_id, edge.evidence, walk.depth + 1"
            " FROM graph_edges edge JOIN walk ON edge.source_id = walk.target_id"
            " WHERE edge.scan_id = ? AND walk.depth < ?"
            ") SELECT source_id, relationship, target_id, evidence, depth FROM walk",
            (str(self._scan.id), source_id, str(self._scan.id), max_depth),
        )
        return tuple({key: str(row[key]) for key in row.keys()} for row in rows)

    def commit(self) -> None:
        self._connection.commit()

    def _node_id(self, model: Model) -> str:
        row = self._connection.execute(
            "SELECT id FROM graph_nodes WHERE scan_id=? AND node_type=? AND natural_key=?",
            (str(self._scan.id), type(model).__name__, self._natural_key(model)),
        ).fetchone()
        if row is None:
            raise RuntimeError("Model was not persisted")
        return str(row[0])

    @staticmethod
    def _natural_key(model: Model) -> str:
        values = model.to_dict()
        values.pop("id", None)
        return json.dumps(values, sort_keys=True, separators=(",", ":"))


def connect(path: Path, migrations_path: Path) -> sqlite3.Connection:
    """Open and migrate a database without exposing SQL to analysis plugins."""
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    # Phase 1 schema is retained as the compatibility base for additive migrations.
    legacy_schema = migrations_path.parent / "schema.sql"
    if legacy_schema.is_file():
        connection.executescript(legacy_schema.read_text(encoding="utf-8"))
    MigrationManager(migrations_path).apply(connection)
    return connection
