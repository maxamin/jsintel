-- Additive Phase 2 platform tables. Legacy Phase 1 tables remain untouched.
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  configuration_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_assets (
  scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  PRIMARY KEY (scan_id, asset_id)
);

CREATE TABLE IF NOT EXISTS graph_nodes (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  node_type TEXT NOT NULL,
  natural_key TEXT NOT NULL,
  attributes_json TEXT NOT NULL,
  UNIQUE(scan_id, node_type, natural_key)
);

CREATE TABLE IF NOT EXISTS graph_edges (
  id INTEGER PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
  relationship TEXT NOT NULL,
  target_id TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
  evidence TEXT NOT NULL DEFAULT '',
  UNIQUE(scan_id, source_id, relationship, target_id, evidence)
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(scan_id, source_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(scan_id, target_id);

CREATE TABLE IF NOT EXISTS plugin_runs (
  id INTEGER PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  plugin_id TEXT NOT NULL,
  plugin_version TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TEXT,
  warning_count INTEGER NOT NULL DEFAULT 0
);
