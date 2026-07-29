PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  local_path TEXT,
  asset_type TEXT NOT NULL,
  sha256 TEXT,
  size_bytes INTEGER,
  mime_type TEXT,
  status TEXT DEFAULT 'discovered',
  discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS urls (
  id INTEGER PRIMARY KEY,
  asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'url',
  UNIQUE(asset_id, url, kind)
);
CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY,
  asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL,
  method TEXT,
  kind TEXT NOT NULL DEFAULT 'api',
  UNIQUE(asset_id, endpoint, kind)
);
CREATE TABLE IF NOT EXISTS technologies (
  id INTEGER PRIMARY KEY,
  asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  evidence TEXT,
  UNIQUE(asset_id, name)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  finding_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  value TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
