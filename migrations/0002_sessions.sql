CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  provider_sub TEXT NOT NULL,
  origin TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_provider ON sessions(provider_sub, expires_at);
