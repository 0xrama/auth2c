CREATE TABLE IF NOT EXISTS flows (id TEXT PRIMARY KEY, redirect_uri TEXT NOT NULL, origin TEXT NOT NULL, challenge TEXT NOT NULL, client_state TEXT NOT NULL, request_profile INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS codes (code_hash TEXT PRIMARY KEY, provider_sub TEXT NOT NULL, origin TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, profile TEXT, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS grants (provider_sub TEXT NOT NULL, origin TEXT NOT NULL, profile_allowed INTEGER NOT NULL DEFAULT 0, revoked_at INTEGER, PRIMARY KEY(provider_sub, origin));
CREATE INDEX IF NOT EXISTS grants_origin ON grants(origin);
