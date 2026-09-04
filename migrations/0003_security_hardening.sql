-- 0003_security_hardening.sql
-- Additive security hardening for nonce persistence, atomic callback claims,
-- race-safe authorization-code redemption, and scheduled cleanup.
--
-- All changes are additive (new columns / indexes) so a deployed pre-hardening
-- worker keeps functioning on the older schema until redeployed. Existing
-- in-flight flows created before this migration have a NULL nonce and will be
-- rejected by the nonce check; users simply restart login.

-- ---- flows: persisted OIDC nonce + atomic single-winner callback claim ----
ALTER TABLE flows ADD COLUMN nonce TEXT;
ALTER TABLE flows ADD COLUMN callback_claim_id TEXT;
ALTER TABLE flows ADD COLUMN callback_claimed_at INTEGER;

-- Index for fast lookup of a flow by id during callback, and for cleanup of
-- expired, never-claimed flows.
CREATE INDEX IF NOT EXISTS flows_created_at ON flows(created_at);

-- ---- codes: created_at + expiry indexes for cleanup and atomic redeem ----
ALTER TABLE codes ADD COLUMN created_at INTEGER;
CREATE INDEX IF NOT EXISTS codes_expiry ON codes(expires_at);

-- ---- sessions: active-session lookup + cleanup-friendly indexes ----
-- Primary active-session lookup is by id (PK). These compound indexes support
-- listing active sessions for a provider subject, per-origin revocation, and
-- scheduled cleanup of expired/revoked sessions.
CREATE INDEX IF NOT EXISTS sessions_provider_active
  ON sessions(provider_sub, revoked_at, expires_at);
CREATE INDEX IF NOT EXISTS sessions_origin_active
  ON sessions(origin, revoked_at, expires_at);
CREATE INDEX IF NOT EXISTS sessions_cleanup
  ON sessions(expires_at, revoked_at);

-- ---- grants: account-overview and per-origin revocation lookups ----
CREATE INDEX IF NOT EXISTS grants_provider_active
  ON grants(provider_sub, revoked_at);
