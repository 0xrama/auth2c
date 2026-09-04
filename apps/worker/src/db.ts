/**
 * Typed D1 data-access layer.
 *
 * Every statement uses an explicit column list so an additive migration can
 * never change column order and break a deployed statement. Race-sensitive
 * operations (callback claim, code redemption, session creation) use a single
 * linearizing SQL statement with conditional WHERE clauses so that exactly one
 * concurrent caller wins.
 */
import { CODE_TTL_MS, FLOW_TTL_MS, TOKEN_TTL_SECONDS, sha256 } from "@auth2c/protocol";

/** Claimed callbacks are retained for 30 minutes before cleanup may remove them. */
export const CLAIMED_FLOW_TIMEOUT_MS = 30 * 60 * 1000;

/** A login flow row. */
export interface FlowRow {
  id: string;
  redirect_uri: string;
  origin: string;
  challenge: string;
  client_state: string;
  request_profile: number;
  nonce: string | null;
  callback_claim_id: string | null;
  callback_claimed_at: number | null;
  created_at: number;
}

/** An authorization-code row. */
export interface CodeRow {
  code_hash: string;
  provider_sub: string;
  origin: string;
  redirect_uri: string;
  challenge: string;
  profile: string | null;
  expires_at: number;
  created_at: number | null;
}

/** A grant row. */
export interface GrantRow {
  provider_sub: string;
  origin: string;
  profile_allowed: number;
  revoked_at: number | null;
}

/** A session row. */
export interface SessionRow {
  id: string;
  provider_sub: string;
  origin: string;
  created_at: number;
  expires_at: number;
  revoked_at: number | null;
}

/** The columns of a freshly inserted flow, in order. */
const FLOW_COLUMNS =
  "(id, redirect_uri, origin, challenge, client_state, request_profile, nonce, callback_claim_id, callback_claimed_at, created_at)";

/** Injected clock so tests can use deterministic time. */
export type Now = () => number;

/** Result of atomically claiming a flow during callback. */
export type ClaimedFlow =
  | { ok: true; flow: FlowRow }
  | { ok: false; reason: "not_found" | "expired" | "already_claimed" };

/**
 * Insert a new login flow with an explicit column list and persisted nonce.
 */
export async function insertFlow(
  db: D1Database,
  flow: {
    id: string;
    redirect_uri: string;
    origin: string;
    challenge: string;
    client_state: string;
    request_profile: number;
    nonce: string;
    created_at: number;
  },
): Promise<void> {
  await db
    .prepare(`INSERT INTO flows ${FLOW_COLUMNS} VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)`)
    .bind(
      flow.id,
      flow.redirect_uri,
      flow.origin,
      flow.challenge,
      flow.client_state,
      flow.request_profile,
      flow.nonce,
      flow.created_at,
    )
    .run();
}

/**
 * Atomically claim an unexpired, unclaimed flow for callback processing.
 *
 * Uses `UPDATE ... WHERE id=? AND callback_claim_id IS NULL AND created_at>?
 * RETURNING *` so that exactly one concurrent callback can proceed. The claim
 * id makes the claim identifiable for later conditional release/deletion.
 */
export async function claimFlowForCallback(
  db: D1Database,
  flowId: string,
  claimId: string,
  now: number,
): Promise<ClaimedFlow> {
  // First check existence/expiry to distinguish failure reasons (the UPDATE
  // itself cannot tell "missing" from "already claimed").
  const existing = await db
    .prepare("SELECT created_at, callback_claim_id FROM flows WHERE id = ?")
    .bind(flowId)
    .first<{ created_at: number; callback_claim_id: string | null }>();
  if (!existing) return { ok: false, reason: "not_found" };
  if (now - existing.created_at > FLOW_TTL_MS) return { ok: false, reason: "expired" };
  if (existing.callback_claim_id !== null) return { ok: false, reason: "already_claimed" };

  const claimed = await db
    .prepare(
      "UPDATE flows SET callback_claim_id = ?, callback_claimed_at = ? " +
        "WHERE id = ? AND callback_claim_id IS NULL RETURNING *",
    )
    .bind(claimId, now, flowId)
    .first<FlowRow>();
  if (!claimed) return { ok: false, reason: "already_claimed" };
  return { ok: true, flow: claimed };
}

/**
 * Conditionally release a callback claim on transient failure, so the browser
 * may retry. Only releases if the claim id still matches (a concurrent retry
 * may have already replaced it).
 */
export async function releaseFlowClaim(db: D1Database, flowId: string, claimId: string): Promise<void> {
  await db
    .prepare(
      "UPDATE flows SET callback_claim_id = NULL, callback_claimed_at = NULL WHERE id = ? AND callback_claim_id = ?",
    )
    .bind(flowId, claimId)
    .run();
}

/**
 * Delete a flow by id (terminal callback completion/failure).
 */
export async function deleteFlow(db: D1Database, flowId: string): Promise<void> {
  await db.prepare("DELETE FROM flows WHERE id = ?").bind(flowId).run();
}

/**
 * Run the transactional callback batch: reactivate/upsert the grant, insert the
 * one-time code, and delete the claimed flow. All three execute as one D1 batch
 * so no grant or code can survive partial completion.
 */
export async function completeCallbackBatch(
  db: D1Database,
  args: {
    providerSub: string;
    origin: string;
    profileAllowed: number;
    profile: string | null;
    codeHash: string;
    redirectUri: string;
    challenge: string;
    expiresAt: number;
    createdAt: number;
    flowId: string;
    claimId: string;
  },
): Promise<void> {
  // Every write is conditioned on this callback still owning the exact flow
  // claim. If cleanup or another terminal path deleted/replaced the claim before
  // the batch begins, all three statements affect zero rows and no grant/code is
  // minted. D1 executes the batch transactionally, so the flow cannot disappear
  // between these statements.
  const results = await db.batch([
    db
      .prepare(
        "INSERT INTO grants (provider_sub, origin, profile_allowed, revoked_at) " +
          "SELECT ?, ?, ?, NULL " +
          "WHERE EXISTS (SELECT 1 FROM flows WHERE id = ? AND callback_claim_id = ?) " +
          "ON CONFLICT(provider_sub, origin) DO UPDATE SET " +
          "profile_allowed = excluded.profile_allowed, revoked_at = NULL",
      )
      .bind(args.providerSub, args.origin, args.profileAllowed, args.flowId, args.claimId),
    db
      .prepare(
        "INSERT INTO codes (code_hash, provider_sub, origin, redirect_uri, challenge, profile, expires_at, created_at) " +
          "SELECT ?, ?, ?, ?, ?, ?, ?, ? " +
          "WHERE EXISTS (SELECT 1 FROM flows WHERE id = ? AND callback_claim_id = ?)",
      )
      .bind(
        args.codeHash,
        args.providerSub,
        args.origin,
        args.redirectUri,
        args.challenge,
        args.profile,
        args.expiresAt,
        args.createdAt,
        args.flowId,
        args.claimId,
      ),
    db.prepare("DELETE FROM flows WHERE id = ? AND callback_claim_id = ?").bind(args.flowId, args.claimId),
  ]);

  const codeChanges = results[1]?.meta.changes ?? 0;
  const flowDeleteChanges = results[2]?.meta.changes ?? 0;
  if (codeChanges !== 1 || flowDeleteChanges !== 1) {
    throw new Error("Callback claim was lost before completion");
  }
}

/**
 * Atomically redeem an authorization code with a single linearizing statement.
 *
 * `DELETE ... WHERE code_hash=? AND expires_at>? AND redirect_uri=? AND
 * challenge=? RETURNING *` ensures one-time use: the first caller deletes the
 * row and wins; every subsequent caller (and any caller with a wrong verifier
 * or redirect) gets zero rows. Callers treat any zero-row result uniformly as
 * `invalid_grant`.
 */
export async function redeemCode(
  db: D1Database,
  rawCode: string,
  verifier: string,
  redirectUri: string,
  now: number,
): Promise<{ ok: true; row: CodeRow } | { ok: false }> {
  const codeHash = await sha256(rawCode);
  const challenge = await sha256(verifier);
  const row = await db
    .prepare(
      "DELETE FROM codes " +
        "WHERE code_hash = ? AND expires_at > ? AND redirect_uri = ? AND challenge = ? " +
        "RETURNING *",
    )
    .bind(codeHash, now, redirectUri, challenge)
    .first<CodeRow>();
  if (!row) return { ok: false };
  return { ok: true, row };
}

/**
 * Create a session only if an active (non-revoked) grant exists for the same
 * provider/origin. Uses `INSERT ... SELECT ... WHERE EXISTS(...) RETURNING id`
 * so revocation either prevents insertion or subsequently revokes the inserted
 * session — closing the redemption/grant-revocation race.
 *
 * Returns the new session id, or null if no active grant existed.
 */
export async function insertSessionIfGrantActive(
  db: D1Database,
  args: {
    sessionId: string;
    providerSub: string;
    origin: string;
    now: number;
  },
): Promise<string | null> {
  const expiresAt = (Math.floor(args.now / 1000) + TOKEN_TTL_SECONDS) * 1000;
  const row = await db
    .prepare(
      "INSERT INTO sessions (id, provider_sub, origin, created_at, expires_at, revoked_at) " +
        "SELECT ?, ?, ?, ?, ?, NULL " +
        "WHERE EXISTS (SELECT 1 FROM grants WHERE provider_sub = ? AND origin = ? AND revoked_at IS NULL) " +
        "RETURNING id",
    )
    .bind(args.sessionId, args.providerSub, args.origin, args.now, expiresAt, args.providerSub, args.origin)
    .first<{ id: string }>();
  return row?.id ?? null;
}

/**
 * Load an active (unexpired, unrevoked) session by id.
 */
export async function getActiveSession(db: D1Database, sessionId: string, now: number): Promise<SessionRow | null> {
  return db
    .prepare("SELECT * FROM sessions WHERE id = ? AND revoked_at IS NULL AND expires_at > ?")
    .bind(sessionId, now)
    .first<SessionRow>();
}

/**
 * Load the active grant for a provider/origin, or null if none/revoked.
 */
export async function getActiveGrant(db: D1Database, providerSub: string, origin: string): Promise<GrantRow | null> {
  return db
    .prepare("SELECT * FROM grants WHERE provider_sub = ? AND origin = ? AND revoked_at IS NULL")
    .bind(providerSub, origin)
    .first<GrantRow>();
}

/**
 * Revoke a single session by id (idempotent). Used by /session/revoke.
 */
export async function revokeSession(db: D1Database, sessionId: string, now: number): Promise<void> {
  await db.prepare("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").bind(now, sessionId).run();
}

/**
 * Revoke a session only if it belongs to `providerSub`. Cross-account ids are
 * indistinguishable from absent ids. Used by /account/sessions/revoke.
 */
export async function revokeOwnedSession(
  db: D1Database,
  sessionId: string,
  providerSub: string,
  now: number,
): Promise<void> {
  await db
    .prepare("UPDATE sessions SET revoked_at = ? WHERE id = ? AND provider_sub = ? AND revoked_at IS NULL")
    .bind(now, sessionId, providerSub)
    .run();
}

/**
 * Revoke a grant and all its active sessions and outstanding codes for one
 * origin, in a single D1 batch. Other origins for the same provider remain
 * active. Used by /account/grants/revoke.
 */
export async function revokeGrantAndSessions(
  db: D1Database,
  providerSub: string,
  origin: string,
  now: number,
): Promise<void> {
  await db.batch([
    db
      .prepare("UPDATE grants SET revoked_at = ? WHERE provider_sub = ? AND origin = ? AND revoked_at IS NULL")
      .bind(now, providerSub, origin),
    db
      .prepare("UPDATE sessions SET revoked_at = ? WHERE provider_sub = ? AND origin = ? AND revoked_at IS NULL")
      .bind(now, providerSub, origin),
    db.prepare("DELETE FROM codes WHERE provider_sub = ? AND origin = ?").bind(providerSub, origin),
  ]);
}

/**
 * List active grants for a provider subject (account overview / grants list).
 */
export async function listActiveGrants(db: D1Database, providerSub: string): Promise<GrantRow[]> {
  const res = await db
    .prepare("SELECT * FROM grants WHERE provider_sub = ? AND revoked_at IS NULL ORDER BY origin")
    .bind(providerSub)
    .all<GrantRow>();
  return res.results;
}

/**
 * List active sessions for a provider subject.
 */
export async function listActiveSessions(db: D1Database, providerSub: string, now: number): Promise<SessionRow[]> {
  const res = await db
    .prepare(
      "SELECT * FROM sessions WHERE provider_sub = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC",
    )
    .bind(providerSub, now)
    .all<SessionRow>();
  return res.results;
}

/** Scheduled cleanup: delete expired flows/codes and expired/revoked sessions. */
export async function cleanupExpired(db: D1Database, now: number): Promise<void> {
  const unclaimedFlowCutoff = now - FLOW_TTL_MS;
  const claimedFlowCutoff = now - CLAIMED_FLOW_TIMEOUT_MS;
  await db.batch([
    // Normal, unclaimed login flows expire after the ten-minute flow TTL.
    db.prepare("DELETE FROM flows WHERE callback_claim_id IS NULL AND created_at < ?").bind(unclaimedFlowCutoff),
    // A callback that was claimed by a Worker invocation receives a much longer
    // safety window. Cleanup cannot delete it while a normal callback is still
    // exchanging/verifying/committing.
    db
      .prepare("DELETE FROM flows WHERE callback_claim_id IS NOT NULL AND callback_claimed_at < ?")
      .bind(claimedFlowCutoff),
    db.prepare("DELETE FROM codes WHERE expires_at < ?").bind(now),
    db.prepare("DELETE FROM sessions WHERE expires_at < ? AND revoked_at IS NOT NULL").bind(now),
  ]);
}

/** Expiry constant re-exported for tests. */
export { CODE_TTL_MS, FLOW_TTL_MS };
