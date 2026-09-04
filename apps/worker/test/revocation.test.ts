/**
 * Revocation coverage: /session/revoke (single jti), /account/sessions/revoke
 * (provider_sub-scoped), and /account/grants/revoke (grant + sessions + codes
 * in one batch, scoped by origin).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  APP_ORIGIN,
  applyAllMigrations,
  authorize,
  call,
  db,
  googleCallback,
  jsonBody,
  makeGoogleDeps,
  resetTime,
  runLoginFlow,
  seedSession,
  signGoogleIdToken,
} from "./_helper.js";

beforeAll(async () => {
  await applyAllMigrations();
});
afterAll(() => {
  resetTime();
});

const HEADERS = (tok: string) => ({ authorization: `Bearer ${tok}` });

describe("revocation: /session/revoke", () => {
  it("revokes only the presented jti and /session/check reflects it immediately", async () => {
    const providerSub = "google-rev-self";
    const a = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: providerSub,
    });
    const b = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: providerSub,
    });

    // Pre-check both are active.
    const checkA1 = await call("POST", "/session/check", { headers: HEADERS(a.idToken) });
    expect(checkA1.status).toBe(200);
    const checkB1 = await call("POST", "/session/check", { headers: HEADERS(b.idToken) });
    expect(checkB1.status).toBe(200);

    // Revoke only a's session.
    const revoke = await call("POST", "/session/revoke", { headers: HEADERS(a.idToken) });
    expect(revoke.status).toBe(200);
    expect((await jsonBody(revoke)).status).toBe("revoked");

    // a is now login_required; b is still active.
    const checkA2 = await call("POST", "/session/check", { headers: HEADERS(a.idToken) });
    expect(checkA2.status).toBe(401);
    const checkB2 = await call("POST", "/session/check", { headers: HEADERS(b.idToken) });
    expect(checkB2.status).toBe(200);
  });
});

describe("revocation: /account/sessions/revoke", () => {
  it("scopes by provider_sub: a cross-account session id is a silent no-op", async () => {
    const a = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: "google-rev-A",
    });
    const b = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: "google-rev-B",
    });

    // A tries to revoke B's session id through its own account token.
    const res = await call("POST", "/account/sessions/revoke", {
      headers: HEADERS(a.idToken),
      body: { sessionId: b.claims.jti as string },
    });
    expect(res.status).toBe(200);
    expect((await jsonBody(res)).status).toBe("revoked");

    // B's session is still active.
    const bRow = await db()
      .prepare("SELECT revoked_at FROM sessions WHERE id = ?")
      .bind(b.claims.jti as string)
      .first<{ revoked_at: number | null }>();
    expect(bRow?.revoked_at).toBeNull();

    // And A can revoke its own session id through the same route.
    const own = await call("POST", "/account/sessions/revoke", {
      headers: HEADERS(a.idToken),
      body: { sessionId: a.claims.jti as string },
    });
    expect(own.status).toBe(200);
    const aRow = await db()
      .prepare("SELECT revoked_at FROM sessions WHERE id = ?")
      .bind(a.claims.jti as string)
      .first<{ revoked_at: number | null }>();
    expect(aRow?.revoked_at).not.toBeNull();
  });
});

describe("revocation: /account/grants/revoke", () => {
  it("revokes the grant + all active sessions for that origin + deletes outstanding codes in one batch", async () => {
    const providerSub = "google-grant-revoke";
    // Active account-origin session, app-origin session, and an unredemed code
    // for the same provider+origin.
    const acct = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: providerSub,
    });
    await seedSession({ sessionId: "sess-grant-app-1", providerSub, origin: APP_ORIGIN });

    // Create an outstanding code for the app origin via /authorize + callback.
    const ar = await authorize({ redirectUri: `${APP_ORIGIN}/cb`, googleSub: providerSub });
    const idToken = await signGoogleIdToken({ sub: providerSub, nonce: ar.nonce });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(302);

    // Sanity: codes exist for the app origin.
    const codesBefore = await db()
      .prepare("SELECT COUNT(*) AS n FROM codes WHERE origin = ?")
      .bind(APP_ORIGIN)
      .first<{ n: number }>();
    expect(codesBefore?.n).toBeGreaterThanOrEqual(1);

    // Revoke the app-origin grant from the account.
    const revoke = await call("POST", "/account/grants/revoke", {
      headers: HEADERS(acct.idToken),
      body: { origin: APP_ORIGIN },
    });
    expect(revoke.status).toBe(200);

    // Grant for the app origin is revoked.
    const appGrant = await db()
      .prepare("SELECT revoked_at FROM grants WHERE provider_sub = ? AND origin = ?")
      .bind(providerSub, APP_ORIGIN)
      .first<{ revoked_at: number | null }>();
    expect(appGrant?.revoked_at).not.toBeNull();

    // All app-origin sessions are revoked.
    const activeAppSessions = await db()
      .prepare("SELECT COUNT(*) AS n FROM sessions WHERE origin = ? AND revoked_at IS NULL")
      .bind(APP_ORIGIN)
      .first<{ n: number }>();
    expect(activeAppSessions?.n).toBe(0);

    // Outstanding codes for that origin are deleted.
    const codesAfter = await db()
      .prepare("SELECT COUNT(*) AS n FROM codes WHERE origin = ?")
      .bind(APP_ORIGIN)
      .first<{ n: number }>();
    expect(codesAfter?.n).toBe(0);
  });

  it("leaves other origins for the same provider active", async () => {
    const providerSub = "google-grant-isolation";
    const acct = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: providerSub,
    });
    // Sessions/grants for two other origins.
    await seedSession({ sessionId: "sess-other1", providerSub, origin: "https://other1.test" });
    await seedSession({ sessionId: "sess-other2", providerSub, origin: "https://other2.test" });
    // Ensure grants exist (seedSession upserts the grant).
    // Revoke only other1.
    const revoke = await call("POST", "/account/grants/revoke", {
      headers: HEADERS(acct.idToken),
      body: { origin: "https://other1.test" },
    });
    expect(revoke.status).toBe(200);

    // other1 is revoked.
    const g1 = await db()
      .prepare("SELECT revoked_at FROM grants WHERE provider_sub = ? AND origin = ?")
      .bind(providerSub, "https://other1.test")
      .first<{ revoked_at: number | null }>();
    expect(g1?.revoked_at).not.toBeNull();
    const s1 = await db()
      .prepare("SELECT revoked_at FROM sessions WHERE id = ?")
      .bind("sess-other1")
      .first<{ revoked_at: number | null }>();
    expect(s1?.revoked_at).not.toBeNull();

    // other2 stays active.
    const g2 = await db()
      .prepare("SELECT revoked_at FROM grants WHERE provider_sub = ? AND origin = ?")
      .bind(providerSub, "https://other2.test")
      .first<{ revoked_at: number | null }>();
    expect(g2?.revoked_at).toBeNull();
    const s2 = await db()
      .prepare("SELECT revoked_at FROM sessions WHERE id = ?")
      .bind("sess-other2")
      .first<{ revoked_at: number | null }>();
    expect(s2?.revoked_at).toBeNull();

    // Account origin also stays active.
    const acctActive = await db()
      .prepare("SELECT revoked_at FROM sessions WHERE id = ?")
      .bind(acct.claims.jti as string)
      .first<{ revoked_at: number | null }>();
    expect(acctActive?.revoked_at).toBeNull();
  });
});
