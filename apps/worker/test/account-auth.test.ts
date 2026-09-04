/**
 * Account-route authorization coverage: third-party vs account-origin tokens,
 * strict session/grant enforcement, cross-account isolation, and rejection of
 * malformed tokens (array audience, mismatched sub/jti/origin/audience).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  advance,
  applyAllMigrations,
  APP_ORIGIN,
  PAIRWISE_SECRET,
  call,
  db,
  jsonBody,
  resetTime,
  runLoginFlow,
  seedSession,
  signCustomIdentityToken,
} from "./_helper.js";
import { pairwiseSubject, TOKEN_TTL_SECONDS } from "@auth2c/protocol";

beforeAll(async () => {
  await applyAllMigrations();
});
afterAll(() => {
  resetTime();
});

const ACCOUNT_HEADERS = (tok: string) => ({ authorization: `Bearer ${tok}` });

describe("account-auth: scope enforcement", () => {
  it("returns 403 insufficient_scope for every /account/* route when the token is a valid third-party app token", async () => {
    const app = await runLoginFlow({
      redirectUri: `${APP_ORIGIN}/cb`,
      googleSub: "google-acct-3p",
    });
    const headers = ACCOUNT_HEADERS(app.idToken);
    const routes = [
      ["GET", "/account/overview"],
      ["GET", "/account/grants"],
      ["POST", "/account/sessions/revoke", { sessionId: "anything" }],
      ["POST", "/account/grants/revoke", { origin: APP_ORIGIN }],
    ] as const;
    for (const [method, path, body] of routes) {
      const res = await call(method, path, { headers, body });
      expect(res.status, `${method} ${path}`).toBe(403);
      expect((await jsonBody(res)).error).toBe("insufficient_scope");
    }
  });

  it("allows a valid account-origin token to read /account/overview", async () => {
    const acct = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: "google-acct-self",
      requestProfile: true,
    });
    const res = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(acct.idToken) });
    expect(res.status).toBe(200);
    const body = await jsonBody(res);
    expect(body.account).toMatchObject({ email: "user@example.com", name: "Test User" });
    const apps = body.apps as Array<{ origin: string; profileAllowed: boolean }>;
    expect(apps.some((a) => a.origin === "https://auth.test")).toBe(true);
    expect(body.currentSessionId).toBe(acct.claims.jti);
  });
});

describe("account-auth: session/grant liveness", () => {
  it("returns 401 after the account session is revoked", async () => {
    const acct = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: "google-acct-rev",
    });
    const revoke = await call("POST", "/session/revoke", { headers: ACCOUNT_HEADERS(acct.idToken) });
    expect(revoke.status).toBe(200);
    const after = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(acct.idToken) });
    expect(after.status).toBe(401);
    const check = await call("POST", "/session/check", { headers: ACCOUNT_HEADERS(acct.idToken) });
    expect(check.status).toBe(401);
  });

  it("returns 401 after the account session expires", async () => {
    const acct = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: "google-acct-exp",
    });
    advance((TOKEN_TTL_SECONDS + 60) * 1000);
    const res = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(acct.idToken) });
    expect(res.status).toBe(401);
  });
});

describe("account-auth: cross-account isolation", () => {
  it("account A cannot revoke or see account B's sessions or grants", async () => {
    // Two different provider subjects (different people).
    const a = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: "google-acct-A",
    });
    const b = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: "google-acct-B",
    });
    const bSessionId = b.claims.jti as string;

    // A attempts to revoke B's session via /account/sessions/revoke.
    const revoke = await call("POST", "/account/sessions/revoke", {
      headers: ACCOUNT_HEADERS(a.idToken),
      body: { sessionId: bSessionId },
    });
    // The endpoint is idempotent and scoped by provider_sub: cross-account ids
    // are a no-op (200) but B's session is unaffected.
    expect(revoke.status).toBe(200);
    const bStillActive = await db()
      .prepare("SELECT revoked_at FROM sessions WHERE id = ?")
      .bind(bSessionId)
      .first<{ revoked_at: number | null }>();
    expect(bStillActive?.revoked_at).toBeNull();

    // A's overview lists only A's apps, not B's.
    const overview = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(a.idToken) });
    expect(overview.status).toBe(200);
    const body = await jsonBody(overview);
    const sessions = body.sessions as Array<{ id: string }>;
    expect(sessions.some((s) => s.id === bSessionId)).toBe(false);

    // A attempts to revoke B's grant for the account origin.
    const grantRevoke = await call("POST", "/account/grants/revoke", {
      headers: ACCOUNT_HEADERS(a.idToken),
      body: { origin: "https://auth.test" },
    });
    expect(grantRevoke.status).toBe(200);
    // B's grant for the account origin is still active.
    const bGrant = await db()
      .prepare("SELECT revoked_at FROM grants WHERE provider_sub = ? AND origin = ?")
      .bind("google-acct-B", "https://auth.test")
      .first<{ revoked_at: number | null }>();
    expect(bGrant?.revoked_at).toBeNull();
  });
});

describe("account-auth: token claim rejections", () => {
  it("rejects a token whose sub does not match the session's pairwise subject", async () => {
    // Seed a real session for provider_sub=google-mismatch, origin=auth.test.
    const providerSub = "google-acct-submismatch";
    const sessionId = "sess-submismatch";
    await seedSession({ sessionId, providerSub, origin: "https://auth.test" });
    // Sign a token whose sub is wrong but whose jti maps to the session row.
    const tok = await signCustomIdentityToken({
      audience: "origin:https://auth.test",
      jti: sessionId,
      sub: "pw_wrong_value",
    });
    const res = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(tok) });
    expect(res.status).toBe(401);
  });

  it("rejects a token whose jti does not map to any session row", async () => {
    const tok = await signCustomIdentityToken({
      audience: "origin:https://auth.test",
      jti: "nonexistent-session",
      sub: "pw_does_not_matter",
    });
    const res = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(tok) });
    expect(res.status).toBe(401);
  });

  it("rejects a token whose audience origin differs from the session origin", async () => {
    const providerSub = "google-acct-origmismatch";
    const sessionId = "sess-origmismatch";
    await seedSession({ sessionId, providerSub, origin: "https://auth.test" });
    // Audience says app.test, session origin is auth.test -> mismatch.
    const tok = await signCustomIdentityToken({
      audience: "origin:https://app.test",
      jti: sessionId,
      sub: await pairwiseSubject(PAIRWISE_SECRET, providerSub, "https://app.test"),
    });
    const res = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(tok) });
    expect(res.status).toBe(401);
  });

  it("rejects a token with a malformed scalar audience", async () => {
    const tok = await signCustomIdentityToken({
      audience: "https://app.test",
      jti: "any",
      sub: "any",
    });
    const res = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(tok) });
    expect(res.status).toBe(401);
  });

  it("rejects a token with an array audience", async () => {
    const tok = await signCustomIdentityToken({
      audience: ["origin:https://auth.test", "origin:https://app.test"],
      jti: "any",
      sub: "any",
    });
    const res = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(tok) });
    expect(res.status).toBe(401);
  });

  it("rejects a token signed with the wrong issuer", async () => {
    const tok = await signCustomIdentityToken({
      audience: "origin:https://auth.test",
      issuer: "https://attacker.example",
      jti: "any",
      sub: "any",
    });
    const res = await call("GET", "/account/overview", { headers: ACCOUNT_HEADERS(tok) });
    expect(res.status).toBe(401);
  });
});

describe("account-auth: multi-session independence", () => {
  it("revoking one session leaves the others active", async () => {
    const providerSub = "google-acct-multi";
    // Account-origin session #1 (via the flow) and #2 (seeded).
    const first = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: providerSub,
    });
    const secondId = "sess-multi-second";
    await seedSession({ sessionId: secondId, providerSub, origin: "https://auth.test" });

    // Revoke the first; the second must remain active.
    const revoke = await call("POST", "/session/revoke", { headers: ACCOUNT_HEADERS(first.idToken) });
    expect(revoke.status).toBe(200);
    const stillActive = await db()
      .prepare("SELECT revoked_at FROM sessions WHERE id = ?")
      .bind(secondId)
      .first<{ revoked_at: number | null }>();
    expect(stillActive?.revoked_at).toBeNull();
    const firstRevoked = await db()
      .prepare("SELECT revoked_at FROM sessions WHERE id = ?")
      .bind(first.claims.jti as string)
      .first<{ revoked_at: number | null }>();
    expect(firstRevoked?.revoked_at).not.toBeNull();
  });
});
