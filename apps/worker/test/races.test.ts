/**
 * Race-safety coverage. Runs against the REAL miniflare D1 binding with no
 * repository mocking: every assertion reflects actual SQLite/D1 transactional
 * semantics (atomic claim, conditional batch, DELETE ... RETURNING).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  applyAllMigrations,
  authorize,
  call,
  db,
  googleCallback,
  jsonBody,
  makeGoogleDeps,
  resetTime,
  runLoginFlow,
  signGoogleIdToken,
  tokenExchange,
} from "./_helper.js";
import { sha256 } from "@auth2c/protocol";

/** Run /authorize + /callback without redeeming the resulting code. */
async function authorizeAndCallback(opts: {
  redirectUri: string;
  googleSub: string;
}): Promise<{ flowId: string; verifier: string; redirectUri: string; auth2cCode: string; nonce: string }> {
  const ar = await authorize({ redirectUri: opts.redirectUri, googleSub: opts.googleSub });
  const idToken = await signGoogleIdToken({ sub: opts.googleSub, nonce: ar.nonce });
  const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
  if (cb.status !== 302) throw new Error(`callback failed: ${cb.status}`);
  const url = new URL(cb.headers.get("location")!);
  return {
    flowId: ar.flowId,
    verifier: ar.verifier,
    redirectUri: ar.redirectUri,
    auth2cCode: url.searchParams.get("code")!,
    nonce: ar.nonce,
  };
}

beforeAll(async () => {
  await applyAllMigrations();
});
afterAll(() => {
  resetTime();
});

/**
 * Two concurrent /authorize-then-callback invocations sharing the same
 * state/cookie must result in exactly one completion and exactly one code.
 */
describe("races: callback claim is single-winner", () => {
  it("two concurrent callbacks for the same flow -> exactly one completes and exactly one code exists", async () => {
    const ar = await authorize({ redirectUri: "https://race1.test/cb", googleSub: "google-race1" });
    const idToken = await signGoogleIdToken({ sub: "google-race1", nonce: ar.nonce });
    const g1 = makeGoogleDeps({ idToken });
    const g2 = makeGoogleDeps({ idToken });
    const [a, b] = await Promise.all([
      googleCallback({ flowId: ar.flowId, google: g1 }),
      googleCallback({ flowId: ar.flowId, google: g2 }),
    ]);
    const statuses = [a.status, b.status].sort();
    // One wins (302), one loses (400).
    expect(statuses).toEqual([302, 400]);

    const codeCount = await db()
      .prepare("SELECT COUNT(*) AS n FROM codes WHERE origin = ?")
      .bind("https://race1.test")
      .first<{ n: number }>();
    expect(codeCount?.n).toBe(1);

    const grantCount = await db()
      .prepare("SELECT COUNT(*) AS n FROM grants WHERE origin = ?")
      .bind("https://race1.test")
      .first<{ n: number }>();
    expect(grantCount?.n).toBe(1);

    // The flow row is gone (winner deleted it).
    const flow = await db().prepare("SELECT 1 FROM flows WHERE id = ?").bind(ar.flowId).first();
    expect(flow).toBeNull();
  });
});

describe("races: code redemption is single-winner", () => {
  it("two concurrent /token with the same code -> exactly one token and exactly one session", async () => {
    const r = await authorizeAndCallback({ redirectUri: "https://race2.test/cb", googleSub: "google-race2" });
    const [a, b] = await Promise.all([
      tokenExchange({ code: r.auth2cCode, verifier: r.verifier, redirectUri: r.redirectUri }),
      tokenExchange({ code: r.auth2cCode, verifier: r.verifier, redirectUri: r.redirectUri }),
    ]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 400]);
    const loser = a.status === 400 ? a : b;
    expect((await jsonBody(loser)).error).toBe("invalid_grant");

    const sessCount = await db()
      .prepare("SELECT COUNT(*) AS n FROM sessions WHERE origin = ? AND revoked_at IS NULL")
      .bind("https://race2.test")
      .first<{ n: number }>();
    expect(sessCount?.n).toBe(1);

    // The code was consumed.
    const codeHash = await sha256(r.auth2cCode);
    const code = await db().prepare("SELECT 1 FROM codes WHERE code_hash = ?").bind(codeHash).first();
    expect(code).toBeNull();
  });

  it("10 concurrent /token redemptions -> still exactly one success", async () => {
    const r = await authorizeAndCallback({
      redirectUri: "https://race10.test/cb",
      googleSub: "google-race10",
    });
    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        tokenExchange({ code: r.auth2cCode, verifier: r.verifier, redirectUri: r.redirectUri }),
      ),
    );
    const ok = results.filter((x) => x.status === 200);
    const bad = results.filter((x) => x.status === 400);
    expect(ok.length).toBe(1);
    expect(bad.length).toBe(9);

    const sessCount = await db()
      .prepare("SELECT COUNT(*) AS n FROM sessions WHERE origin = ? AND revoked_at IS NULL")
      .bind("https://race10.test")
      .first<{ n: number }>();
    expect(sessCount?.n).toBe(1);
  });
});

describe("races: grant revocation vs /token redemption", () => {
  it("never leaves an active session behind when grant revocation races code redemption", async () => {
    // Establish a real app-origin code (not yet redeemed) and a real
    // account-origin token for the same provider, so the revocation call is
    // authorized end-to-end.
    const app = await authorize({ redirectUri: "https://revrace.test/cb", googleSub: "google-revrace" });
    const idTokenApp = await signGoogleIdToken({ sub: "google-revrace", nonce: app.nonce });
    const cb = await googleCallback({ flowId: app.flowId, google: makeGoogleDeps({ idToken: idTokenApp }) });
    expect(cb.status).toBe(302);
    const cbCode = new URL(cb.headers.get("location")!).searchParams.get("code")!;

    // Account-origin login for the same provider.
    const acct = await runLoginFlow({
      redirectUri: "https://auth.test/account",
      googleSub: "google-revrace",
    });
    const acctHeaders = { authorization: `Bearer ${acct.idToken}` };

    // Race: redeem the app code vs revoke the app grant.
    const [redemption, revocation] = await Promise.all([
      tokenExchange({ code: cbCode, verifier: app.verifier, redirectUri: "https://revrace.test/cb" }),
      call("POST", "/account/grants/revoke", {
        headers: acctHeaders,
        body: { origin: "https://revrace.test" },
      }),
    ]);
    expect(revocation.status).toBe(200);

    // After both settle: no active (unrevoked, unexpired) session for that
    // origin survives.
    const activeSessions = await db()
      .prepare("SELECT COUNT(*) AS n FROM sessions WHERE origin = ? AND revoked_at IS NULL AND expires_at > ?")
      .bind("https://revrace.test", Date.now())
      .first<{ n: number }>();
    expect(activeSessions?.n).toBe(0);

    // And the grant is revoked regardless of which side won.
    const grant = await db()
      .prepare("SELECT revoked_at FROM grants WHERE provider_sub = ? AND origin = ?")
      .bind("google-revrace", "https://revrace.test")
      .first<{ revoked_at: number | null }>();
    expect(grant?.revoked_at).not.toBeNull();

    // The redemption either failed (grant revoked first) or succeeded but the
    // session it created was then revoked by the racing batch.
    if (redemption.status === 200) {
      const total = await db()
        .prepare("SELECT COUNT(*) AS n FROM sessions WHERE origin = ?")
        .bind("https://revrace.test")
        .first<{ n: number }>();
      expect(total?.n).toBe(1);
    } else {
      expect(redemption.status).toBe(400);
      expect((await jsonBody(redemption)).error).toBe("invalid_grant");
    }
  });
});

describe("races: idempotent revocation", () => {
  it("two concurrent /session/revoke calls on the same token both succeed and revoke exactly once", async () => {
    const r = await runLoginFlow({
      redirectUri: "https://idem.test/cb",
      googleSub: "google-idem",
    });
    const headers = { authorization: `Bearer ${r.idToken}` };
    const [a, b] = await Promise.all([
      call("POST", "/session/revoke", { headers }),
      call("POST", "/session/revoke", { headers }),
    ]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const sc = await db()
      .prepare("SELECT revoked_at FROM sessions WHERE id = ?")
      .bind(r.claims.jti as string)
      .first<{ revoked_at: number | null }>();
    expect(sc?.revoked_at).not.toBeNull();
  });
});

describe("races: callback replay", () => {
  it("cannot create another code by replaying a successful callback", async () => {
    // Run authorize + callback (do NOT redeem the resulting code).
    const r = await authorizeAndCallback({
      redirectUri: "https://replay.test/cb",
      googleSub: "google-replay",
    });
    const idToken = await signGoogleIdToken({ sub: "google-replay", nonce: r.nonce });
    const replay = await googleCallback({
      flowId: r.flowId,
      google: makeGoogleDeps({ idToken }),
    });
    expect(replay.status).toBe(400);
    // Still exactly one code for that origin (the original; no second code minted).
    const codeCount = await db()
      .prepare("SELECT COUNT(*) AS n FROM codes WHERE origin = ?")
      .bind("https://replay.test")
      .first<{ n: number }>();
    expect(codeCount?.n).toBe(1);
  });
});
