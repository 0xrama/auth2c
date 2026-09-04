/**
 * End-to-end OAuth/PKCE happy-path and rejection coverage for the worker.
 *
 * Drives /authorize -> /oauth/google/callback -> /token against the real
 * (miniflare) D1 binding; Google is faked via injected deps but REAL jose
 * verification of the id_token runs inside google.ts.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  APP_ORIGIN,
  PAIRWISE_SECRET,
  applyAllMigrations,
  authorize,
  baseDeps,
  call,
  db,
  GOOGLE_CLIENT_ID,
  jsonBody,
  locationParams,
  makeGoogleDeps,
  parseLocation,
  parseSetCookie,
  resetTime,
  runLoginFlow,
  signGoogleIdToken,
  advance,
  googleCallback,
  tokenExchange,
} from "./_helper.js";
import { sha256, pairwiseSubject, audienceForOrigin } from "@auth2c/protocol";
import { CODE_TTL_MS, FLOW_TTL_MS } from "../src/db.js";

beforeAll(async () => {
  await applyAllMigrations();
});
afterAll(() => {
  resetTime();
});

describe("auth-flow: happy path", () => {
  it("completes /authorize -> /callback -> /token and returns a signed pairwise identity token", async () => {
    const r = await runLoginFlow({ requestProfile: true });

    // /authorize persisted a flow with a nonce equal to the nonce in the Google auth URL.
    const persistedNonce = await db()
      .prepare("SELECT nonce FROM flows WHERE id = ?")
      .bind(r.flowId)
      .first<{ nonce: string | null }>();
    // Flow was deleted by the callback batch, so the row is gone.
    expect(persistedNonce).toBeNull();

    // Location of /authorize pointed at Google with the persisted nonce.
    expect(r.location.origin + r.location.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(r.location.searchParams.get("nonce")).toBe(r.nonce);
    expect(r.location.searchParams.get("state")).toBe(r.flowId);
    expect(r.location.searchParams.get("redirect_uri")).toBe(`${"https://auth.test"}/oauth/google/callback`);

    // The token has the correct issuer, scalar origin audience, and a pairwise sub.
    const claims = r.claims;
    expect(claims.iss).toBe("https://auth.test");
    expect(claims.aud).toBe(audienceForOrigin(APP_ORIGIN));
    expect(typeof claims.sub).toBe("string");
    expect(claims.sub).not.toContain(r.googleSub);
    const expectedSub = await pairwiseSubject(PAIRWISE_SECRET, r.googleSub, APP_ORIGIN);
    expect(claims.sub).toBe(expectedSub);
    expect(claims.email).toBe("user@example.com");
    expect(claims.name).toBe("Test User");
    expect(claims.exp as number).toBeGreaterThan(claims.iat as number);
  });

  it("persists the nonce exactly as it appears in the Google authorization URL", async () => {
    const ar = await authorize({ redirectUri: "https://nonce.test/cb" });
    const persisted = await db()
      .prepare("SELECT nonce, redirect_uri, origin FROM flows WHERE id = ?")
      .bind(ar.flowId)
      .first<{ nonce: string; redirect_uri: string; origin: string }>();
    expect(persisted).not.toBeNull();
    expect(persisted!.nonce).toBe(ar.nonce);
    expect(persisted!.redirect_uri).toBe("https://nonce.test/cb");
    expect(persisted!.origin).toBe("https://nonce.test");
  });

  it("issues the Google token exchange with the exact configured callback URI", async () => {
    const ar = await authorize({ redirectUri: "https://callback.test/cb" });
    let receivedRedirectUri = "";
    const idToken = await signGoogleIdToken({ sub: "google-cb-1", nonce: ar.nonce });
    const google = makeGoogleDeps({
      idToken,
      onTokenRequest: async () => {
        /* observed below */
      },
    });
    // Wrap fetch to capture the redirect_uri form field.
    const origFetch = google.fetch!;
    const captured: { redirect_uri?: string; client_id?: string } = {};
    google.fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url === "https://oauth2.googleapis.com/token" && init?.body) {
        const params = new URLSearchParams(String(init.body));
        captured.redirect_uri = params.get("redirect_uri") ?? undefined;
        captured.client_id = params.get("client_id") ?? undefined;
      }
      const res = await origFetch(input, init);
      // Capture synchronously after the call.
      receivedRedirectUri = captured.redirect_uri ?? receivedRedirectUri;
      return res;
    };
    const cb = await googleCallback({ flowId: ar.flowId, google });
    expect(cb.status).toBe(302);
    expect(receivedRedirectUri).toBe(`${"https://auth.test"}/oauth/google/callback`);
    expect(captured.client_id).toBe(GOOGLE_CLIENT_ID);
  });

  it("callback atomically creates grant + code and removes the flow", async () => {
    const ar = await authorize({ redirectUri: "https://atomic.test/cb", googleSub: "google-atomic" });
    const idToken = await signGoogleIdToken({ sub: "google-atomic", nonce: ar.nonce });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(302);

    const codeCount = await db()
      .prepare("SELECT COUNT(*) AS n FROM codes WHERE origin = ?")
      .bind("https://atomic.test")
      .first<{ n: number }>();
    expect(codeCount?.n).toBe(1);

    const grant = await db()
      .prepare("SELECT provider_sub, origin, profile_allowed, revoked_at FROM grants WHERE origin = ?")
      .bind("https://atomic.test")
      .first<{ provider_sub: string; origin: string; profile_allowed: number; revoked_at: number | null }>();
    expect(grant).not.toBeNull();
    expect(grant!.provider_sub).toBe("google-atomic");
    expect(grant!.revoked_at).toBeNull();

    const flow = await db().prepare("SELECT id FROM flows WHERE id = ?").bind(ar.flowId).first();
    expect(flow).toBeNull();
  });

  it("preserves legitimate pre-existing redirect_uri query params through authorize+callback+/token", async () => {
    const redirectUri = "https://query.test/cb?utm_source=app&session=xyz";
    const r = await runLoginFlow({ redirectUri });
    // Token succeeded with the exact stored redirect URI.
    expect(r.claims.aud).toBe(audienceForOrigin("https://query.test"));
    // Replaying the same code should fail (it was consumed).
    const replay = await tokenExchange({ code: r.auth2cCode, verifier: r.verifier, redirectUri });
    expect(replay.status).toBe(400);
  });
});

describe("auth-flow: issuer / audience / expiry / sub rejection", () => {
  it("rejects an id_token with the wrong issuer", async () => {
    const ar = await authorize({ redirectUri: "https://issuer.test/cb" });
    const idToken = await signGoogleIdToken({
      sub: "google-issuer",
      nonce: ar.nonce,
      issuer: "https://evil.example",
    });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(400);
    expect(await cb.text()).toMatch(/iss|issuer/i);
    // No grant/code created; flow was terminally deleted.
    const grant = await db().prepare("SELECT 1 FROM grants WHERE origin = ?").bind("https://issuer.test").first();
    const code = await db().prepare("SELECT 1 FROM codes WHERE origin = ?").bind("https://issuer.test").first();
    const flow = await db().prepare("SELECT 1 FROM flows WHERE id = ?").bind(ar.flowId).first();
    expect(grant).toBeNull();
    expect(code).toBeNull();
    expect(flow).toBeNull();
  });

  it("rejects an id_token with the wrong audience", async () => {
    const ar = await authorize({ redirectUri: "https://aud.test/cb" });
    const idToken = await signGoogleIdToken({
      sub: "google-aud",
      nonce: ar.nonce,
      audience: "someone-else.apps.example",
    });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(400);
    expect(await cb.text()).toMatch(/audience|aud/i);
  });

  it("rejects an expired id_token", async () => {
    const ar = await authorize({ redirectUri: "https://exp.test/cb" });
    const idToken = await signGoogleIdToken({
      sub: "google-exp",
      nonce: ar.nonce,
      expiresIn: "-10s",
    });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(400);
  });

  it("rejects an id_token with no subject (sub claim missing)", async () => {
    const ar = await authorize({ redirectUri: "https://nosub.test/cb" });
    const idToken = await signGoogleIdToken({ omitSub: true, nonce: ar.nonce });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(400);
    expect(await cb.text()).toContain("identity");
  });
});

describe("auth-flow: nonce rejection", () => {
  it("rejects an id_token missing the nonce claim", async () => {
    const ar = await authorize({ redirectUri: "https://nononce.test/cb" });
    const idToken = await signGoogleIdToken({ omitNonce: true, sub: "google-nononce" });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(400);
    // Flow is terminally deleted on cryptographic/nonce failure.
    const flow = await db().prepare("SELECT 1 FROM flows WHERE id = ?").bind(ar.flowId).first();
    expect(flow).toBeNull();
    const grant = await db().prepare("SELECT 1 FROM grants WHERE origin = ?").bind("https://nononce.test").first();
    expect(grant).toBeNull();
  });

  it("rejects an id_token whose nonce does not match the persisted nonce, with NO grant/code created", async () => {
    const ar = await authorize({ redirectUri: "https://mismatch.test/cb" });
    const idToken = await signGoogleIdToken({
      sub: "google-mismatch",
      nonce: "totally-different-nonce",
    });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(400);
    expect(await cb.text()).toContain("Nonce");
    const grant = await db().prepare("SELECT 1 FROM grants WHERE origin = ?").bind("https://mismatch.test").first();
    const code = await db().prepare("SELECT 1 FROM codes WHERE origin = ?").bind("https://mismatch.test").first();
    const flow = await db().prepare("SELECT 1 FROM flows WHERE id = ?").bind(ar.flowId).first();
    expect(grant).toBeNull();
    expect(code).toBeNull();
    expect(flow).toBeNull();
  });
});

describe("auth-flow: google exchange failure", () => {
  it("creates no grant/code when the Google token endpoint returns a terminal (4xx) failure", async () => {
    const ar = await authorize({ redirectUri: "https://gfail.test/cb" });
    const cb = await googleCallback({
      flowId: ar.flowId,
      google: makeGoogleDeps({ errorStatus: 400, errorBody: { error: "invalid_grant" } }),
    });
    expect(cb.status).toBe(400);
    const grant = await db().prepare("SELECT 1 FROM grants WHERE origin = ?").bind("https://gfail.test").first();
    const code = await db().prepare("SELECT 1 FROM codes WHERE origin = ?").bind("https://gfail.test").first();
    expect(grant).toBeNull();
    expect(code).toBeNull();
    // Terminal failure deletes the claimed flow.
    const flow = await db().prepare("SELECT 1 FROM flows WHERE id = ?").bind(ar.flowId).first();
    expect(flow).toBeNull();
  });

  it("releases the callback claim on transient failure so the browser may retry", async () => {
    const ar = await authorize({ redirectUri: "https://transient.test/cb" });
    const cb = await googleCallback({
      flowId: ar.flowId,
      google: makeGoogleDeps({ throwOnToken: true }),
    });
    expect(cb.status).toBe(400);
    // Claim was released: callback_claim_id is NULL again and the flow is still present.
    const flow = await db()
      .prepare("SELECT callback_claim_id FROM flows WHERE id = ?")
      .bind(ar.flowId)
      .first<{ callback_claim_id: string | null }>();
    expect(flow).not.toBeNull();
    expect(flow!.callback_claim_id).toBeNull();
  });
});

describe("auth-flow: /token redirect_uri and code semantics", () => {
  it("returns invalid_grant for redirect_uri mismatch and does NOT consume the code", async () => {
    const ar = await authorize({ redirectUri: "https://rd.test/cb", googleSub: "google-rd" });
    const idToken = await signGoogleIdToken({ sub: "google-rd", nonce: ar.nonce });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(302);
    const auth2cCode = locationParams(cb).get("code") ?? "";

    // Wrong redirect_uri -> invalid_grant, code not consumed.
    const wrong = await tokenExchange({
      code: auth2cCode,
      verifier: ar.verifier,
      redirectUri: "https://different.test/cb",
    });
    expect(wrong.status).toBe(400);
    expect((await jsonBody(wrong)).error).toBe("invalid_grant");

    // The code row still exists.
    const codeHash = await sha256(auth2cCode);
    const code = await db().prepare("SELECT 1 FROM codes WHERE code_hash = ?").bind(codeHash).first();
    expect(code).not.toBeNull();

    // Correct redemption now succeeds.
    const good = await tokenExchange({
      code: auth2cCode,
      verifier: ar.verifier,
      redirectUri: ar.redirectUri,
    });
    expect(good.status).toBe(200);
  });

  it("callback batch rolls back when the flow claim is lost before completion", async () => {
    const ar = await authorize({ redirectUri: "https://rollback.test/cb", googleSub: "google-rb" });
    // Force the failure: while the token endpoint is being called, delete the
    // claimed flow. The final batch's conditional EXISTS guards then fail to
    // match, so the batch throws and no grant/code is minted.
    const idToken = await signGoogleIdToken({ sub: "google-rb", nonce: ar.nonce });
    const google = makeGoogleDeps({
      idToken,
      onTokenRequest: async () => {
        await db().prepare("DELETE FROM flows WHERE id = ?").bind(ar.flowId).run();
      },
    });
    const cb = await googleCallback({ flowId: ar.flowId, google });
    expect(cb.status).toBe(400);
    const grant = await db().prepare("SELECT 1 FROM grants WHERE origin = ?").bind("https://rollback.test").first();
    const code = await db().prepare("SELECT 1 FROM codes WHERE origin = ?").bind("https://rollback.test").first();
    expect(grant).toBeNull();
    expect(code).toBeNull();
  });
});

describe("auth-flow: cookie / state coupling", () => {
  it("rejects a callback whose state does not match the flow cookie", async () => {
    const ar = await authorize({ redirectUri: "https://state.test/cb" });
    // Cookie says flowId-A, query state says flowId-B.
    const params = new URLSearchParams({ code: "g-x", state: "someone-else" });
    const res = await call(
      "GET",
      `/oauth/google/callback?${params}`,
      { headers: { cookie: `a2c_flow=${ar.flowId}` } },
      baseDeps(),
    );
    expect(res.status).toBe(400);
  });

  it("clears the flow cookie on a successful callback", async () => {
    const r = await runLoginFlow({ redirectUri: "https://cookie.test/cb" });
    // Re-issue a callback we know succeeded and inspect Set-Cookie on the callback response.
    const ar = await authorize({ redirectUri: "https://cookie2.test/cb" });
    const idToken = await signGoogleIdToken({ sub: "google-cookie", nonce: ar.nonce });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    const sc = parseSetCookie(cb);
    expect(sc.a2c_flow ?? "").toBe(""); // Max-Age=0 clears the cookie
    void r;
  });
});

describe("auth-flow: expiry windows", () => {
  it("rejects a callback after the flow TTL has elapsed", async () => {
    const ar = await authorize({ redirectUri: "https://flowttl.test/cb" });
    advance(FLOW_TTL_MS + 1);
    const idToken = await signGoogleIdToken({ sub: "google-ttl", nonce: ar.nonce });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    expect(cb.status).toBe(400);
    expect(await cb.text()).toContain("expired");
  });

  it("rejects /token redemption after the code TTL has elapsed", async () => {
    const ar = await authorize({ redirectUri: "https://codettl.test/cb", googleSub: "google-cttl" });
    const idToken = await signGoogleIdToken({ sub: "google-cttl", nonce: ar.nonce });
    const cb = await googleCallback({ flowId: ar.flowId, google: makeGoogleDeps({ idToken }) });
    const code = locationParams(cb).get("code") ?? "";
    advance(CODE_TTL_MS + 1);
    const res = await tokenExchange({ code, verifier: ar.verifier, redirectUri: ar.redirectUri });
    expect(res.status).toBe(400);
    expect((await jsonBody(res)).error).toBe("invalid_grant");
  });
});
