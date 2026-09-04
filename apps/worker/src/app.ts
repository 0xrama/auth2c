/**
 * Route dispatch, CORS policy, and all request handlers.
 *
 * Authorization model:
 *  - Token/session validation is strict and row-level: an active session row
 *    keyed by `jti` is required for every protected route (see tokens.ts).
 *  - Account routes additionally require the session origin to equal the
 *    account origin (the origin of PUBLIC_URL). A valid third-party app token
 *    receives 403 insufficient_scope rather than account-wide access.
 *  - CORS is same-origin (reflective, no credentials) for account routes, and
 *    permissive `*` (non-credentialed) for public SDK/token/session endpoints.
 */
import {
  appOrigin,
  audienceForOrigin,
  pairwiseSubject,
  randomToken,
  validatePkceRequest,
  sha256,
  CODE_TTL_MS,
} from "@auth2c/protocol";
import type { AppConfig } from "./env.js";
import {
  claimFlowForCallback,
  cleanupExpired,
  completeCallbackBatch,
  deleteFlow,
  insertFlow,
  insertSessionIfGrantActive,
  listActiveGrants,
  listActiveSessions,
  redeemCode,
  releaseFlowClaim,
  revokeGrantAndSessions,
  revokeOwnedSession,
  revokeSession,
  type FlowRow,
} from "./db.js";
import {
  buildGoogleAuthUrl,
  exchangeGoogleCode,
  generateNonce,
  verifyGoogleIdToken,
  type GoogleDeps,
} from "./google.js";
import { signIdentityToken, validateBearer } from "./tokens.js";
import { browserClient } from "./client.js";
import { account, docs, errorPage, home, shell } from "./pages.js";

const FLOW_COOKIE = "a2c_flow";
/** Host-only, HttpOnly, Secure, SameSite=Lax cookie attributes. */
const flowCookieAttrs = "Path=/; HttpOnly; Secure; SameSite=Lax";
const clearFlowCookie = `${FLOW_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;

/** Injectable deps so tests can supply a deterministic clock and Google mock. */
export interface HandlerDeps {
  now?: () => number;
  google?: GoogleDeps;
  randomUUID?: () => string;
}

const json = (x: unknown, status = 200, h: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(x), {
    status,
    headers: { "content-type": "application/json", ...h },
  });

const html = (x: string, status = 200, h: Record<string, string> = {}): Response =>
  new Response(x, { status, headers: { "content-type": "text/html;charset=utf-8", ...h } });

function cookie(req: Request, name: string): string | undefined {
  return req.headers.get("cookie")?.match(new RegExp(`(?:^|; )${name}=([^;]+)`))?.[1];
}

/**
 * CORS for public, non-credentialed endpoints (SDK, token, session).
 * Allows any origin without credentials.
 */
function publicCorsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("origin");
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST",
    "access-control-allow-headers": "content-type,authorization",
    ...(origin ? { vary: "Origin" } : {}),
  };
}

/**
 * Same-origin CORS for account routes. Reflects the request origin only if it
 * equals the account origin; otherwise no ACAO header is sent. Credentials are
 * not used (bearer tokens travel in the Authorization header), but we still
 * restrict ACAO so a third-party page cannot read account responses.
 */
function accountCorsHeaders(req: Request, config: AppConfig): Record<string, string> {
  const origin = req.headers.get("origin");
  const allow = origin === config.accountOrigin ? origin : null;
  return {
    ...(allow ? { "access-control-allow-origin": allow, vary: "Origin" } : {}),
    "access-control-allow-methods": "GET,POST",
    "access-control-allow-headers": "content-type,authorization",
  };
}

/** True if `pathname` is an account-management route. */
function isAccountRoute(pathname: string): boolean {
  return pathname === "/account" || pathname.startsWith("/account/");
}

/** Read the JSON body of a request, or null on parse failure. */
async function readJson<T = Record<string, unknown>>(req: Request): Promise<T | null> {
  try {
    return (await req.json()) as T;
  } catch {
    return null;
  }
}

/**
 * Main request router. Throws AuthError for expected failures; the caller
 * (index.ts) maps thrown errors to a safe HTML error page.
 */
export async function handleRequest(req: Request, config: AppConfig, deps: HandlerDeps = {}): Promise<Response> {
  const url = new URL(req.url);
  const now = deps.now?.() ?? Date.now();
  const uuid = deps.randomUUID ?? crypto.randomUUID.bind(crypto);

  // ---- Preflight ----
  if (req.method === "OPTIONS") {
    const cors = isAccountRoute(url.pathname) ? accountCorsHeaders(req, config) : publicCorsHeaders(req);
    return new Response(null, { status: 204, headers: cors });
  }

  // ---- Static / public pages ----
  if (url.pathname === "/") return html(home(config.publicUrl));
  if (url.pathname === "/docs") return html(docs(config.publicUrl));
  if (url.pathname === "/account" && req.method === "GET") {
    return html(account(config.publicUrl));
  }
  if (url.pathname === "/auth2c.js") {
    return new Response(browserClient, {
      headers: {
        "content-type": "application/javascript",
        "cache-control": "no-store",
        "access-control-allow-origin": "*",
      },
    });
  }

  // ---- Public discovery ----
  if (url.pathname === "/.well-known/jwks.json") {
    return json({
      keys: [{ ...config.publicJwk, kid: "auth2c-v1", use: "sig", alg: "ES256" }],
    });
  }
  if (url.pathname === "/.well-known/openid-configuration") {
    return json({
      issuer: config.publicUrl,
      authorization_endpoint: `${config.publicUrl}/authorize`,
      token_endpoint: `${config.publicUrl}/token`,
      jwks_uri: `${config.publicUrl}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      subject_types_supported: ["pairwise"],
      id_token_signing_alg_values_supported: ["ES256"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid", "email", "profile"],
    });
  }

  // ---- /authorize: start OAuth + PKCE, persist nonce ----
  if (url.pathname === "/authorize" && req.method === "GET") {
    return authorize(req, config, url, now, deps.google);
  }

  // ---- /oauth/google/callback: atomic claim, verify nonce, transactional batch ----
  if (url.pathname === "/oauth/google/callback") {
    return googleCallback(req, config, url, now, uuid, deps.google);
  }

  // ---- /token: atomic race-safe redemption + conditional session creation ----
  if (url.pathname === "/token" && req.method === "POST") {
    return tokenExchange(req, config, now, uuid, deps.google);
  }

  // ---- /session/check: requires active session + active grant ----
  if (url.pathname === "/session/check" && req.method === "POST") {
    const result = await validateBearer(req, config, now);
    if (!result.ok) {
      return json({ status: "login_required", reason: "invalid_token" }, 401, {
        "access-control-allow-origin": "*",
      });
    }
    return json({ status: "active" }, 200, { "access-control-allow-origin": "*" });
  }

  // ---- /session/revoke: revoke only the presented token's session ----
  if (url.pathname === "/session/revoke" && req.method === "POST") {
    const result = await validateBearer(req, config, now);
    if (!result.ok) {
      return json({ error: "invalid_token" }, 401, {
        "access-control-allow-origin": "*",
      });
    }
    await revokeSession(config.db, result.auth.claims.jti, now);
    return json({ status: "revoked" }, 200, { "access-control-allow-origin": "*" });
  }

  // ---- Account routes: require account-origin session ----
  if (url.pathname.startsWith("/account/") && req.method !== "OPTIONS") {
    const cors = accountCorsHeaders(req, config);
    const result = await validateBearer(req, config, now);
    if (!result.ok) return json({ error: "invalid_token" }, 401, cors);

    // Account-origin enforcement: the session origin must equal the account
    // origin. A valid third-party app token gets 403 insufficient_scope.
    if (result.auth.origin !== config.accountOrigin) {
      return json({ error: "insufficient_scope" }, 403, cors);
    }

    if (url.pathname === "/account/overview" && req.method === "GET") {
      return accountOverview(config, result.auth.providerSub, result.auth.claims.jti, result.auth.profile, now, cors);
    }
    if (url.pathname === "/account/grants" && req.method === "GET") {
      return accountGrants(config, result.auth.providerSub, cors);
    }
    if (url.pathname === "/account/sessions/revoke" && req.method === "POST") {
      return accountSessionsRevoke(req, config, result.auth.providerSub, now, cors);
    }
    if (url.pathname === "/account/grants/revoke" && req.method === "POST") {
      return accountGrantsRevoke(req, config, result.auth.providerSub, now, cors);
    }
  }

  return html(shell("Not found", "<h1>404</h1><p>That page does not exist.</p>"), 404);
}

/** /authorize handler. */
async function authorize(
  req: Request,
  config: AppConfig,
  url: URL,
  now: number,
  google: GoogleDeps | undefined,
): Promise<Response> {
  void req;
  void google;
  const redirectUri = url.searchParams.get("redirect_uri") ?? "";
  const challengeParam = url.searchParams.get("code_challenge") ?? "";
  const method = url.searchParams.get("code_challenge_method") ?? "";
  const state = url.searchParams.get("state") ?? "";

  // Validate PKCE request + redirect URI (origin/scheme).
  const { origin, redirectUri: validatedRedirect } = validatePkceRequest({
    redirect_uri: redirectUri,
    code_challenge: challengeParam,
    code_challenge_method: method,
    state,
  });

  // Reject redirect URIs that already carry broker-owned code/state params or
  // credentials/fragments (appOrigin already rejected creds/fragments).
  const parsed = new URL(validatedRedirect);
  if (parsed.searchParams.has("code") || parsed.searchParams.has("state")) {
    throw new Error("redirect_uri must not include broker code/state parameters");
  }

  const scope = url.searchParams.get("scope") ?? "";
  const requestProfile = scope.includes("email") ? 1 : 0;
  const flowId = randomToken();
  const nonce = generateNonce();

  await insertFlow(config.db, {
    id: flowId,
    redirect_uri: validatedRedirect,
    origin,
    challenge: challengeParam,
    client_state: state,
    request_profile: requestProfile,
    nonce,
    created_at: now,
  });

  const googleUrl = buildGoogleAuthUrl({
    googleClientId: config.googleClientId,
    callbackUrl: `${config.publicUrl}/oauth/google/callback`,
    flowId,
    nonce,
    requestProfile: requestProfile === 1,
  });

  return new Response(null, {
    status: 302,
    headers: {
      location: googleUrl,
      "set-cookie": `${FLOW_COOKIE}=${flowId}; ${flowCookieAttrs}; Max-Age=600`,
    },
  });
}

/** /oauth/google/callback handler. */
async function googleCallback(
  req: Request,
  config: AppConfig,
  url: URL,
  now: number,
  uuid: () => string,
  google: GoogleDeps | undefined,
): Promise<Response> {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookieFlowId = cookie(req, FLOW_COOKIE);

  if (!code || !state || !cookieFlowId || state !== cookieFlowId) {
    throw new Error("Invalid callback state");
  }

  // Atomically claim the flow so exactly one concurrent callback proceeds.
  const claimId = uuid();
  const claimed = await claimFlowForCallback(config.db, state, claimId, now);
  if (!claimed.ok) {
    const msg = claimed.reason === "expired" ? "Login flow expired" : "Login flow not found";
    throw new Error(msg);
  }
  const flow: FlowRow = claimed.flow;

  // A pre-hardening flow with a null nonce cannot be verified; treat as terminal.
  if (!flow.nonce) {
    await deleteFlow(config.db, state);
    throw new Error("Login flow expired");
  }

  const callbackUrl = `${config.publicUrl}/oauth/google/callback`;

  // Exchange the code with Google.
  const exchange = await exchangeGoogleCode(
    code,
    config.googleClientId,
    config.googleClientSecret,
    callbackUrl,
    google,
  );
  if (!exchange.ok) {
    if (exchange.transient) {
      // Release the claim so the browser may retry.
      await releaseFlowClaim(config.db, state, claimId);
    } else {
      // Terminal exchange failure: delete the claimed flow.
      await deleteFlow(config.db, state);
    }
    throw new Error(exchange.message);
  }

  // Verify the Google ID token, requiring the signed nonce to equal persisted.
  const verified = await verifyGoogleIdToken(exchange.exchange.idToken, config.googleClientId, flow.nonce, google);
  if (!verified.ok) {
    // Cryptographic/claim/nonce failure is terminal.
    await deleteFlow(config.db, state);
    throw new Error(verified.message);
  }

  const profile =
    flow.request_profile === 1
      ? JSON.stringify({
          email: verified.id.email,
          email_verified: verified.id.email_verified,
          name: verified.id.name,
          picture: verified.id.picture,
        })
      : null;

  const rawCode = randomToken();
  const codeHash = await sha256(rawCode);

  // Transactional batch: grant upsert/reactivation + code insert + flow delete.
  await completeCallbackBatch(config.db, {
    providerSub: verified.id.sub,
    origin: flow.origin,
    profileAllowed: flow.request_profile,
    profile,
    codeHash,
    redirectUri: flow.redirect_uri,
    challenge: flow.challenge,
    expiresAt: now + CODE_TTL_MS,
    createdAt: now,
    flowId: state,
    claimId,
  });

  // Redirect with exact stored redirect URI, appending only code + client state.
  const back = new URL(flow.redirect_uri);
  back.searchParams.set("code", rawCode);
  back.searchParams.set("state", flow.client_state);

  return new Response(null, {
    status: 302,
    headers: { location: back.toString(), "set-cookie": clearFlowCookie },
  });
}

/** /token handler: atomic redemption + conditional session creation. */
async function tokenExchange(
  req: Request,
  config: AppConfig,
  now: number,
  uuid: () => string,
  google: GoogleDeps | undefined,
): Promise<Response> {
  void google;
  const body = await readJson<{
    code?: string;
    code_verifier?: string;
    redirect_uri?: string;
  }>(req);
  if (
    !body ||
    typeof body.code !== "string" ||
    typeof body.code_verifier !== "string" ||
    typeof body.redirect_uri !== "string"
  ) {
    return json({ error: "invalid_grant" }, 400, { "access-control-allow-origin": "*" });
  }

  // Atomically redeem: hash first, then DELETE ... RETURNING. Any zero-row
  // result (replay, wrong verifier, wrong redirect, expired) is invalid_grant.
  const redeemed = await redeemCode(config.db, body.code, body.code_verifier, body.redirect_uri, now);
  if (!redeemed.ok) {
    return json({ error: "invalid_grant" }, 400, { "access-control-allow-origin": "*" });
  }
  const row = redeemed.row;

  // Create the session only if an active grant still exists. If the grant was
  // revoked between code issuance and redemption, no session is created.
  const sessionId = uuid();
  const insertedId = await insertSessionIfGrantActive(config.db, {
    sessionId,
    providerSub: row.provider_sub,
    origin: row.origin,
    now,
  });
  if (!insertedId) {
    return json({ error: "invalid_grant" }, 400, { "access-control-allow-origin": "*" });
  }

  const pairwiseSub = await pairwiseSubject(config.pairwiseSecret, row.provider_sub, row.origin);
  const profile = row.profile ? (JSON.parse(row.profile) as Record<string, unknown>) : {};
  const idToken = await signIdentityToken(
    config.privateJwk,
    config.publicUrl,
    audienceForOrigin(row.origin),
    insertedId,
    pairwiseSub,
    profile,
    now,
  );

  return json({ id_token: idToken, token_type: "Bearer", expires_in: 900 }, 200, {
    "access-control-allow-origin": "*",
  });
}

/** /account/overview handler. */
async function accountOverview(
  config: AppConfig,
  providerSub: string,
  currentJti: string,
  profile: { email: string | null; name: string | null; picture: string | null },
  now: number,
  cors: Record<string, string>,
): Promise<Response> {
  const [grants, sessions] = await Promise.all([
    listActiveGrants(config.db, providerSub),
    listActiveSessions(config.db, providerSub, now),
  ]);
  return json(
    {
      // Safe display-only profile from the verified account-origin token.
      // Apps signed in with a stricter (private) profile do not leak through.
      account: {
        name: profile.name,
        email: profile.email,
        picture: profile.picture,
      },
      apps: grants.map((g) => ({
        origin: g.origin,
        profileAllowed: g.profile_allowed === 1,
      })),
      sessions: sessions.map((s) => ({
        id: s.id,
        origin: s.origin,
        created_at: s.created_at,
        expires_at: s.expires_at,
      })),
      currentSessionId: currentJti,
    },
    200,
    cors,
  );
}

/** /account/grants handler. */
async function accountGrants(config: AppConfig, providerSub: string, cors: Record<string, string>): Promise<Response> {
  const grants = await listActiveGrants(config.db, providerSub);
  return json(
    {
      grants: grants.map((g) => ({
        origin: g.origin,
        profileAllowed: g.profile_allowed === 1,
      })),
    },
    200,
    cors,
  );
}

/** /account/sessions/revoke handler. */
async function accountSessionsRevoke(
  req: Request,
  config: AppConfig,
  providerSub: string,
  now: number,
  cors: Record<string, string>,
): Promise<Response> {
  const body = await readJson<{ sessionId?: string }>(req);
  if (!body || typeof body.sessionId !== "string") {
    return json({ error: "invalid_request" }, 400, cors);
  }
  await revokeOwnedSession(config.db, body.sessionId, providerSub, now);
  return json({ status: "revoked" }, 200, cors);
}

/** /account/grants/revoke handler. */
async function accountGrantsRevoke(
  req: Request,
  config: AppConfig,
  providerSub: string,
  now: number,
  cors: Record<string, string>,
): Promise<Response> {
  const body = await readJson<{ origin?: string }>(req);
  if (!body || typeof body.origin !== "string") {
    return json({ error: "invalid_request" }, 400, cors);
  }
  // Normalize the target origin via the same validation used everywhere.
  let targetOrigin: string;
  try {
    // body.origin is an origin string; validate via URL parsing.
    targetOrigin = appOrigin(body.origin.includes("://") ? body.origin : `https://${body.origin}/`);
  } catch {
    return json({ error: "invalid_request" }, 400, cors);
  }
  await revokeGrantAndSessions(config.db, providerSub, targetOrigin, now);
  return json({ status: "revoked" }, 200, cors);
}

/**
 * Scheduled handler: clean up expired flows, codes, and expired/revoked
 * sessions according to the documented retention windows.
 */
export async function handleScheduled(config: AppConfig, deps: { now?: () => number } = {}): Promise<void> {
  const now = deps.now?.() ?? Date.now();
  await cleanupExpired(config.db, now);
}
