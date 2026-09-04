/**
 * Shared integration-test harness for the Auth2C Worker.
 *
 * Runs inside the Workers pool (miniflare) so it can reach a real local D1
 * binding via `env`. Google dependencies are injected: a test ES256 (P-256)
 * keypair signs fake id_tokens, and a fake JWKS + token endpoint are served
 * through the injected `fetch` so REAL jose verification runs in google.ts.
 *
 * `now` is a deterministic, mutable clock so expiry assertions do not depend on
 * wall-clock time.
 */
import { env } from "cloudflare:workers";
import { applyD1Migrations } from "cloudflare:test";
import { exportJWK, importJWK, SignJWT, type JWK } from "jose";
import { randomToken, sha256 } from "@auth2c/protocol";
import { handleRequest, type HandlerDeps } from "../src/app.js";
import { validateEnv, type AppConfig, type Env as WorkerEnv } from "../src/env.js";
import type { GoogleDeps } from "../src/google.js";

// `env` from cloudflare:workers is typed as `Cloudflare.Env`, an ambient
// interface declared by @cloudflare/workers-types and intended to be merged by
// the project. Augment it with our worker Env shape plus the test-only
// TEST_MIGRATIONS binding so `env.DB` / `env.TEST_MIGRATIONS` type-check.
declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {
      /** Parsed D1 migrations, supplied as a binding by vitest.config.ts. */
      TEST_MIGRATIONS: { name: string; queries: string[] }[];
    }
  }
}

// ---- fixed test configuration ----
export const PUBLIC_URL = "https://auth.test";
export const ACCOUNT_ORIGIN = PUBLIC_URL;
export const APP_ORIGIN = "https://app.test";
export const GOOGLE_CLIENT_ID = "google-test-client-123.apps.example";
export const GOOGLE_CLIENT_SECRET = "google-test-secret";
export const PAIRWISE_SECRET = "test-pairwise-secret-not-for-production";

/** Canonical Google issuers (matches google.ts). */
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
/** Token URL hardcoded in google.ts; intercepted via the injected fetch. */
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
/** Fake JWKS URL; the injected fetch answers here with the test public key. */
export const FAKE_JWKS_URL = "https://test-fake-googleapis.test/oauth2/v3/certs";
/** Stable key id for the test Google signing key. */
const GOOGLE_KID = "google-test-key-v1";

// ---- deterministic clock ----
/** Base time: 2026-01-01T00:00:00Z. */
export const BASE_TIME = Date.UTC(2026, 0, 1);
let currentTime = BASE_TIME;

/** The deterministic "now" used by every handleRequest call in tests. */
export function now(): number {
  return currentTime;
}
export function setNow(t: number): void {
  currentTime = t;
}
export function advance(ms: number): void {
  currentTime += ms;
}
export function resetTime(): void {
  currentTime = BASE_TIME;
}

// ---- per-isolate keypairs (lazy singleton) ----
export interface TestKeys {
  configPrivate: JWK;
  configPublic: JWK;
  googlePrivate: JWK;
  googlePublic: JWK;
  /** Imported CryptoKey for signing Google id_tokens with jose. */
  googleCryptoKey: CryptoKey;
  /** Imported CryptoKey for signing Auth2C identity tokens (manual cases). */
  configCryptoKey: CryptoKey;
}
let keysPromise: Promise<TestKeys> | null = null;

export function getTestKeys(): Promise<TestKeys> {
  if (!keysPromise) {
    keysPromise = (async () => {
      const gen = () => crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      const configPair = await gen();
      const googlePair = await gen();
      const configPrivate = (await exportJWK(configPair.privateKey)) as JWK;
      const configPublic = (await exportJWK(configPair.publicKey)) as JWK;
      const googlePrivate = (await exportJWK(googlePair.privateKey)) as JWK;
      const googlePublic = (await exportJWK(googlePair.publicKey)) as JWK;
      for (const k of [configPrivate, configPublic, googlePrivate, googlePublic]) k.alg = "ES256";
      const googleCryptoKey = (await importJWK({ ...googlePrivate, kid: GOOGLE_KID }, "ES256")) as CryptoKey;
      const configCryptoKey = (await importJWK({ ...configPrivate, kid: "auth2c-v1" }, "ES256")) as CryptoKey;
      return {
        configPrivate,
        configPublic,
        googlePrivate,
        googlePublic,
        googleCryptoKey,
        configCryptoKey,
      };
    })();
  }
  return keysPromise;
}

/** Build an AppConfig via the production validateEnv path with test keys. */
export async function getConfig(): Promise<AppConfig> {
  const k = await getTestKeys();
  return validateEnv({
    DB: env.DB,
    PUBLIC_URL,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    PAIRWISE_SECRET,
    PRIVATE_JWK: JSON.stringify(k.configPrivate),
    PUBLIC_JWK: JSON.stringify(k.configPublic),
  });
}

/** Apply every D1 migration (idempotent — safe to call once per test file). */
export async function applyAllMigrations(): Promise<void> {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
}

/** Apply a subset of migrations matched by name prefix (e.g. "0001"). */
export async function applyMigrationsMatching(...prefixes: string[]): Promise<void> {
  const subset = env.TEST_MIGRATIONS.filter((m) => prefixes.some((p) => m.name.startsWith(p)));
  await applyD1Migrations(env.DB, subset);
}

/** All rows for a column expression, scoped helper. */
export function db(): D1Database {
  return env.DB;
}

// ---- Google id_token signing ----
export interface GoogleSignOpts {
  sub?: string;
  nonce?: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  picture?: string;
  issuer?: string;
  audience?: string;
  expiresIn?: string;
  omitNonce?: boolean;
  omitSub?: boolean;
}

/** Sign a Google id_token with the test ES256 key. Real jose verification runs in google.ts. */
export async function signGoogleIdToken(opts: GoogleSignOpts = {}): Promise<string> {
  const k = await getTestKeys();
  const sub = opts.omitSub ? undefined : (opts.sub ?? "google-sub-default");
  const issuer = opts.issuer ?? GOOGLE_ISSUERS[0];
  const audience = opts.audience ?? GOOGLE_CLIENT_ID;
  const payload: Record<string, unknown> = {};
  if (!opts.omitNonce) payload.nonce = opts.nonce ?? "missing-nonce-placeholder";
  if (opts.email !== undefined) payload.email = opts.email;
  if (opts.emailVerified !== undefined) payload.email_verified = opts.emailVerified;
  if (opts.name !== undefined) payload.name = opts.name;
  if (opts.picture !== undefined) payload.picture = opts.picture;
  const builder = new SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", kid: GOOGLE_KID, typ: "JWT" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(opts.expiresIn ?? "1h");
  if (sub !== undefined) builder.setSubject(sub);
  return builder.sign(k.googleCryptoKey);
}

// ---- fake Google fetch (token endpoint + JWKS endpoint) ----
export interface GoogleFetchOpts {
  /** id_token to return from the fake token endpoint. */
  idToken?: string;
  /** If set, the token endpoint responds with this non-200 status. */
  errorStatus?: number;
  errorBody?: Record<string, unknown>;
  /** If true, the token endpoint fetch throws (transient network error). */
  throwOnToken?: boolean;
  /** Optional hook invoked before the token endpoint responds. */
  onTokenRequest?: () => Promise<void>;
}

export function makeGoogleDeps(opts: GoogleFetchOpts = {}): GoogleDeps {
  const fetchImpl: typeof fetch = async (input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith(FAKE_JWKS_URL)) {
      const k = await getTestKeys();
      const jwks = {
        keys: [{ ...k.googlePublic, kid: GOOGLE_KID, use: "sig", alg: "ES256" }],
      };
      return new Response(JSON.stringify(jwks), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (url === GOOGLE_TOKEN_URL) {
      if (opts.onTokenRequest) await opts.onTokenRequest();
      if (opts.throwOnToken) throw new Error("simulated network error");
      if (opts.errorStatus || opts.errorBody) {
        return new Response(JSON.stringify(opts.errorBody ?? { error: "invalid_grant" }), {
          status: opts.errorStatus ?? 400,
          headers: { "content-type": "application/json" },
        });
      }
      if (opts.idToken !== undefined) {
        return new Response(JSON.stringify({ id_token: opts.idToken, token_type: "Bearer", expires_in: 3600 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error("test misconfiguration: no id_token configured for fake token endpoint");
    }
    return new Response("not found", { status: 404 });
  };
  return { fetch: fetchImpl, jwksUrl: new URL(FAKE_JWKS_URL) };
}

// ---- request / response helpers ----
/** Base HandlerDeps with the deterministic clock and ambient randomUUID. */
export function baseDeps(): HandlerDeps {
  return { now };
}

/**
 * Drive handleRequest directly. Mirrors index.ts: a thrown Error becomes a 400
 * Response whose body carries the message, so tests can uniformly assert on the
 * response status / body.
 */
export async function call(
  method: string,
  pathAndQuery: string,
  init: { body?: unknown; headers?: Record<string, string> } = {},
  deps: HandlerDeps = baseDeps(),
): Promise<Response> {
  const config = await getConfig();
  const url = new URL(pathAndQuery, PUBLIC_URL);
  const headers = new Headers(init.headers ?? {});
  let body: BodyInit | undefined;
  if (init.body !== undefined) {
    if (typeof init.body === "string") {
      body = init.body;
    } else {
      body = JSON.stringify(init.body);
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
    }
  }
  const req = new Request(url, { method, headers, body });
  try {
    return await handleRequest(req, config, deps);
  } catch (e) {
    const message = e instanceof Error ? e.message : "Request failed";
    return new Response(message, {
      status: 400,
      headers: { "content-type": "text/html;charset=utf-8" },
    });
  }
}

/** Parse all Set-Cookie header values into a name→value map. */
export function parseSetCookie(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  const getter = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  const list = getter
    ? getter.call(res.headers)
    : (res.headers.get("set-cookie")?.split(/,(?=\s*[\w!#$%&'*+.^`|~-]+=)/) ?? []);
  for (const c of list) {
    const m = c.match(/^([^=;]+)=([^;]*)/);
    if (m) out[m[1].trim()] = m[2].trim();
  }
  return out;
}

export function parseLocation(res: Response): URL {
  const loc = res.headers.get("location");
  if (!loc) throw new Error(`expected Location header (status=${res.status})`);
  return new URL(loc);
}

export function locationParams(res: Response): URLSearchParams {
  return parseLocation(res).searchParams;
}

export async function jsonBody(res: Response): Promise<Record<string, unknown>> {
  return JSON.parse(await res.text()) as Record<string, unknown>;
}

/** Decode a JWT payload without verification (test assertions only). */
export function decodeJwtPayload(token: string): Record<string, unknown> {
  const p = token.split(".")[1];
  const s = p.replace(/-/g, "+").replace(/_/g, "/");
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  return JSON.parse(atob(padded)) as Record<string, unknown>;
}

// ---- PKCE helpers ----
export async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  // 32 bytes -> 43 base64url chars (the S256 minimum).
  const verifier = randomToken(32);
  const challenge = await sha256(verifier);
  return { verifier, challenge };
}

/**
 * Manually sign an Auth2C identity token with arbitrary claims, signed with the
 * test config private key. Used to construct tokens that exercise specific
 * rejection paths (array audience, mismatched sub/jti/origin, custom expiry).
 */
export async function signCustomIdentityToken(args: {
  audience: string | string[];
  jti: string;
  sub: string;
  profile?: Record<string, unknown>;
  issuer?: string;
  issuedAtSeconds?: number;
  expiresInSeconds?: number;
}): Promise<string> {
  const k = await getTestKeys();
  const iat = args.issuedAtSeconds ?? Math.floor(currentTime / 1000);
  const exp = iat + (args.expiresInSeconds ?? 900);
  return new SignJWT({ sub: args.sub, pairwise_sub: args.sub, ...(args.profile ?? {}) })
    .setProtectedHeader({ alg: "ES256", kid: "auth2c-v1" })
    .setIssuer(args.issuer ?? PUBLIC_URL)
    .setAudience(args.audience)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setJti(args.jti)
    .sign(k.configCryptoKey);
}

/** Insert a session + grant row directly (for rejection / revocation tests). */
export async function seedSession(args: {
  sessionId: string;
  providerSub: string;
  origin: string;
  profileAllowed?: number;
  nowMs?: number;
  expiresAtMs?: number;
  revokedAtMs?: number | null;
}): Promise<void> {
  const n = args.nowMs ?? currentTime;
  const expiresAt = args.expiresAtMs ?? (Math.floor(n / 1000) + 900) * 1000;
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO grants (provider_sub, origin, profile_allowed, revoked_at) VALUES (?, ?, ?, ?) " +
        "ON CONFLICT(provider_sub, origin) DO UPDATE SET revoked_at = NULL, profile_allowed = excluded.profile_allowed",
    ).bind(args.providerSub, args.origin, args.profileAllowed ?? 0, args.revokedAtMs ?? null),
    env.DB.prepare(
      "INSERT INTO sessions (id, provider_sub, origin, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).bind(args.sessionId, args.providerSub, args.origin, n, expiresAt, args.revokedAtMs ?? null),
  ]);
}

/** Count rows in `table` matching `where` (bound to `params`). */
export async function countRows(table: string, where: string, params: unknown[]): Promise<number> {
  const r = await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE ${where}`)
    .bind(...params)
    .first<{ n: number }>();
  return r?.n ?? 0;
}

/** Get a single row in `table` matching `where`. */
export async function getRow<T>(table: string, where: string, params: unknown[]): Promise<T | null> {
  return env.DB.prepare(`SELECT * FROM ${table} WHERE ${where}`)
    .bind(...params)
    .first<T>();
}

// ---- high-level flow helpers ----
export interface AuthorizeResult {
  status: number;
  flowId: string;
  nonce: string;
  cookieHeader: string;
  redirectUri: string;
  state: string;
  verifier: string;
  location: URL;
}

/** Drive GET /authorize with PKCE; return the parsed flow fields. */
export async function authorize(
  opts: {
    redirectUri?: string;
    state?: string;
    requestProfile?: boolean;
    googleSub?: string;
    extraParams?: Record<string, string>;
  } = {},
): Promise<AuthorizeResult & { googleSub?: string }> {
  const redirectUri = opts.redirectUri ?? `${APP_ORIGIN}/cb`;
  const { verifier, challenge } = await pkcePair();
  const state = opts.state ?? randomToken(18);
  const params = new URLSearchParams({
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    ...(opts.requestProfile ? { scope: "openid email profile" } : {}),
    ...(opts.extraParams ?? {}),
  });
  const res = await call("GET", `/authorize?${params}`);
  const location = parseLocation(res);
  const flowId = location.searchParams.get("state") ?? "";
  const nonce = location.searchParams.get("nonce") ?? "";
  return {
    status: res.status,
    flowId,
    nonce,
    cookieHeader: `a2c_flow=${flowId}`,
    redirectUri,
    state,
    verifier,
    location,
  };
}

/** Drive GET /oauth/google/callback with a cookie + GoogleDeps. */
export async function googleCallback(args: {
  flowId: string;
  googleCode?: string;
  google: GoogleDeps;
}): Promise<Response> {
  const code = args.googleCode ?? `g-${randomToken(12)}`;
  const params = new URLSearchParams({ code, state: args.flowId });
  return call(
    "GET",
    `/oauth/google/callback?${params}`,
    { headers: { cookie: `a2c_flow=${args.flowId}` } },
    { ...baseDeps(), google: args.google },
  );
}

/** Drive POST /token. */
export async function tokenExchange(args: { code: string; verifier: string; redirectUri: string }): Promise<Response> {
  return call("POST", "/token", {
    body: { code: args.code, code_verifier: args.verifier, redirect_uri: args.redirectUri },
  });
}

export interface LoginResult extends AuthorizeResult {
  auth2cCode: string;
  idToken: string;
  claims: Record<string, unknown>;
  googleSub: string;
}

/** Run the full /authorize -> /callback -> /token happy path. */
export async function runLoginFlow(
  opts: {
    redirectUri?: string;
    state?: string;
    requestProfile?: boolean;
    googleSub?: string;
    googleIdTokenOpts?: GoogleSignOpts;
  } = {},
): Promise<LoginResult> {
  const ar = await authorize(opts);
  if (ar.status !== 302) throw new Error(`/authorize failed: ${ar.status}`);
  const googleSub = opts.googleSub ?? `google-sub-${randomToken(6)}`;
  const idToken = await signGoogleIdToken({
    sub: googleSub,
    nonce: ar.nonce,
    email: "user@example.com",
    emailVerified: true,
    name: "Test User",
    picture: "https://example.test/avatar.png",
    ...opts.googleIdTokenOpts,
  });
  const cb = await googleCallback({
    flowId: ar.flowId,
    google: makeGoogleDeps({ idToken }),
  });
  if (cb.status !== 302) throw new Error(`/callback failed: ${cb.status}: ${await cb.text()}`);
  const auth2cCode = locationParams(cb).get("code") ?? "";
  const tok = await tokenExchange({ code: auth2cCode, verifier: ar.verifier, redirectUri: ar.redirectUri });
  if (tok.status !== 200) throw new Error(`/token failed: ${tok.status}: ${await tok.text()}`);
  const body = await jsonBody(tok);
  const jwt = body.id_token as string;
  return { ...ar, auth2cCode, idToken: jwt, claims: decodeJwtPayload(jwt), googleSub };
}
