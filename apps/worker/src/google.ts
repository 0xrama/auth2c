/**
 * Google OIDC integration: authorization URL, token exchange, and signed
 * ID-token verification.
 *
 * `fetch`, the clock, and the JWKS URL are injectable so tests can use
 * deterministic signed Google fixtures without bypassing production
 * verification (real `jose` verification still runs).
 */
import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { randomToken, timingSafeEqual } from "@auth2c/protocol";

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

/** Injectable dependencies for testability. */
export interface GoogleDeps {
  /** Fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch;
  /** JWKS URL (defaults to Google's public certs). */
  jwksUrl?: URL;
}

/** Parameters for building the Google authorization URL. */
export interface GoogleAuthParams {
  googleClientId: string;
  callbackUrl: string;
  flowId: string;
  nonce: string;
  requestProfile: boolean;
}

/**
 * Build the Google authorization URL. The flow id is passed as OAuth `state`;
 * the nonce is freshly generated here and persisted alongside the flow so the
 * callback can require the signed ID-token `nonce` claim to match.
 */
export function buildGoogleAuthUrl(params: GoogleAuthParams): string {
  const u = new URL(GOOGLE_AUTH_URL);
  u.search = new URLSearchParams({
    client_id: params.googleClientId,
    redirect_uri: params.callbackUrl,
    response_type: "code",
    scope: params.requestProfile ? "openid email profile" : "openid",
    state: params.flowId,
    nonce: params.nonce,
    prompt: "select_account",
  }).toString();
  return u.toString();
}

/** Generate a fresh OIDC nonce. */
export function generateNonce(): string {
  return randomToken(18);
}

/** Result of a successful token exchange. */
export interface GoogleTokenExchange {
  idToken: string;
}

/** Outcome of exchanging the authorization code with Google. */
export type ExchangeResult =
  | { ok: true; exchange: GoogleTokenExchange }
  | { ok: false; transient: boolean; message: string };

/**
 * Exchange a Google authorization code for an ID token. A network/HTTP error is
 * treated as transient (the caller may retry the callback); a malformed success
 * body is terminal.
 */
export async function exchangeGoogleCode(
  code: string,
  googleClientId: string,
  googleClientSecret: string,
  callbackUrl: string,
  deps: GoogleDeps = {},
): Promise<ExchangeResult> {
  const fetchImpl = deps.fetch ?? fetch;
  try {
    const res = await fetchImpl(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: googleClientId,
        client_secret: googleClientSecret,
        redirect_uri: callbackUrl,
        grant_type: "authorization_code",
      }),
    });
    if (!res.ok) {
      let description = "Google exchange failed";
      try {
        const body = (await res.json()) as { error_description?: string; error?: string };
        description = body.error_description || body.error || description;
      } catch {
        /* ignore parse error */
      }
      // A 4xx from Google (bad code, etc.) is terminal for this flow; 5xx/network
      // is transient. Treat any non-ok as transient-by-default so the browser
      // may retry, except explicit invalid_grant/bad codes which are terminal.
      const transient = res.status >= 500;
      return { ok: false, transient, message: description };
    }
    const body = (await res.json()) as { id_token?: string };
    if (!body.id_token) return { ok: false, transient: false, message: "Missing id_token" };
    return { ok: true, exchange: { idToken: body.id_token } };
  } catch (e) {
    return {
      ok: false,
      transient: true,
      message: e instanceof Error ? e.message : "Google exchange network error",
    };
  }
}

/** A verified Google ID-token payload. */
export interface VerifiedGoogleId {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
  nonce: string;
}

/** Outcome of verifying a Google ID token. */
export type VerifyResult = { ok: true; id: VerifiedGoogleId } | { ok: false; message: string };

/**
 * Verify a Google ID token: signature (real jose), issuer, audience, required
 * subject, and require the signed `nonce` claim to equal the persisted nonce.
 * Cryptographic/claim/nonce failures are terminal for the flow.
 */
export async function verifyGoogleIdToken(
  idToken: string,
  googleClientId: string,
  expectedNonce: string,
  deps: GoogleDeps = {},
): Promise<VerifyResult> {
  const jwksUrl = deps.jwksUrl ?? new URL(GOOGLE_JWKS_URL);
  // Honor an injected fetch so tests can serve a fake JWKS endpoint while still
  // exercising real jose signature verification. `customFetch` is jose's symbol
  // for a per-key-set fetch implementation.
  const jwks = createRemoteJWKSet(jwksUrl, deps.fetch ? { [customFetch]: deps.fetch } : undefined);
  let payload;
  try {
    ({ payload } = await jwtVerify(idToken, jwks, {
      issuer: GOOGLE_ISSUERS,
      audience: googleClientId,
    }));
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : "ID-token verification failed" };
  }
  if (typeof payload.sub !== "string" || !payload.sub) {
    return { ok: false, message: "Missing provider identity" };
  }
  if (typeof payload.nonce !== "string" || !(await timingSafeEqual(payload.nonce, expectedNonce))) {
    return { ok: false, message: "Nonce mismatch" };
  }
  return {
    ok: true,
    id: {
      sub: payload.sub,
      email: typeof payload.email === "string" ? payload.email : undefined,
      email_verified: payload.email_verified === true,
      name: typeof payload.name === "string" ? payload.name : undefined,
      picture: typeof payload.picture === "string" ? payload.picture : undefined,
      nonce: payload.nonce,
    },
  };
}
