/**
 * Auth2C token signing and strict bearer/session validation.
 *
 * Signing produces ES256 tokens with a scalar `origin:<origin>` audience and a
 * `jti` equal to the session id. Validation is strict: it verifies the
 * signature/issuer/expiry, requires a scalar audience, and then enforces an
 * *active session row* keyed by `jti` — a signed-but-revoked token is rejected
 * immediately, because Auth2C revocation is row-level.
 */
import { createLocalJWKSet, importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import {
  pairwiseSubject,
  parseVerifiedClaims,
  originFromAudience,
  timingSafeEqual,
  TOKEN_TTL_SECONDS,
} from "@auth2c/protocol";
import type { AppConfig } from "./env.js";
import { getActiveGrant, getActiveSession, type GrantRow, type SessionRow } from "./db.js";

/** Result of authenticating a bearer token against the live session/grant state. */
export interface AuthenticatedSession {
  claims: {
    sub: string;
    aud: string;
    jti: string;
    iat: number;
    exp: number;
  };
  origin: string;
  providerSub: string;
  /** Safe display-only profile fields from the verified signed token. */
  profile: {
    email: string | null;
    name: string | null;
    picture: string | null;
  };
  session: SessionRow;
  grant: GrantRow;
}

/** Outcome of strict bearer validation. */
export type ValidateTokenResult =
  | { ok: true; auth: AuthenticatedSession }
  | { ok: false; status: number; body: { error: string } };

/** Build a verification key set from the configured public JWK. */
function verificationKeySet(publicJwk: JWK) {
  const key = { ...publicJwk, kid: "auth2c-v1", use: "sig", alg: "ES256" };
  return createLocalJWKSet({ keys: [key] });
}

/** Profile fields embedded in a signed token (display-only). */
export interface ProfileClaims {
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
  [k: string]: unknown;
}

/**
 * Sign an Auth2C identity token bound to a session id / origin.
 */
export async function signIdentityToken(
  privateJwk: JWK,
  issuer: string,
  audience: string,
  sessionId: string,
  pairwiseSub: string,
  profile: ProfileClaims,
  nowMs: number,
): Promise<string> {
  const key = await importJWK({ ...privateJwk, kid: "auth2c-v1" }, "ES256");
  const nowSeconds = Math.floor(nowMs / 1000);
  return new SignJWT({ sub: pairwiseSub, pairwise_sub: pairwiseSub, ...profile })
    .setProtectedHeader({ alg: "ES256", kid: "auth2c-v1" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + TOKEN_TTL_SECONDS)
    .setJti(sessionId)
    .sign(key);
}

/**
 * Strictly validate a bearer token against live session/grant rows.
 *
 * Steps:
 *  1. Verify ES256 signature, exact issuer, expiry, and a scalar
 *     `origin:<origin>` audience; parse required claims.
 *  2. Load the session by id (`jti`) and require it active (unrevoked/unexpired).
 *  3. Require the session's origin to match the audience origin.
 *  4. Recompute the pairwise subject from the session's stored `provider_sub`
 *     and origin, and require it to equal the token `sub`.
 *  5. Require an active (non-revoked) grant for that provider/origin.
 *
 * Returns a typed failure (HTTP status + body) or the authenticated binding.
 */
export async function validateBearer(req: Request, config: AppConfig, now: number): Promise<ValidateTokenResult> {
  const authHeader = req.headers.get("authorization");
  const token = authHeader?.replace(/^Bearer\s+/i, "");
  if (!token) {
    return { ok: false, status: 401, body: { error: "invalid_token" } };
  }

  let claims;
  let profile: AuthenticatedSession["profile"];
  try {
    const keySet = verificationKeySet(config.publicJwk);
    const { payload } = await jwtVerify(token, keySet, {
      issuer: config.publicUrl,
      currentDate: new Date(now),
    });
    claims = parseVerifiedClaims(payload as Record<string, unknown>);
    profile = {
      email: typeof payload.email === "string" ? payload.email : null,
      name: typeof payload.name === "string" ? payload.name : null,
      picture: typeof payload.picture === "string" ? payload.picture : null,
    };
  } catch {
    return { ok: false, status: 401, body: { error: "invalid_token" } };
  }

  // Scalar audience of exactly origin:<origin> is enforced by parseVerifiedClaims.
  const audienceOrigin = originFromAudience(claims.aud);

  const session = await getActiveSession(config.db, claims.jti, now);
  if (!session) {
    return { ok: false, status: 401, body: { error: "invalid_token" } };
  }

  // Session origin must match the audience origin.
  if (session.origin !== audienceOrigin) {
    return { ok: false, status: 401, body: { error: "invalid_token" } };
  }

  // Recompute pairwise subject from stored provider subject + origin.
  const expectedSub = await pairwiseSubject(config.pairwiseSecret, session.provider_sub, session.origin);
  if (!(await timingSafeEqual(expectedSub, claims.sub))) {
    return { ok: false, status: 401, body: { error: "invalid_token" } };
  }

  const grant = await getActiveGrant(config.db, session.provider_sub, session.origin);
  if (!grant) {
    return { ok: false, status: 401, body: { error: "invalid_token" } };
  }

  return {
    ok: true,
    auth: {
      claims,
      origin: session.origin,
      providerSub: session.provider_sub,
      profile,
      session,
      grant,
    },
  };
}
