/**
 * @auth2c/protocol — portable authentication domain primitives.
 *
 * Uses Web Crypto only (no Node APIs) so it runs unchanged in the Cloudflare
 * Worker and in Node-based tests. All functions are pure aside from access to
 * the injected/ambient Web Crypto and TextEncoder.
 */

/**
 * Encode a string as UTF-8 bytes.
 */
export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/**
 * Narrow a Uint8Array to a BufferSource for Web Crypto call sites. This works
 * around a TypeScript lib variance quirk where `Uint8Array<ArrayBufferLike>` is
 * not assignable to `BufferSource` even though the runtime buffer is always a
 * plain ArrayBuffer here.
 */
function buf(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

/**
 * Base64url-encode bytes or an ArrayBuffer. Output has no padding.
 */
export function base64url(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/**
 * Decode a base64url string (with or without padding) into bytes.
 */
export function base64urlDecode(value: string): Uint8Array {
  const s = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

/**
 * Cryptographically-strong random token of `bytes` bytes (default 32),
 * base64url-encoded.
 */
export function randomToken(bytes = 32): string {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return base64url(a);
}

/**
 * SHA-256 digest of `value`, base64url-encoded. Used for PKCE S256 challenges
 * and authorization-code hashing.
 */
export async function sha256(value: string): Promise<string> {
  return base64url(await crypto.subtle.digest("SHA-256", buf(utf8(value))));
}

/** Hosts for which HTTP (not HTTPS) redirect origins are permitted. */
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Derive the canonical origin of a redirect URI and validate the scheme.
 *
 * Rejects URLs containing credentials or a fragment, and any non-HTTPS scheme
 * except loopback HTTP (localhost / 127.0.0.1 / [::1]) used during local
 * development. The returned origin is the exact `protocol://host[:port]`.
 */
export function appOrigin(redirectUri: string): string {
  const url = new URL(redirectUri);
  if (url.username || url.password || url.hash) {
    throw new Error("Invalid redirect_uri");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname))) {
    throw new Error("redirect_uri must use HTTPS (HTTP is allowed on localhost)");
  }
  return url.origin;
}

/**
 * Constant-time string equality. Compares SHA-256 digests of both inputs so the
 * comparison time is independent of where (and whether) the first byte differs,
 * and is safe to call with values of differing length. Digests are async under
 * Web Crypto, so this is async too.
 */
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest("SHA-256", buf(enc.encode(a))),
    crypto.subtle.digest("SHA-256", buf(enc.encode(b))),
  ]);
  const x = new Uint8Array(da);
  const y = new Uint8Array(db);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

/**
 * Derive a pairwise subject: the same provider subject always maps to a stable,
 * distinct identifier per relying-party origin, using an HMAC-SHA256 keyed by
 * the pairwise secret. The output is never the raw provider subject.
 */
export async function pairwiseSubject(secret: string, providerSub: string, origin: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", buf(utf8(secret)), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const sig = await crypto.subtle.sign("HMAC", key, buf(utf8(`${providerSub}\0${origin}`)));
  return `pw_${base64url(sig)}`;
}

/** Token lifetimes in seconds. */
export const TOKEN_TTL_SECONDS = 900; // 15 minutes
/** Authorization-code lifetime in milliseconds. */
export const CODE_TTL_MS = 120_000; // 2 minutes
/** Authorization flow (cookie) lifetime in milliseconds. */
export const FLOW_TTL_MS = 600_000; // 10 minutes

/**
 * Build the canonical audience string for an origin: `origin:<normalized-origin>`.
 */
export function audienceForOrigin(origin: string): string {
  return `origin:${origin}`;
}

/**
 * Parse a strict scalar audience of the form `origin:<origin>` and return the
 * origin. Throws if the audience is an array, missing, or not the expected
 * shape. This is the single source of truth for what an Auth2C token audience
 * means.
 */
export function originFromAudience(aud: unknown): string {
  if (aud === undefined || aud === null || typeof aud === "object") {
    throw new Error("Invalid audience");
  }
  const s = String(aud);
  if (!s.startsWith("origin:")) throw new Error("Invalid audience");
  const origin = s.slice("origin:".length);
  if (!origin) throw new Error("Invalid audience");
  return origin;
}

/**
 * Strict, verified JWT claim set. After signature/issuer/expiry verification,
 * these fields are required and parsed to their canonical types.
 */
export interface VerifiedClaims {
  /** Pairwise subject (`sub`). */
  sub: string;
  /** Scalar audience, exactly `origin:<origin>`. */
  aud: string;
  /** Token / session id (`jti`). */
  jti: string;
  /** Issued-at, seconds since epoch. */
  iat: number;
  /** Expiry, seconds since epoch. */
  exp: number;
}

/**
 * Parse a verified JWT payload into a strict {@link VerifiedClaims}, throwing
 * if any required claim is missing or the audience is an array. The caller is
 * responsible for signature/issuer/expiry verification beforehand.
 */
export function parseVerifiedClaims(payload: Record<string, unknown>): VerifiedClaims {
  const { sub, aud, jti, iat, exp } = payload;
  if (typeof sub !== "string" || !sub) throw new Error("Invalid token: sub");
  if (Array.isArray(aud)) throw new Error("Invalid token: audience must be scalar");
  if (typeof aud !== "string" || !aud.startsWith("origin:")) {
    throw new Error("Invalid token: audience");
  }
  if (typeof jti !== "string" || !jti) throw new Error("Invalid token: jti");
  if (typeof iat !== "number" || !Number.isFinite(iat)) throw new Error("Invalid token: iat");
  if (typeof exp !== "number" || !Number.isFinite(exp)) throw new Error("Invalid token: exp");
  return { sub, aud, jti, iat, exp };
}

/** Minimum PKCE code-challenge length (S256 produces 43 base64url chars). */
export const MIN_CHALLENGE_LEN = 43;
/** Minimum OAuth state length, in characters. */
export const MIN_STATE_LEN = 16;
/** Minimum PKCE code-verifier length, in characters. */
export const MIN_VERIFIER_LEN = 43;

/**
 * Validate a PKCE S256 authorization request's core parameters.
 * Throws on any invalid/missing value.
 */
export function validatePkceRequest(params: {
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  state: string;
}): { origin: string; redirectUri: string } {
  if (
    params.code_challenge.length < MIN_CHALLENGE_LEN ||
    params.code_challenge_method !== "S256" ||
    params.state.length < MIN_STATE_LEN
  ) {
    throw new Error("Invalid PKCE authorization request");
  }
  const origin = appOrigin(params.redirect_uri);
  return { origin, redirectUri: params.redirect_uri };
}

/**
 * Validate a PKCE code-verifier for token exchange.
 */
export function validateCodeVerifier(verifier: string): void {
  if (verifier.length < MIN_VERIFIER_LEN) {
    throw new Error("Invalid code_verifier");
  }
}
