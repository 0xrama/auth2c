/**
 * Worker environment binding and startup validation.
 *
 * `Env` is the Cloudflare Worker environment: bindings declared in
 * `wrangler.jsonc`. `validateEnv` parses and validates the bindings once per
 * request composition so route handlers receive a fully-typed, trusted config.
 */
import type { JWK } from "jose";

export interface Env {
  DB: D1Database;
  PUBLIC_URL: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  PAIRWISE_SECRET: string;
  PRIVATE_JWK: string;
  PUBLIC_JWK: string;
}

/** Validated, derived runtime configuration. */
export interface AppConfig {
  db: D1Database;
  /** Canonical PUBLIC_URL with no trailing slash. */
  publicUrl: string;
  /** Normalized origin of PUBLIC_URL (the account-management origin). */
  accountOrigin: string;
  googleClientId: string;
  googleClientSecret: string;
  pairwiseSecret: string;
  privateJwk: JWK;
  publicJwk: JWK;
}

function requireString(env: Record<string, unknown>, key: string): string {
  const v = env[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`Missing required binding: ${key}`);
  }
  return v;
}

/** Derive the origin (scheme://host[:port]) from a URL string. */
export function originOf(url: string): string {
  return new URL(url).origin;
}

/**
 * Validate the raw Worker environment and produce a trusted {@link AppConfig}.
 * Throws on any missing/malformed binding; the caller maps that to a 500.
 */
export function validateEnv(env: Env): AppConfig {
  const publicUrl = requireString(env as unknown as Record<string, unknown>, "PUBLIC_URL").replace(/\/$/, "");
  let publicUrlOrigin: string;
  try {
    publicUrlOrigin = originOf(publicUrl);
  } catch {
    throw new Error("PUBLIC_URL is not a valid URL");
  }

  const googleClientId = requireString(env as unknown as Record<string, unknown>, "GOOGLE_CLIENT_ID");
  const googleClientSecret = requireString(env as unknown as Record<string, unknown>, "GOOGLE_CLIENT_SECRET");
  const pairwiseSecret = requireString(env as unknown as Record<string, unknown>, "PAIRWISE_SECRET");
  const privateJwkStr = requireString(env as unknown as Record<string, unknown>, "PRIVATE_JWK");
  const publicJwkStr = requireString(env as unknown as Record<string, unknown>, "PUBLIC_JWK");

  let privateJwk: JWK;
  let publicJwk: JWK;
  try {
    privateJwk = JSON.parse(privateJwkStr) as JWK;
    publicJwk = JSON.parse(publicJwkStr) as JWK;
  } catch {
    throw new Error("PRIVATE_JWK / PUBLIC_JWK must be valid JSON");
  }
  if (!privateJwk.kty || !publicJwk.kty) {
    throw new Error("PRIVATE_JWK / PUBLIC_JWK are missing required fields");
  }

  if (!env.DB) throw new Error("Missing D1 database binding: DB");

  return {
    db: env.DB,
    publicUrl,
    accountOrigin: publicUrlOrigin,
    googleClientId,
    googleClientSecret,
    pairwiseSecret,
    privateJwk,
    publicJwk,
  };
}
