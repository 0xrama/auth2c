# Deployment

This document covers every binding, secret, and configuration required to deploy the Auth2C Worker to Cloudflare, including generation, provisioning, rotation, and migration ordering.

## Wrangler configuration

The canonical configuration is in `wrangler.jsonc` at the repository root:

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "auth2c",
  "main": "apps/worker/src/index.ts",
  "compatibility_date": "2026-07-12",
  "routes": [{ "pattern": "auth.example.com", "custom_domain": true }],
  "vars": { "PUBLIC_URL": "https://auth.example.com" },
  "d1_databases": [
    { "binding": "DB", "database_name": "auth2c-production", "database_id": "00000000-0000-0000-0000-000000000000" },
  ],
  "triggers": { "crons": ["0 */6 * * *"] },
}
```

## Complete binding and secret inventory

| Binding                | Type        | Source                          | Description                                                 |
| ---------------------- | ----------- | ------------------------------- | ----------------------------------------------------------- |
| `DB`                   | D1 database | `wrangler.jsonc` `d1_databases` | Primary data store for flows, codes, grants, sessions       |
| `PUBLIC_URL`           | Plain var   | `wrangler.jsonc` `vars`         | Canonical public URL; used as JWT issuer and account origin |
| `GOOGLE_CLIENT_ID`     | Secret      | `wrangler secret put`           | Google OAuth web client ID                                  |
| `GOOGLE_CLIENT_SECRET` | Secret      | `wrangler secret put`           | Google OAuth web client secret                              |
| `PAIRWISE_SECRET`      | Secret      | `wrangler secret put`           | HMAC-SHA256 key for pairwise subject derivation             |
| `PRIVATE_JWK`          | Secret      | `wrangler secret put`           | JSON-encoded ES256 private key (EC P-256, includes `d`)     |
| `PUBLIC_JWK`           | Secret      | `wrangler secret put`           | JSON-encoded ES256 public key (EC P-256, no `d`)            |

### D1 database

- **Binding name**: `DB`
- **Database name**: `auth2c-production`
- **Database ID**: replace the all-zero example in `wrangler.jsonc` with the ID returned by Wrangler
- **Referenced in code**: `apps/worker/src/env.ts` (`Env.DB`)

### Cron trigger

- **Schedule**: `0 */6 * * *` (every 6 hours, at minute 0)
- **Handler**: `scheduled()` in `apps/worker/src/index.ts` → `handleScheduled()` in `apps/worker/src/app.ts`
- **Purpose**: Deletes expired flows, expired codes, and expired-and-revoked sessions

## Generation and provisioning

### 1. Create the D1 database (one-time)

```bash
npx wrangler d1 create auth2c-production
```

Update the returned `database_id` in `wrangler.jsonc`.

### 2. Generate and provision the pairwise secret

```bash
PAIRWISE=$(openssl rand -hex 32)
npx wrangler secret put PAIRWISE_SECRET <<< "$PAIRWISE"
```

Store the value securely offline. The pairwise secret must be the same value used in any environment that needs to verify or derive the same pairwise subjects.

### 3. Generate and provision ES256 signing keys

Generate a P-256 EC keypair:

```bash
node -e "
const { generateKeyPairSync } = require('crypto');
const pair = generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: { type: 'spki', format: 'jwk' },
  privateKeyEncoding: { type: 'pkcs8', format: 'jwk' }
});
console.log('PRIVATE_JWK=' + JSON.stringify(pair.privateKey));
console.log('PUBLIC_JWK=' + JSON.stringify(pair.publicKey));
"
```

Provision each as a separate secret:

```bash
npx wrangler secret put PRIVATE_JWK    # paste the JSON with kty, crv, x, y, d
npx wrangler secret put PUBLIC_JWK     # paste the JSON with kty, crv, x, y
```

The `PUBLIC_JWK` must correspond exactly to `PRIVATE_JWK` minus the private key parameter `d`. Mismatched keys cause all token signature verification to fail.

### 4. Provision Google OAuth credentials

Create a Google OAuth web client in the Google Cloud Console with authorized redirect URI:

```
https://auth.example.com/oauth/google/callback
```

```bash
npx wrangler secret put GOOGLE_CLIENT_ID     # paste client ID
npx wrangler secret put GOOGLE_CLIENT_SECRET  # paste client secret
```

### 5. Apply D1 migrations

```bash
npm run db:migrate
```

This runs `wrangler d1 migrations apply auth2c-production --remote`, applying all migrations from `migrations/` in order.

### 6. Deploy

```bash
npm run deploy
```

This runs `wrangler deploy`.

## Migration ordering

Migrations must be applied **before** deploying Worker code that depends on new columns or indexes. The migration files are:

| Migration                     | Purpose                                                                                                   |
| ----------------------------- | --------------------------------------------------------------------------------------------------------- |
| `0001_initial.sql`            | Creates `flows`, `codes`, `grants` tables and initial indexes                                             |
| `0002_sessions.sql`           | Creates `sessions` table with `sessions_provider` index                                                   |
| `0003_security_hardening.sql` | Adds nonce/claim columns to `flows`, `created_at` to `codes`, multiple active-session and cleanup indexes |

All migrations are additive (new columns are nullable, no column drops or renames). A pre-`0003` Worker continues to function on the older schema because it does not reference the new columns. After `0003` is applied, pre-hardening in-flight flows have `nonce IS NULL` and are rejected at callback time; users must restart the login flow.

**Recommended order**:

1. Apply migrations (`npm run db:migrate`)
2. Verify migration status (`npx wrangler d1 migrations list auth2c-production --remote`)
3. Deploy the Worker (`npm run deploy`)

## Rotation consequences

### Pairwise secret rotation

Rotating `PAIRWISE_SECRET` changes every pairwise subject derived from `(provider_sub, origin)`. Existing tokens still carry the old `sub` claim and will fail validation because the Worker recomputes the expected pairwise subject from the session's stored `provider_sub` and the **new** secret. All active sessions become invalid.

**Consequences of rotating `PAIRWISE_SECRET`**:

- All existing sessions fail bearer validation (recomputed `sub` does not match token `sub`)
- All existing grants remain valid in the database (they are keyed by raw `provider_sub`, not pairwise)
- Users must re-authenticate to obtain new tokens with the new pairwise subjects
- No data loss — grants persist and sessions are re-created on next login

### ES256 signing key rotation

Rotating `PRIVATE_JWK` / `PUBLIC_JWK` changes the signing key used for identity tokens. The JWKS endpoint at `/.well-known/jwks.json` publishes a single key with `kid: "auth2c-v1`. The current implementation does not support multiple active keys or key rotation without redeployment.

**Consequences of rotating the signing key**:

- All existing tokens signed with the old key fail verification at `/session/check` and any relying-party server verification
- All active sessions remain valid in the database (they are keyed by session `id`, not the signing key)
- The JWKS endpoint immediately serves the new public key
- Relying parties that cache JWKS may reject valid tokens until their cache refreshes
- Users must re-authenticate to obtain tokens signed with the new key

**If you need to support key rotation without downtime**, the JWKS endpoint and verification logic would need to be extended to publish and accept multiple `kid` values, with a grace period during which both old and new keys are accepted. This is not currently implemented.

### Google OAuth credential rotation

Rotating `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`:

- The new client must be configured in Google Cloud Console with the same redirect URI
- In-flight flows created with the old credentials will fail at the Google token exchange step
- The flow cookie expires after 10 minutes (`FLOW_TTL_MS`), after which users can retry with the new credentials
- No database changes needed — flows and codes are independent of the Google client ID

## Deploying to a custom domain

The `wrangler.jsonc` route configuration maps an example custom domain:

```jsonc
"routes": [{ "pattern": "auth.example.com", "custom_domain": true }]
```

The `PUBLIC_URL` var must match the custom domain exactly. The Cloudflare dashboard must have the domain's DNS record pointing to the Worker (configured automatically when `custom_domain: true` is set and the zone is in the same account).

## Dry-run verification

Before deploying to production, verify the Worker bundle without actually deploying:

```bash
npx wrangler deploy --dry-run
```

This checks that the Worker code compiles and all bindings are resolvable.
