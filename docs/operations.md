# Operations

Runbook for operating Auth2C in production: validating keys and secrets, applying migrations safely, monitoring cleanup, smoke testing, and incident response.

## Canonical runtime

Auth2C runs as a single Cloudflare Worker (`apps/worker`) backed by one D1 database (`auth2c-production`). There is no second runtime — the Worker is the sole implementation. Local development uses `wrangler dev` against local D1 — see `docs/local-development.md`.

## Environment bindings

All production bindings are configured via `wrangler.jsonc` (vars, D1) and Wrangler secrets. See `docs/deployment.md` for provisioning commands.

| Binding                | Kind       | Notes                                                              |
| ---------------------- | ---------- | ------------------------------------------------------------------ |
| `PUBLIC_URL`           | var        | Canonical issuer / account origin, e.g. `https://auth.example.com` |
| `GOOGLE_CLIENT_ID`     | secret     | Google OAuth web client id                                         |
| `GOOGLE_CLIENT_SECRET` | secret     | Google OAuth web client secret                                     |
| `PAIRWISE_SECRET`      | secret     | HMAC key for pairwise subjects; rotation-sensitive                 |
| `PRIVATE_JWK`          | secret     | ES256 (P-256) private signing key                                  |
| `PUBLIC_JWK`           | secret/var | matching public key (must match `PRIVATE_JWK`)                     |
| `DB`                   | D1 binding | database `auth2c-production`                                       |

## Validating keys and secrets

After provisioning, confirm the configuration is coherent before trusting it:

```bash
# List configured secrets (names only, never values)
npx wrangler secret list

# Public/private JWK match check (extract x,y of both and compare)
node -e "
const priv = JSON.parse(process.env.PRIVATE_JWK || '{}');
const pub  = JSON.parse(process.env.PUBLIC_JWK  || '{}');
console.log(priv.x === pub.x && priv.y === pub.y && priv.crv === 'P-256' ? 'JWK pair matches' : 'JWK MISMATCH');
"
```

Smoke checks against the running Worker:

```bash
curl -s https://auth.example.com/.well-known/openid-configuration | jq .issuer
curl -s https://auth.example.com/.well-known/jwks.json | jq '.keys[0] | {kty,crv,alg,kid}'
```

The `kid` must be `auth2c-v1`, `alg` `ES256`, `crv` `P-256`.

## Migration safety

Migrations live in `migrations/` and are applied in order. `0003_security_hardening.sql` is **additive** (new columns and indexes only) so a pre-hardening Worker keeps running until redeployed.

Safe rollout order (do not reverse):

1. **Compatibility deployment** (already in place): the deployed Worker uses explicit SQL column lists, so an additive migration cannot reorder columns and break it.
2. Apply the migration to production: `npm run db:migrate`.
3. Verify applied: `npx wrangler d1 migrations list auth2c-production --remote`.
4. Deploy the hardened Worker: `npm run deploy`.
5. Purge expectation of in-flight pre-hardening flows — any flow created before step 4 with a `NULL` nonce is rejected as expired and the user simply restarts sign-in.

Rollback constraints:

- Migrations are forward-only. There is no automated down-migration.
- Rolling the Worker back to a pre-hardening version is safe (the new columns are ignored), but rolling the schema back is not supported — back up D1 first.

```bash
# Before any production migration, create a D1 backup in the Cloudflare dashboard
# (D1 > auth2c-production > Backups > Create backup).
npx wrangler d1 migrations list auth2c-production --remote
```

## Scheduled cleanup

The Worker registers a `scheduled` handler (cron, every 6 hours in `wrangler.jsonc` `[triggers]`) that runs `cleanupExpired`:

- Deletes **unclaimed** flows older than `FLOW_TTL_MS` (10 min).
- Deletes **claimed** flows only after a 30-minute claim safety window, so a legitimately in-progress callback is never swept mid-exchange.
- Deletes expired authorization codes (`expires_at < now`).
- Deletes sessions that are both expired **and** revoked (retention of expired-but-active sessions for audit — see `docs/data-retention.md`).

Monitoring:

- Inspect cron invocations in the Cloudflare dashboard under Workers > auth2c > Triggers / Cron Events.
- A failing scheduled handler does not affect request serving, but stale rows will accumulate; treat repeated scheduled failures as an operational alert.

To run cleanup manually against local D1 in tests or scripts, call `handleScheduled(config)` via the test harness; there is no HTTP endpoint for cleanup.

## Smoke tests

Non-secret checks to run after any deploy:

```bash
BASE=https://auth.example.com
curl -fsS $BASE/                                      # home page 200
curl -fsS $BASE/.well-known/openid-configuration | jq # discovery
curl -fsS $BASE/.well-known/jwks.json | jq            # JWKS
curl -fsS $BASE/auth2c.js | head -c 40                # SDK served
curl -fsS -X POST $BASE/session/check                 # 401 without token (expected)
```

A controlled end-to-end check (do this in staging or with a test Google account before promoting):

1. Load the account page and sign in with Google.
2. Confirm `/account/overview` returns your profile, one app grant, and the current session.
3. Revoke the session; confirm `/session/check` returns `401` immediately with the same token.
4. Re-authenticate, then revoke the app grant; confirm all sessions for that origin are revoked and any outstanding code is invalidated.

## Dependency and lockfile hygiene

Dependencies are pinned to exact versions and the lockfile is committed. The CI gate enforces `npm ci` (lockfile must match manifests). To update a dependency:

1. Bump the exact version in the relevant `package.json`.
2. Run `npm install` to regenerate `package-lock.json`.
3. Run `npm run typecheck && npm test && npm run build`.
4. Commit both files in the same change.

Never re-pin a security-relevant dependency (`jose`, `wrangler`) without running the full test suite.

## Incident response

### Suspected stolen browser token

1. The relying party should call `/session/revoke` (or `Auth2C.signOut()`) — the token's session is revoked at the row level and `/session/check` immediately returns `401`.
2. If the token was already exfiltrated, it remains usable only until its 15-minute expiry. There is no way to revoke a self-contained JWT without the session check — relying parties must enforce `/session/check` for sensitive actions.

### Compromised signing key (`PRIVATE_JWK`)

1. Generate a new ES256 keypair and update `PRIVATE_JWK` / `PUBLIC_JWK`.
2. Redeploy. Tokens signed by the old key still verify until relying parties' cached JWKS refresh; the old key remains in JWKS only if manually retained (Auth2C publishes a single key, so old tokens stop validating immediately after redeploy).
3. Because sessions are bound to the live `jti`, revoking sessions is not automatic on key rotation — consider a grant revocation sweep if full invalidation is required.

### Compromised or rotated `PAIRWISE_SECRET`

1. Rotating `PAIRWISE_SECRET` **changes every relying party's `sub` for every user**. This is a breaking event: all issued tokens' `sub` claims no longer match the recomputed pairwise subject, so all sessions effectively invalidate on next `/session/check`.
2. Coordinate with relying parties before rotating; treat it as a user re-authentication event.
3. There is no dual-key pairwise mechanism; rotation is immediate and global.

### Data retention / deletion requests

See `docs/data-retention.md`. Account-level revocation (`/account/grants/revoke`) revokes grants, sessions, and outstanding codes for an origin. Full per-subject purging requires direct D1 access (back up first).

## Observability

- The Worker contains no application logging of secrets, tokens, codes, or verifiers.
- Cloudflare Analytics captures request counts, status codes, and error rates. Use these for health dashboards.
- If configuring Logpush/Real-time Logs, ensure the `Authorization` header and `/token` request bodies are excluded from captured fields.
