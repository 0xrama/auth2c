# Data Retention

This document covers the data stored in each database table, the exact cleanup windows implemented by the scheduled handler, and the consequences of revocation.

## Database tables and data

### `flows`

Stores in-flight OAuth login flows from `/authorize` until callback completion.

| Column                | Type              | Description                                                                     |
| --------------------- | ----------------- | ------------------------------------------------------------------------------- |
| `id`                  | TEXT PK           | Random 32-byte base64url token; also used as the OAuth `state` and cookie value |
| `redirect_uri`        | TEXT              | The exact redirect URI validated and stored at `/authorize`                     |
| `origin`              | TEXT              | Canonical origin derived from `redirect_uri`                                    |
| `challenge`           | TEXT              | PKCE S256 code challenge                                                        |
| `client_state`        | TEXT              | The app's `state` parameter (passed through to the redirect)                    |
| `request_profile`     | INTEGER           | 1 if `openid email profile` scope requested, 0 otherwise                        |
| `created_at`          | INTEGER           | Millisecond timestamp of flow creation                                          |
| `nonce`               | TEXT, nullable    | OIDC nonce persisted for callback verification (added in 0003)                  |
| `callback_claim_id`   | TEXT, nullable    | UUID set when a callback atomically claims the flow (added in 0003)             |
| `callback_claimed_at` | INTEGER, nullable | Timestamp of the claim (added in 0003)                                          |

**Retention**: Flows are deleted by the scheduled cleanup when `created_at < (now - FLOW_TTL_MS)`, where `FLOW_TTL_MS = 600_000` (10 minutes). Successfully completed flows are deleted immediately as part of the transactional callback batch. Stuck or abandoned flows are cleaned up after the 10-minute window.

### `codes`

Stores one-time authorization codes issued at callback completion, consumed at `/token`.

| Column         | Type              | Description                                                       |
| -------------- | ----------------- | ----------------------------------------------------------------- |
| `code_hash`    | TEXT PK           | SHA-256 hash of the raw authorization code                        |
| `provider_sub` | TEXT              | Google identity provider subject (never exposed externally)       |
| `origin`       | TEXT              | Canonical origin of the relying party                             |
| `redirect_uri` | TEXT              | Exact redirect URI stored at callback; must match at redemption   |
| `challenge`    | TEXT              | PKCE S256 challenge; must match `SHA-256(verifier)` at redemption |
| `profile`      | TEXT, nullable    | JSON-serialized profile (email, name, picture) or null            |
| `expires_at`   | INTEGER           | Millisecond timestamp; code is invalid after this time            |
| `created_at`   | INTEGER, nullable | Millisecond timestamp of code creation (added in 0003)            |

**Retention**: Codes are deleted by the scheduled cleanup when `expires_at < now` (i.e., after they have expired). The code lifetime is `CODE_TTL_MS = 120_000` (2 minutes). Successfully redeemed codes are deleted atomically at redemption time (`DELETE ... RETURNING`).

### `grants`

Stores the authorization grant linking a Google identity to a relying-party origin.

| Column            | Type              | Description                                             |
| ----------------- | ----------------- | ------------------------------------------------------- |
| `provider_sub`    | TEXT              | Google identity provider subject (composite PK)         |
| `origin`          | TEXT              | Canonical origin of the relying party (composite PK)    |
| `profile_allowed` | INTEGER           | 1 if the user consented to sharing profile, 0 otherwise |
| `revoked_at`      | INTEGER, nullable | Timestamp of revocation; null means active              |

**Retention**: Grants have **no scheduled cleanup**. Active grants persist indefinitely. Revoked grants (with a non-null `revoked_at`) also persist indefinitely — they are retained so that the same user re-authenticating for the same origin can reactivate the grant (the callback batch uses `ON CONFLICT ... DO UPDATE SET revoked_at = NULL`).

### `sessions`

Stores active authentication sessions, each bound to a grant.

| Column         | Type              | Description                                               |
| -------------- | ----------------- | --------------------------------------------------------- |
| `id`           | TEXT PK           | Session ID; also used as the JWT `jti` claim              |
| `provider_sub` | TEXT              | Google identity provider subject                          |
| `origin`       | TEXT              | Canonical origin of the relying party                     |
| `created_at`   | INTEGER           | Millisecond timestamp of session creation                 |
| `expires_at`   | INTEGER           | Millisecond timestamp; session is invalid after this time |
| `revoked_at`   | INTEGER, nullable | Timestamp of revocation; null means active                |

**Retention**: The scheduled cleanup deletes sessions only when **both** `expires_at < now` **and** `revoked_at IS NOT NULL`. See the mismatch note below.

## Exact cleanup implementation

The scheduled handler runs every 6 hours (cron `0 */6 * * *`) and executes `cleanupExpired(db, now)`, which runs one D1 `batch`:

```sql
DELETE FROM flows WHERE created_at < ?    -- cutoff = now - FLOW_TTL_MS (600_000ms = 10min)
DELETE FROM codes WHERE expires_at < ?     -- cutoff = now (deletes all expired codes)
DELETE FROM sessions WHERE expires_at < ? AND revoked_at IS NOT NULL  -- see below
```

### Cleanup windows summary

| Table                           | Cleanup condition                             | Effective window                           |
| ------------------------------- | --------------------------------------------- | ------------------------------------------ |
| `flows`                         | `created_at < (now - 600_000)`                | Up to 10 minutes + 6-hour cleanup interval |
| `codes`                         | `expires_at < now`                            | Up to 2 minutes + 6-hour cleanup interval  |
| `sessions` (revoked)            | `expires_at < now AND revoked_at IS NOT NULL` | Up to 15 minutes + 6-hour cleanup interval |
| `sessions` (expired, unrevoked) | **Not cleaned**                               | Retained indefinitely                      |
| `grants` (active or revoked)    | **Not cleaned**                               | Retained indefinitely                      |

### Claimed callback safety window

Flows that have been claimed for callback processing (`callback_claim_id IS NOT NULL`) are cleaned up on the same basis as other flows — after the 10-minute `FLOW_TTL_MS` window. If a callback fails transiently and the claim is released, the flow is eligible for retry until it ages out or is successfully completed. If a callback gets stuck (claim never released, batch never completed), the flow is swept after the 10-minute window, and the user must restart the login flow.

## Implementation mismatch: expired-unrevoked sessions

**The current cleanup code does not delete sessions that have expired but were never revoked.** The condition is:

```sql
DELETE FROM sessions WHERE expires_at < ? AND revoked_at IS NOT NULL
```

This means the `sessions` table grows unbounded for users who simply let their tokens expire without explicitly signing out. Every time a user authenticates, a new session row is created; expired sessions without revocation are never purged.

The indexes `sessions_cleanup(expires_at, revoked_at)`, `sessions_provider(provider_sub, expires_at)`, and `sessions_provider_active(provider_sub, revoked_at, expires_at)` are optimized for querying active sessions and cleanup, but the cleanup query only targets the revoked subset.

**This may be intentional** (retaining all session history for audit/forensic purposes) or an oversight. If bounded growth is desired, the cleanup should also delete sessions where `expires_at < now` regardless of `revoked_at`, or after a longer retention period (e.g., 30 days).

## Revocation effects

### `/session/revoke` (single session)

Revokes the session identified by the token's `jti`:

```sql
UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
```

- Idempotent — if already revoked, no rows are updated.
- The token becomes invalid immediately at Auth2C (bearer validation requires `revoked_at IS NULL`).
- The session row is eligible for cleanup after it expires (both `expires_at < now` and `revoked_at IS NOT NULL`).
- Other sessions for the same user/origin are unaffected.

### `/account/sessions/revoke` (targeted session)

Revokes a session only if it belongs to the authenticated `provider_sub`:

```sql
UPDATE sessions SET revoked_at = ? WHERE id = ? AND provider_sub = ? AND revoked_at IS NULL
```

- Cross-account session IDs are indistinguishable from absent IDs (no information disclosure).

### `/account/grants/revoke` (grant + all sessions + codes)

Runs one D1 batch:

```sql
UPDATE grants SET revoked_at = ? WHERE provider_sub = ? AND origin = ? AND revoked_at IS NULL
UPDATE sessions SET revoked_at = ? WHERE provider_sub = ? AND origin = ? AND revoked_at IS NULL
DELETE FROM codes WHERE provider_sub = ? AND origin = ?
```

- Revokes the grant, all active sessions for that provider/origin, and all outstanding authorization codes.
- Other origins for the same provider remain active.
- All affected sessions become eligible for cleanup after expiry.

## Backup implications

- Cloudflare D1 databases are backed up automatically by Cloudflare with point-in-time recovery capability.
- All tables use millisecond-epoch timestamps stored as `INTEGER`.
- The `provider_sub` column stores the raw Google subject — rotating `PAIRWISE_SECRET` does not affect this value. Pairwise subjects are derived at runtime.
- No foreign key constraints exist between tables; referential integrity is enforced at the application level.
- Grants persist through revocation (only `revoked_at` is set). A user who re-authenticates for the same origin reactivates the existing grant rather than creating a new one.
