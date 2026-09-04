# Auth2C

Auth2C is a zero-registration, privacy-first identity broker. An app supplies its callback URL; Auth2C derives its audience from that origin, runs Google OAuth with mandatory PKCE, and returns an ES256-signed, origin-scoped identity token.

## What is included

- Google OpenID Connect broker with strict redirect validation
- PKCE S256 authorization-code flow and one-time codes
- pairwise, origin-scoped subjects (HMAC-SHA256 keyed derivation)
- persisted OIDC nonce with atomic single-winner callback claim
- transactional callback completion (grant + code + flow delete in one D1 batch)
- atomic authorization-code redemption (DELETE ... RETURNING, one winner)
- conditional session creation gated on active grant existence
- session validation and per-site revocation (row-level, immediate)
- account-origin authorization enforcement (third-party tokens receive 403)
- scheduled cleanup of expired flows, codes, and revoked/expired sessions
- dependency-free hosted browser SDK (`/auth2c.js`)
- React hook (`@auth2c/react`) and Convex auth adapter
- OpenID discovery (`/.well-known/openid-configuration`, JWKS)
- landing page, account management UI, and hosted developer docs

## Architecture

The project is a monorepo with npm workspaces:

| Package             | Purpose                                                                                   |
| ------------------- | ----------------------------------------------------------------------------------------- |
| `apps/worker`       | Cloudflare Worker + D1 — the canonical authentication runtime                             |
| `packages/protocol` | Portable domain primitives (PKCE, pairwise subject, base64url, SHA-256, audience parsing) |
| `packages/auth`     | Browser SDK TypeScript types and loader (`@auth2c/auth`)                                  |
| `packages/react`    | React hook and Convex adapter (`@auth2c/react`)                                           |

The Worker entry point (`apps/worker/src/index.ts`) wires environment validation and delegates all routing to `app.ts`. Data access is in `db.ts`, Google OIDC integration in `google.ts`, token signing and bearer validation in `tokens.ts`, the hosted browser SDK in `client.ts`, and HTML pages in `pages.ts`.

## Run locally

```bash
cp .dev.vars.example .dev.vars   # then fill in Google credentials
npm install
npm run db:migrate:local         # apply D1 migrations locally
npm run dev                       # starts wrangler dev (local D1 + Worker)
```

Create a Google OAuth web client with callback URL `http://localhost:8787/oauth/google/callback`, then fill in the Google credentials and other bindings in `.dev.vars`. See [docs/local-development.md](docs/local-development.md) for full instructions.

The hosted SDK is served at `http://localhost:8787/auth2c.js`:

```html
<script src="http://localhost:8787/auth2c.js"></script>
<button onclick="Auth2C.signIn({ requestProfile: true })">Sign in</button>
```

## Cloudflare Workers deployment

Before deployment, replace the example domain and D1 database ID in `wrangler.jsonc` with values from your Cloudflare account. Schema migrations are under `migrations/`.

```bash
npm run db:migrate               # apply migrations to remote D1
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put PAIRWISE_SECRET
npx wrangler secret put PRIVATE_JWK
npx wrangler secret put PUBLIC_JWK
npm run deploy
```

The Google OAuth web client must allow this redirect URI:

```text
https://auth.example.com/oauth/google/callback
```

See [docs/deployment.md](docs/deployment.md) for the complete binding/secret reference and rotation procedures.

## Documentation

| Document                                       | Description                                                                         |
| ---------------------------------------------- | ----------------------------------------------------------------------------------- |
| [Local development](docs/local-development.md) | Local setup, D1 migrations, `wrangler dev`, `--local` vs `--remote`                 |
| [Deployment](docs/deployment.md)               | Every binding/secret, generation/provisioning, rotation, migration ordering         |
| [Security](docs/security.md)                   | Authorization model, PKCE/state/nonce, XSS/localStorage, CSP, revocation limits     |
| [Data retention](docs/data-retention.md)       | Per-table data, cleanup windows, claimed callback safety, backup implications       |
| [SDK contract](docs/sdk-contract.md)           | `signIn`, redirect behavior, identity fields, async `signOut`, events, React/Convex |
| [Operations](docs/operations.md)               | Key validation, smoke tests, monitoring, rollback, incident response                |

## npm scripts

| Script                     | Description                                              |
| -------------------------- | -------------------------------------------------------- |
| `npm run dev`              | Start local Worker via `wrangler dev`                    |
| `npm run deploy`           | Deploy Worker to Cloudflare                              |
| `npm run db:migrate`       | Apply D1 migrations to remote production database        |
| `npm run db:migrate:local` | Apply D1 migrations to local D1 (used by `wrangler dev`) |
| `npm run build`            | Build all workspaces (typecheck + compile)               |
| `npm run test`             | Run tests across all workspaces                          |
| `npm run typecheck`        | Typecheck all workspaces                                 |

## Token lifetimes

| Resource             | Lifetime                               |
| -------------------- | -------------------------------------- |
| Identity token (JWT) | 15 minutes (`TOKEN_TTL_SECONDS = 900`) |
| Authorization code   | 2 minutes (`CODE_TTL_MS = 120_000`)    |
| Login flow (cookie)  | 10 minutes (`FLOW_TTL_MS = 600_000`)   |
| Scheduled cleanup    | Every 6 hours (`0 */6 * * *`)          |

## Important notes

- The browser SDK stores bearer tokens in `localStorage` — these are display-only claims. Authoritative revocation checking requires calling `/session/check` server-side.
- `Auth2C.signOut()` is async: it calls `/session/revoke` before clearing local state.
- Third-party app tokens (audience `origin:<other-origin>`) cannot access account routes; they receive `403 insufficient_scope`.
- A signed-but-revoked token is rejected immediately at Auth2C because revocation is enforced at the session row level.
- This is an independent implementation inspired by the product category explored by Shoo; it contains no Shoo source code.
