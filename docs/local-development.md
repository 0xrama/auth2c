# Local Development

This document covers setting up and running the Auth2C Worker locally using Wrangler's local mode with an in-memory D1 database.

## Prerequisites

- Node.js (version compatible with Cloudflare Workers; check `engines` if set)
- npm
- A Google Cloud project with an OAuth web client configured for local callbacks

## Setup

```bash
npm install
```

### Google OAuth credentials

Create a Google OAuth web client in the Google Cloud Console:

1. Go to **APIs & Services > Credentials**.
2. Create an **OAuth 2.0 Client ID** of type **Web application**.
3. Add **Authorized redirect URI**: `http://localhost:8787/oauth/google/callback`
4. Copy the **Client ID** and **Client Secret**.

### Local secrets and bindings

Auth2C requires seven bindings. Six are secrets and one (`PUBLIC_URL`) is a plain var in `wrangler.jsonc`.

For local development, create or edit `.dev.vars` in the project root (this file is gitignored):

```ini
PUBLIC_URL=http://localhost:8787
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
PAIRWISE_SECRET=<generate below>
PRIVATE_JWK=<generate below>
PUBLIC_JWK=<generate below>
```

#### Generating a pairwise secret

The pairwise secret is any high-entropy string used as an HMAC-SHA256 key. Generate one with:

```bash
openssl rand -hex 32
```

Example output: `a1b2c3d4e5f6...` (64 hex characters). Paste the entire string as `PAIRWISE_SECRET`.

#### Generating ES256 (P-256) signing keys

Auth2C signs identity tokens with ES256 (ECDSA over P-256). Generate a keypair and extract the JWKs:

```bash
node -e "
const { generateKeyPairSync } = require('crypto');
const pair = generateKeyPairSync('ec', { namedCurve: 'P-256', publicKeyEncoding: { type: 'spki', format: 'jwk' }, privateKeyEncoding: { type: 'pkcs8', format: 'jwk' } });
console.log('PRIVATE_JWK=' + JSON.stringify(pair.privateKey));
console.log('PUBLIC_JWK=' + JSON.stringify(pair.publicKey));
"
```

Alternatively, using the `jose` library already in the project:

```bash
npx tsx -e "
import { generateKeyPair } from 'jose';
const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
console.log('PRIVATE_JWK=' + JSON.stringify(privateKey));
console.log('PUBLIC_JWK=' + JSON.stringify(publicKey));
"
```

Copy each line into `.dev.vars`. The `PRIVATE_JWK` will contain fields `{kty:"EC",crv:"P-256",x,y,d}` and `PUBLIC_JWK` will contain `{kty:"EC",crv:"P-256",x,y}` (no `d`).

### D1 local migrations

Apply the schema to the local (in-memory) D1 database before starting the dev server:

```bash
npm run db:migrate:local
```

This runs `wrangler d1 migrations apply auth2c-production --local`. Wrangler uses a local SQLite file under `.wrangler/` to persist migrations between dev restarts.

To reset the local database, delete the Wrangler state and re-apply:

```bash
rm -rf .wrangler
npm run db:migrate:local
```

## Running the Worker

```bash
npm run dev
```

This runs `wrangler dev`, which:

- Starts a local HTTP server on port 8787.
- Uses the local D1 database from `.wrangler/`.
- Reads bindings from `.dev.vars`.
- Hot-reloads Worker code changes.

The server is available at `http://localhost:8787`.

### Quick verification

- Home page: `http://localhost:8787`
- OpenID configuration: `http://localhost:8787/.well-known/openid-configuration`
- JWKS: `http://localhost:8787/.well-known/jwks.json`
- Hosted SDK: `http://localhost:8787/auth2c.js`
- Docs: `http://localhost:8787/docs`
- Account: `http://localhost:8787/account`

## `--local` vs `--remote`

### `--local` (default for `npm run dev`)

`wrangler dev` uses the **local** D1 database by default. The local database:

- Is stored as a SQLite file in `.wrangler/`.
- Does **not** connect to the Cloudflare production D1 instance.
- Is suitable for development and integration testing.
- Shares the same schema as production (via the same migration files).

When you run `npm run db:migrate:local`, migrations apply only to this local file. Production data is untouched.

### `--remote`

To connect `wrangler dev` to the **production** D1 database (dangerous in development; use only when intentionally testing against real data):

```bash
npx wrangler dev --remote
```

This makes the local Worker process connect to the Cloudflare D1 database `auth2c-production` over the network. All reads and writes go to production. Be careful — code under development could modify or delete production data.

### Migration commands

| Command                    | Target                              |
| -------------------------- | ----------------------------------- |
| `npm run db:migrate:local` | Local D1 (`.wrangler/` SQLite file) |
| `npm run db:migrate`       | Remote production D1                |

Both run the same migration files from `migrations/` against the same database name `auth2c-production`.

## Local Google OAuth flow

When running locally with `PUBLIC_URL=http://localhost:8787`:

1. The `/authorize` endpoint redirects the browser to Google with `redirect_uri=http://localhost:8787/oauth/google/callback`.
2. After Google authentication, Google redirects back to `http://localhost:8787/oauth/google/callback`.
3. Auth2C processes the callback and redirects to the app's `redirect_uri`.

The Google OAuth client must have `http://localhost:8787/oauth/google/callback` in its allowed redirect URIs.

## Running integration tests

```bash
npm run test
```

This runs `vitest` across all workspaces. The Worker tests use Cloudflare's Workers test pool with an isolated local D1 binding, generating deterministic ES256 Google fixtures with the real `jose` verification path.
