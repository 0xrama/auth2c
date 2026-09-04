# SDK Contract

This document specifies the supported browser and React integration contract for Auth2C. It is the stability surface relying-party apps build against. Breaking changes follow the versioning policy at the end.

## Packages

| Package                                            | Purpose                                                           | Entry                  |
| -------------------------------------------------- | ----------------------------------------------------------------- | ---------------------- |
| Hosted script `https://auth.example.com/auth2c.js` | Zero-dependency browser SDK; exposes the global `window.Auth2C`   | served at `/auth2c.js` |
| `@auth2c/auth`                                     | TypeScript types for `window.Auth2C` and a `getAuth2C()` accessor | built `dist`           |
| `@auth2c/react`                                    | `useAuth2C()` hook and `createAuth2CConvex()` Convex auth adapter | built `dist`           |

The hosted script is the single source of truth for runtime behavior; `@auth2c/auth` and `@auth2c/react` only provide types and thin wrappers over the global.

## Browser API

Load the script from the Auth2C origin, then use the global `Auth2C`:

```html
<script src="https://auth.example.com/auth2c.js"></script>
<button onclick="Auth2C.signIn({ requestProfile: true })">Sign in</button>
<script>
  console.log(Auth2C.getIdentity());
</script>
```

### `signIn(options?) => Promise<void>`

Begins an OAuth + PKCE sign-in by redirecting the browser to Auth2C `/authorize`, then to Google.

`SignInOptions`:

| Option           | Type      | Default                               | Meaning                                                                                                                            |
| ---------------- | --------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `requestProfile` | `boolean` | `false`                               | If true, requests the `openid email profile` scopes and consent; otherwise `openid` only (private identity).                       |
| `redirectUri`    | `string`  | `location.origin + location.pathname` | The relying-party callback URL. Must be HTTPS (loopback HTTP for local dev). **Stored verbatim** and replayed to `/token` exactly. |
| `returnTo`       | `string`  | `location.pathname + location.search` | Where to land after the callback completes.                                                                                        |

The SDK generates a 48-byte PKCE verifier, a 24-byte `state`, and an S256 challenge, and stores `{ v, state, redirectUri, returnTo }` in `sessionStorage` under `auth2c.transaction`. The browser is then redirected away to Google.

### `handleCallback() => Promise<Auth2CIdentity | null>`

Resumes the flow on the callback URL. Automatically invoked on page load when the URL contains a `code` query parameter.

- Verifies the returned `state` against the stored transaction.
- Verifies the current URL corresponds to the stored `redirectUri` after removing only the broker-added `code` and `state` parameters. **Legitimate pre-existing query parameters on the redirect URI are preserved** and sent verbatim to `/token`.
- POSTs `{ code, code_verifier, redirect_uri }` to `/token`.
- On success, stores the identity in `localStorage` (`auth2c.identity`), removes the transaction from `sessionStorage`, rewrites the URL to `returnTo`, and dispatches an `auth2c:change` event.

Returns `null` if there is no `code` parameter (i.e., the page is not a callback).

### `getIdentity() => Auth2CIdentity | null`

Returns the stored identity if present and not past `expiresAt`, else `null`. Does not perform network I/O and does **not** verify revocation. Use `checkSession()` for live validation.

### `signOut() => Promise<void>` _(async)_

Revokes the session server-side and clears local state.

1. If an identity exists, POSTs to `/session/revoke` with the bearer token.
2. In a `finally` block, removes the identity from `localStorage` and dispatches `auth2c:change` with `null`.
3. Resolves after the remote revocation attempt (success or failure).

This is **asynchronous** as of this contract version. A previous version was synchronous and only cleared local state. Callers should `await Auth2C.signOut()`. Local state is always cleared even if the network request fails.

### `checkSession() => Promise<boolean>`

POSTs the stored token to `/session/check`. Returns `true` if active. If the server returns non-OK (expired, revoked, or invalid), local state is cleared and `false` is returned.

## `Auth2CIdentity`

```ts
type Auth2CIdentity = {
  userId: string; // pairwise subject (sub), origin-scoped
  token: string; // the ES256 JWT bearer token
  email: string | null; // present only if requestProfile was true
  name: string | null;
  picture: string | null;
  expiresAt: number; // epoch milliseconds
};
```

`email`, `name`, and `picture` are **decoded from the JWT** and are display-only — they are not cryptographically verified client-side. Use server-side verification for any authorization decision.

## Browser events

- `auth2c:change` — `CustomEvent` dispatched on `window` whenever the identity changes (after callback success, sign-out, or a failed `checkSession`). `event.detail` is the new `Auth2CIdentity | null`.

## Storage keys and persistence

| Key                  | Storage          | Purpose                                      | Lifetime                                                      |
| -------------------- | ---------------- | -------------------------------------------- | ------------------------------------------------------------- |
| `auth2c.identity`    | `localStorage`   | The signed identity + token                  | Persists across tabs and restarts until expiry or `signOut()` |
| `auth2c.transaction` | `sessionStorage` | PKCE verifier, state, redirect URI, returnTo | Single tab; removed after callback                            |

## Multi-tab behavior

`localStorage` is shared across tabs of the same origin, so signing in on one tab makes the identity available to other tabs. Tabs listening for `auth2c:change` will not automatically receive an event for changes made in _another_ tab (the event is dispatched in the tab that performed the change). Apps wanting cross-tab synchronization should listen to the browser `storage` event and re-call `getIdentity()`.

## React API

```tsx
import { useAuth2C } from "@auth2c/react";

const { identity, loading, signIn, signOut, checkSession } = useAuth2C();
```

- `identity: Auth2CIdentity | null`
- `loading: boolean` — true until the initial `handleCallback()` resolves and the first sync completes.
- `signIn(options?)` — delegates to the global `Auth2C.signIn`.
- `signOut()` — delegates to the global `Auth2C.signOut` (async).
- `checkSession()` — delegates to the global `Auth2C.checkSession`.

The hook subscribes to `auth2c:change` and re-renders on identity changes.

## Convex adapter

```ts
import { createAuth2CConvex } from "@auth2c/react";
const adapter = createAuth2CConvex();
// adapter.signIn, adapter.signOut, adapter.useAuth()
```

`useAuth()` returns `{ isLoading, isAuthenticated, fetchAccessToken }` for Convex's auth model. `fetchAccessToken` resolves to the stored token or `null`.

## Token response shape (`/token`)

```json
{
  "id_token": "<ES256 JWT>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

The `id_token` claims:

| Claim                                        | Value                                          |
| -------------------------------------------- | ---------------------------------------------- |
| `iss`                                        | `PUBLIC_URL` (e.g. `https://auth.example.com`) |
| `aud`                                        | `origin:<normalized-origin>` (scalar)          |
| `sub`                                        | pairwise subject (`pw_...`)                    |
| `pairwise_sub`                               | same as `sub`                                  |
| `jti`                                        | session id                                     |
| `iat` / `exp`                                | seconds since epoch; lifetime 900s             |
| `email`, `email_verified`, `name`, `picture` | only if `requestProfile` was true              |

## Server-side verification (the authoritative path)

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

const jwks = createRemoteJWKSet(new URL("https://auth.example.com/.well-known/jwks.json"));
const { payload } = await jwtVerify(token, jwks, {
  issuer: "https://auth.example.com",
  audience: "origin:https://your-app.com", // scalar
});

// payload.sub is the stable, origin-scoped user id.
// Optionally call /session/check to confirm the session is still active.
```

See `docs/security.md` for why local verification does not detect revocation.

## Errors

- `signIn` redirects away; errors surface as the Auth2C error page after the redirect.
- `handleCallback` rejects with an `Error` whose `message` is the server error string (e.g. `"invalid_grant"`, `"Invalid OAuth state"`, `"Callback path mismatch"`).
- `/token` returns `400 { "error": "invalid_grant" }` for replay, wrong verifier, wrong/expired code, or redirect mismatch — uniformly, to avoid leaking which check failed.

## Versioning and compatibility

- The hosted script and `@auth2c/auth` / `@auth2c/react` are versioned together. The current contract version is **0.2.0** (async `signOut`, exact redirect-URI fidelity, `account` profile in overview).
- Additive changes (new optional `SignInOptions`, new identity fields) are non-breaking.
- Removing or re-typing an existing field, or changing `signOut`'s return type, is breaking and requires a major bump and a migration note.
- Apps should pin `@auth2c/auth` / `@auth2c/react` to an exact version and load the hosted script from the documented origin.
