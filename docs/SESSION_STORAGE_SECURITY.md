# Session storage security

Status: **open production decision.** Raw session tokens are stored in D1.
This is acceptable on staging with the compensating controls below. It is
**not** resolved for production and needs explicit review before launch.

Findings are from the installed Better Auth 1.7.7 source
(`better-auth/dist/db/internal-adapter.mjs`, `api/routes/session.mjs`,
`@better-auth/core/dist/types/init-options.d.mts`), not from memory or blog
posts.

## Current behavior (Better Auth 1.7.7)

- `createSession` generates `token = generateId(32)` (32 random characters
  from `[A-Za-z0-9]`, about 190 bits) and inserts it **as is** into
  `session.token`.
- The browser cookie `__Secure-lightagent.session_token` carries
  `<token>.<HMAC signature>`. Better Auth verifies the signature with
  `BETTER_AUTH_SECRET`, then looks the session up with
  `WHERE token = <token>` (`findSession`).
- So `session.token` is the live bearer value. The signature only binds the
  cookie to our secret; it doesn't stop someone who has the raw token *and* the
  secret, and the lookup itself needs only the raw token.
- There is no option to store a hash of the token. Hashing appears in this
  code only for verification-row reservation ids.
- `secondaryStorage` (KV/Redis) stores sessions under the raw token as the
  key, so it moves the bearer value to another store but doesn't remove it.
- `session.cookieCache` (`compact` / `jwt` / `jwe`) caches the session in a
  signed or encrypted cookie to skip database reads. It doesn't change what is
  stored, and it delays revocation for up to `maxAge`. We keep it **disabled**
  so revocation is immediate.
- "Stateless" sessions (cookie cache only, no database) give up server-side
  revocation, the suspension gate's session listing, and sign out everywhere.
  Not suitable here.

### Why a custom hashing layer is not used

Better Auth reads and writes the `token` column in several places:
`findSession`, `findSessions`, `updateSession`, `deleteSession`,
`deleteSessions`, listing, and refresh. The value it gets back from the
database is reused as the key for later calls. The session-create hook can't
help either: the value it returns becomes the cookie value, so hashing there
just turns the hash into the bearer value.

A wrapping database adapter that hashes `token` on every write and in every
`WHERE token = …` could work in principle. But it would have to recognize
whether each value is raw or already hashed, for every call path, in every
future Better Auth version, and our own code (`deleteSession(target.token)`)
passes stored values back. It is an unsupported patch to Better Auth's lookup
model, so it is **not implemented**, as decided.

## Threat model

| Asset | `session.token` rows in D1 (and their user ids) |
|---|---|
| Valid for | up to 7 days from last refresh (see *Lifetime*), until revoked |
| Who can read D1 | anyone with the Cloudflare account's D1 read permission (dashboard, API token, `wrangler d1 execute`); the Worker itself |
| Not exposed | D1 has no public endpoint; the Worker never returns session rows or tokens (only opaque session ids); tokens aren't logged or audited (tests scan logs, audit rows, and responses) |

### Realistic impact of a D1 read compromise

Reading `session.token` gives the bearer half of every live session's
cookie. To use it, an attacker also needs a valid cookie signature, which
takes `BETTER_AUTH_SECRET`:

- **D1 read access alone isn't enough to forge a cookie.** The secret is a
  Worker secret and can't be read back through the dashboard or API.
- **D1 read access plus the secret** (leaked, or used by code deployed with
  Worker write access) takes over every live session.

In practice, whoever has broad Cloudflare account access holds everything:
D1, Worker deployment, and so the secret. Hashing tokens at rest would mainly
protect against a **D1-only** leak (an exported backup, an over-scoped
read-only token, a query result pasted somewhere) combined with a separate
leak of the secret. That is a real but narrower case.

What an attacker gets: the user's application identity. Today that means
their profile, security settings and passkey management (not removal, which
needs a fresh session). After Phase 5, it means agent provisioning. An
account suspension still blocks a stolen session immediately.

## Compensating controls in place

| Control | Where |
|---|---|
| D1 is never exposed to clients; no public database endpoint | architecture; only the Worker binds `DB` |
| Session tokens never in responses, logs, or audit rows | gateway reduces bodies; `GET /api/security/sessions` returns ids; tests scan logs, audit rows, and responses for the live token |
| Cookie: `HttpOnly; Secure; SameSite=Strict; Path=/api`, host-only, signed | `options.ts` |
| Immediate server-side revocation (no cookie cache) | `cookieCache: { enabled: false }` |
| Per-session and sign out everywhere revocation (current session included, cookie cleared) | `security.ts` |
| Application status checked on every request (suspension wins over any session) | `requirePrincipal` |
| Incident: revoke one user's sessions, or every session, with an audit event | `npm run operator -- revoke-sessions` / `revoke-all-sessions` ([OPERATIONS.md](OPERATIONS.md)) |
| Rotating `BETTER_AUTH_SECRET` invalidates every cookie signature (all sessions end) | `wrangler secret put BETTER_AUTH_SECRET --env …` |
| Narrow Cloudflare account access | operational: few members, scoped API tokens, no read-all tokens in CI |

## Lifetime

Current settings: `expiresIn = 7 days`, `updateAge = 1 day`,
`freshAge = 10 minutes`.

Better Auth's refresh rule (`api/routes/session.mjs`): on each authenticated
request, if `expiresAt − expiresIn + updateAge ≤ now` (at least a day has
passed since the last refresh), it sets `expiresAt = now + expiresIn`.

So today a session:

- expires after **7 days without use** (idle timeout), and
- has **no absolute maximum**: one used at least weekly never expires.

Better Auth 1.7.7 offers `session.disableSessionRefresh: true`, which makes
`expiresIn` an absolute lifetime (no sliding), but no separate absolute cap
combined with an idle timeout.

### Recommendation (not applied; needs approval)

For a control plane that will provision agents:

| Option | How | Effect |
|---|---|---|
| **A (recommended)**: 24 h absolute | `expiresIn: 86400`, `disableSessionRefresh: true` | sign in once a day; supported option, no custom code; a stolen token is useful for at most 24 h |
| B: 12 h idle + 72 h absolute | `expiresIn: 43200`, `updateAge: 3600`, plus an application check `now − session.createdAt ≤ 72 h` in `requirePrincipal` | smoother for daily users; adds one small application rule |
| C: keep 7 days sliding | — | most convenient; a stolen session can live indefinitely |

Sensitive operations already require a fresh session (10 minutes) whatever
the lifetime: passkey add and remove now, and agent creation in Phase 5.
Passkey sign-in makes daily re-authentication cheap. Changing the lifetime
affects the login experience, so it waits for approval.

## Supported mitigation options

| Option | Supported in 1.7.7 | Removes raw tokens at rest | Cost |
|---|---|---|---|
| Shorter lifetime (A or B) | yes | no, but limits the exposure window | sign in more often |
| Narrow account access, scoped tokens, no D1 exports outside the account | yes (operational) | — | process |
| Incident revocation (operator CLI, secret rotation) | yes | — | none |
| `secondaryStorage` | yes | no (raw token is the key) | another store |
| Cookie cache (`jwe`) | yes | no | delayed revocation: rejected |
| Hashed tokens via a custom adapter | **not supported** | yes | fragile, version-coupled: rejected |
| Upstream feature (hashed session tokens) | not in 1.7.7 | yes | wait; re-check at each Better Auth upgrade |

## Recommendation for this project

1. Keep Better Auth's supported storage model. Don't patch the lookup.
2. Before production: decide the lifetime (option A recommended) and
   confirm the operational controls (Cloudflare members, API token scopes,
   no D1 export procedure outside the account).
3. Check each Better Auth upgrade for hashed or opaque session-token storage,
   and adopt it if it appears.
4. Treat raw session-token storage as an **accepted, documented production
   risk that needs explicit sign-off**. It is not resolved.

**Required before production:** a sign-off on this risk, and a lifetime
decision. A code change isn't required unless the sign-off says otherwise.
