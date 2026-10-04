# Session storage security

Status: **accepted (2026-10-04)** with mandatory compensating controls.
The project keeps Better Auth 1.7.7's supported session-storage model (raw
session tokens in D1). No custom hashing layer, no patch to Better Auth.
This is a **security dependency to re-evaluate on every Better Auth
upgrade**: if a supported hashed or opaque session-token storage mode
appears, review it before adopting it. Never build an incompatible one.

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
| Valid for | at most 24 hours after sign-in (see *Lifetime*), or until revoked |
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

## Mandatory compensating controls

All of these are required while raw tokens are stored. Removing or
weakening any of them reopens the decision.

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
| Cloudflare account membership tightly limited | operational |
| Least-privilege API tokens (no broad D1 read tokens, none in CI) | operational |
| Session cookie `HttpOnly`, `Secure`, host-only, `SameSite=Strict` | `options.ts`, tests |
| Suspension/disable checked on every authenticated request | `requirePrincipal`, tests |
| 24-hour absolute session lifetime | `options.ts` (see *Lifetime*) |
| Emergency global invalidation: rotate `BETTER_AUTH_SECRET` | [OPERATIONS.md](OPERATIONS.md) |

## Lifetime

**Current (approved 2026-10-04): 24-hour absolute.** `expiresIn: 86400`
with `disableSessionRefresh: true`, both supported Better Auth options; no
custom timer. A session and its cookie expire 24 hours after sign-in; use
never extends it; after that the user signs in again. `freshAge` stays 10
minutes for passkey changes (and later sensitive operations). Sign-out,
revocation, and suspension still end access immediately. Tests use fake
time to prove each of these (`tests/integration/session-lifetime.test.ts`).

Before this change the settings were `expiresIn = 7 days`, `updateAge = 1
day`. Better Auth's refresh rule (`api/routes/session.mjs`): on each
authenticated request, if `expiresAt − expiresIn + updateAge ≤ now`, it sets
`expiresAt = now + expiresIn`. That made the old lifetime a sliding 7-day
idle timeout with no absolute maximum.

### Options considered

For a control plane that will provision agents:

| Option | How | Effect |
|---|---|---|
| **A (chosen)**: 24 h absolute | `expiresIn: 86400`, `disableSessionRefresh: true` | sign in once a day; supported option, no custom code; a stolen token is useful for at most 24 h |
| B: 12 h idle + 72 h absolute | `expiresIn: 43200`, `updateAge: 3600`, plus an application check `now − session.createdAt ≤ 72 h` in `requirePrincipal` | smoother for daily users; adds one small application rule |
| C: keep 7 days sliding | — | most convenient; a stolen session can live indefinitely |

Sensitive operations require a fresh session (10 minutes) whatever the
lifetime. Passkey sign-in makes daily re-authentication cheap.

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

## Decision

1. Keep Better Auth's supported storage model. Don't patch the lookup or
   add a hashing layer. **Accepted.**
2. Keep every mandatory control above. Before production, confirm the
   operational ones (Cloudflare members, API token scopes, no D1 export
   outside the account).
3. On every Better Auth upgrade, check for a supported hashed or opaque
   session-token storage mode, and review it before adopting it (step 5 of
   the upgrade procedure in [AUTHENTICATION.md](AUTHENTICATION.md)).
4. Session lifetime: 24 hours absolute. **Applied.**
