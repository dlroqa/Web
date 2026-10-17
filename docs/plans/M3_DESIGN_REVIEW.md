# M3 focused design review (addendum to M3_PASSKEY_TURNSTILE.md)

Status: review only, 2026-10-17. Not approved for implementation. Sources:
Better Auth 1.7.7, @better-auth/passkey 1.7.7, better-call 1.4.0 and the
Kysely adapter as installed (`node_modules`), plus `src/worker/auth/*`.

## Corrections to the plan

1. **Do not use `internalAdapter.findVerificationValue` in the pre-check.**
   It is not read-only. Unless `verification.disableCleanup` is set, every
   call runs `deleteMany(verification WHERE expiresAt < now)`. As a pre-check
   it would add a D1 write path, reachable by anyone holding a signed cookie.
   Replacement: the generic adapter's `findOne({ model: "verification",
   where: [{ field: "identifier", value: token }] })`. That is one indexed
   read with no side effects, through Better Auth's own schema mapping
   (field names, date decoding). The gateway already uses `adapter.findOne`
   for passkey rows. Our configuration sets no `storeIdentifier`, so the
   identifier is stored as plain text, equal to the cookie token.
2. **Steps 1–2 alone (signature only) are not enough.** better-call's
   signature has no expiry. One genuine cookie, bought with one Turnstile
   solve, could be replayed forever, from any number of addresses, into the
   per-IP counters. The read-only row check (step 3) is what makes replay
   cost nothing: Better Auth deletes the row on first use, so later replays
   stop before the Durable Object.

## Review points

| Topic | Finding | Design consequence |
|---|---|---|
| Options POST, Turnstile first | `signInSocial` already has the order body → unidentified client → Siteverify → limiter. Better Auth's endpoint is `GET` and reads no body. | The gateway accepts `POST {turnstileToken}` and calls Better Auth with a rebuilt GET without a body. Better Auth sees the same request as today. |
| Origin / CSRF | The router checks the exact Origin on every non-GET/HEAD request before routes. A GET has no Origin check today. Better Auth skips its own origin check on GET. | POST closes this: the options request now gets the origin check. Verify stays POST and is checked by the router, and Better Auth requires `origin` as well. The challenge cookie is `SameSite=Lax`, `HttpOnly`, `Secure`, `__Secure-` prefixed, path `/api`. Unchanged. |
| Token expiry, replay, widget reset | Siteverify rejects reuse (`timeout-or-duplicate`) and tokens older than 300 s. Our verifier also checks hostname, action and `challenge_ts`. The idempotency key is the request id, so a retried Siteverify call for the same request does not count as a replay. | The client resets the widget after every passkey attempt, success, failure or cancel, because the options request has spent the token. An expired token clears through `expired-callback`, and the widget refreshes on its own. The button waits for a token, as the OAuth buttons do. |
| Better Auth compatibility | Options: Better Auth writes the challenge row (300 s) and sets a signed cookie. Verify: `getSignedCookie`, then `consumeVerificationValue`, then type `authentication`, then passkey lookup and WebAuthn verification. | Nothing in Better Auth changes. The pre-check is a necessary condition only and never replaces a Better Auth check. Better Auth still runs every check itself afterwards. |
| Cookie signature | Format: `encodeURIComponent(token + "." + base64(HMAC-SHA-256(secret, token)))`. better-call requires a 44-character signature ending in `=`. `verifySignature` is not a package export. | A local checker mirrors the format and refuses anything Better Auth would refuse; Better Auth checks again anyway. Pinned by a test that feeds a cookie actually issued by Better Auth through the checker (and an upgrade would fail that test, not production). better-call/better-auth stay pinned exactly. |
| D1 row, atomic consumption, replay | `consumeVerificationValue` → Kysely `consumeOne` = `DELETE … WHERE id = ? RETURNING *` (atomic in SQLite/D1), then deletes other rows for the identifier. Expired rows are deleted and return null. | Consumption stays with Better Auth. The pre-check only reads: row present and `expiresAt` in the future. A row the pre-check sees may still be consumed by a concurrent request; Better Auth then returns 400, which is correct. |
| Concurrent attempts | N parallel verifies with one live cookie all pass the read, take N admissions, and exactly one wins the `DELETE … RETURNING`. | Bounded by the attacker's own concurrency on one fresh challenge, and still under the per-IP limit. A test sends parallel verifies and expects exactly one 200 and the rest 400. |
| Turnstile unavailable | The verifier returns `siteverify_unavailable` (timeout 5 s, non-200 or malformed). | 403 `TURNSTILE_FAILED`, as sign-in does today; fails closed, no Durable Object call. Decision for you: accept that passkey sign-in depends on Siteverify. |
| D1 unavailable | Better Auth already needs D1 for options and verify. | A pre-check read error gives 500 `INTERNAL_ERROR` without a Durable Object request, logged as `auth.passkey.precheck_failed`. Fails closed, the same outcome Better Auth would give. |
| Registration | `generate-register-options` / `verify-registration`: principal (`active`) first, then `security_write` per user, then Better Auth. The same cookie name and challenge rows (type `registration`). | Unchanged: no Turnstile and no pre-check. The verify pre-check is only on `verify-authentication`. A registration row would pass the row check, then Better Auth refuses it (wrong type), so there is no false acceptance. |
| Login compatibility | One click: token → options → `navigator.credentials.get` → verify. No conditional UI or autofill. | Siteverify adds about 100–300 ms before the WebAuthn call. The operator browser test includes Safari/iOS if that is a target. |
| Provisioning r4 | M3 touches only `src/worker/auth`, `src/client` and tests. | No file under `protocol/`; `protocol:verify` (digest `454066f8…29a43`) stays in the pipeline. |
| Free / Paid quota | See the plan, §8. | Anonymous options and verify requests: 0 Durable Object requests. A replayed cookie: 0 Durable Object requests and 1 D1 read. A real sign-in: unchanged (2 admissions). Distributed real-browser abuse can still spend the allowance, so M5 is still needed. |

## Pre-check semantics (proposed, not implemented)

```
verify-authentication:
  cookie = createAuthCookie("better-auth-passkey").name   (from Better Auth's $context)
  value missing / no "." / signature not 44 chars ending "=" / HMAC invalid → 400, no DO, no D1
  findOne(verification, identifier = token):
      error            → 500, no DO
      none or expired  → 400, no DO
  → enforceRateLimit(passkey_login, ip) → parse body → Better Auth (full checks, atomic consume)
```

The 400 body is `INVALID_REQUEST`, which Better Auth's own `CHALLENGE_NOT_FOUND`
maps to today, so a client sees no difference.

Safer alternative, if you would rather keep Better Auth internals out of the
gateway entirely: no pre-check on verify. Instead, a separate
`passkey_verify` counter keyed by the challenge-token hash (one admission per
challenge), which needs an extra Durable Object request. It does not reduce
the quota cost, so it is not recommended.

## M5: passkey RP ID migration (custom domain)

A passkey is bound to its RP ID (`PASSKEY_RP_ID` = the workers.dev host
today). A browser will not use it on another domain. Related-origin requests
(WebAuthn L3, `/.well-known/webauthn`) let a credential's RP ID be used from
other origins, but only when the RP ID's own domain serves that file. We do
not control `workers.dev` there, so this route is unavailable.

Strategy:

1. Before the cutover, the custom domain serves the app. Configuration
   (`PUBLIC_ORIGIN`, `PASSKEY_RP_ID`, Turnstile hostnames, OAuth redirect
   URIs, `trustedOrigins`) switches in one version. OAuth (Google/GitHub)
   keeps working, since accounts are keyed by provider identity, not domain.
2. Existing workers.dev passkeys stop working on the new domain. At sign-in
   the user signs in with OAuth. The Security page then shows passkeys from
   the old RP ID as "needs re-adding" (passkey rows store no RP ID today, so
   the cutover date decides). The user adds a new passkey on the new domain,
   then removes the old one.
3. Keep `workers.dev` serving only a redirect to the custom domain for a
   transition period, then set `workers_dev: false`, so the WAF rule cannot
   be bypassed.
4. Staging first, with test accounts. Production gets an announcement, and
   OAuth always remains available as the recovery path.

No schema change is required for steps 1–3. Recording the RP ID per passkey
(for the "needs re-adding" label) would be a migration and needs its own
approval.

## Decisions for you

1. M3b with signature check plus read-only row check (recommended), or no
   verify pre-check (residual: the anonymous verify path still reaches the
   Durable Object).
2. Accept that passkey sign-in fails closed when Siteverify is unavailable.
3. Turnstile action: reuse `login` (recommended) or a separate
   `passkey_login` (needs a second widget).
4. Browser targets for the P2 operator test (Safari/iOS?).
