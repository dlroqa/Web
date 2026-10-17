# M3 implementation blueprint

Status: final blueprint for review, 2026-10-17. **Not authorized for
implementation.** It supersedes the open choices in
[M3_PASSKEY_TURNSTILE.md](M3_PASSKEY_TURNSTILE.md) and builds on
[M3_DESIGN_REVIEW.md](M3_DESIGN_REVIEW.md).

Baseline: `deploy/staging` = `92e3899` (validated by Builds `81ead6f0`:
r4 `454066f8…29a43`, `tsc -b` clean, 46 files / 1,075 tests, `test:build`
12/12, guarded dry run). Live: carrier `7750a63c` 100%, F1 `6b397259` 0%.

## 1. Approved decisions (2026-10-17)

| Decision | Choice |
|---|---|
| M3a | Turnstile first on passkey authentication-options requests |
| M3b | A strictly read-only challenge-row lookup before the limiter; Better Auth keeps challenge ownership, expiry, single use and the final decision |
| Hidden writes | No helper that writes during the pre-check (`findVerificationValue` is excluded: it deletes expired rows) |
| Turnstile unavailable | Fail closed (403), no Durable Object admission |
| Turnstile action | Reuse `login`; the server checks action and hostname (tested with a realistic, non-test Siteverify result) |
| Browser matrix | Safari/macOS, Safari/iOS, Chrome desktop; Edge and Firefox where supported |
| Execution | All builds, tests and rendering on Workers Builds; no local CI and no GitHub Actions |

## 2. Scope

In: `src/worker/auth/gateway.ts`, new `src/worker/auth/passkey-challenge.ts`,
`src/client/lib/passkeys.ts`, `src/client/pages/Login.tsx`, tests, docs, and
`package.json` / `package-lock.json` (one explicit pin, §4.3).

Out (unchanged): Better Auth configuration and plugins, `wrangler.jsonc`,
`migrations/`, `protocol/` (r4), the `AuthRateLimiter` class, `RATE_LIMIT_POLICIES`,
passkey registration, CSP, `scripts/p1-bounded-tests.sh` (the P1 record),
Lightagent, W2.

## 3. Commits (branch `m3/passkey-turnstile`, rebased on `92e3899`)

Each commit stays consistent and testable on its own; Builds validates the
branch head.

1. `feat(security): Turnstile before the limiter on passkey sign-in options (M3a)`
   gateway route + client + tests (the browser contract changes in the
   same commit as the server).
2. `feat(security): refuse passkey verification without a live challenge before the limiter (M3b)`
   `passkey-challenge.ts`, gateway wiring, `better-call` pin, tests.
3. `docs: M3 endpoint, threat model and runbook`; also the 81ead6f0
   validation record in `DEPLOYMENT.md`.

## 4. Source changes

### 4.1 `src/worker/auth/gateway.ts` (M3a)

- Header table: `POST /passkey/generate-authenticate-options   Turnstile, IP limit`;
  `POST /passkey/verify-authentication   live challenge, IP limit, body bounded`.
- `const PasskeyAuthOptionsBody = z.object({ turnstileToken: z.string().min(1).max(2048) }).strict();`
- Extract the existing Turnstile block of `signInSocial` (lines 203–209)
  unchanged into `async function requireTurnstile(ctx, token: string): Promise<void>`.
  Same verifier options, `expectedAction: "login"`,
  `remoteIp` = `cf-connecting-ip`, `idempotencyKey` = request id. Throws
  `TURNSTILE_FAILED`. `signInSocial` calls it; its behaviour is unchanged
  (the existing 23 `auth-rate-limit` tests guard this).
- `passkeyAuthenticateOptions`:
  ```ts
  const body = parse(PasskeyAuthOptionsBody, await readJson(ctx.request));
  const address = clientAddress(ctx);
  if (address === null) await enforceRateLimit(s.limiter, "passkey_login", { kind: "ip", address });
  await requireTurnstile(ctx, body.turnstileToken);
  await enforceRateLimit(s.limiter, "passkey_login", { kind: "ip", address });
  const upstream = await s.auth.handler(asGet(ctx.request, new URL(ctx.url.pathname, ctx.url)));
  // rest unchanged
  ```
- `asGet(original, url)`: a GET to `url` with the original headers minus
  `content-type` and `content-length`, and no body. Better Auth's endpoint
  is `GET` and reads no body or query.
- `ROUTES`: `{ method: "POST", path: "/passkey/generate-authenticate-options", … }`.
  A GET then gets 405 `Allow: POST` from the existing matcher.

Origin/CSRF: the router's exact-origin check now applies to the options
request (a non-GET). No gateway change is needed for that.

### 4.2 `src/worker/auth/passkey-challenge.ts` (new, M3b)

```ts
export type PasskeyChallengeFailure = "missing" | "malformed" | "bad_signature" | "not_found" | "expired";

/** better-call 1.4.0 signed-cookie check: "<token>.<base64 HMAC-SHA-256>"; null if Better Auth would refuse it. */
export async function signedCookieToken(value: string, secret: string): Promise<string | null>;

/** Why verify-authentication cannot succeed, decided without the limiter; null when Better Auth must decide. Read-only. */
export async function passkeyChallengeFailure(request: Request, auth: AuthInstance, now?: () => number): Promise<PasskeyChallengeFailure | null>;
```

Semantics (each step mirrors the check Better Auth makes later, never a
looser or stricter one):

1. `const c = await auth.$context;`
   `const name = c.createAuthCookie("better-auth-passkey").name`. This is the
   plugin's default `webAuthnChallengeCookie`; we don't override it, and a
   test pins it.
2. `parseCookies` **from `better-call`** (the parser `getSignedCookie`
   uses: first occurrence wins, values URI-decoded). Not
   `better-auth/cookies`, which keeps the last duplicate and validates
   values by regex. Missing gives `missing`.
3. `signedCookieToken`: `lastIndexOf(".") >= 1`; the signature is exactly
   44 characters ending in `=`; then `crypto.subtle.verify("HMAC", key(secret), atob(sig), utf8(token))`
   (constant time). `atob` failure or a bad format gives `malformed`; a
   failed verification gives `bad_signature`. `secret` = `c.secret`.
4. `await c.adapter.findOne<{ expiresAt: Date }>({ model: "verification", where: [{ field: "identifier", value: token }] })`
   is the generic adapter: one `SELECT`, no cleanup, no hooks that write.
   No row gives `not_found`; `expiresAt <= now` gives `expired`. The
   identifier is stored as plain text (no `verification.storeIdentifier`
   configured), and a test pins this.
5. It does **not** check the row's `type`, challenge, user, credential or
   origin. Those remain Better Auth's checks, as does the atomic consumption
   (`consumeVerificationValue` → `DELETE … RETURNING`).

`gateway.ts` `passkeyVerifyAuthentication`, before `enforceRateLimit`:

```ts
let failure: PasskeyChallengeFailure | null;
try {
  failure = await passkeyChallengeFailure(ctx.request, s.auth);
} catch (error) {
  ctx.logger.error("auth.passkey.precheck_failed", { errorName: error instanceof Error ? error.name : typeof error });
  throw new ApiError("INTERNAL_ERROR", { logReason: "passkey challenge lookup failed" });
}
if (failure) {
  ctx.logger.warn("auth.passkey.login.failure", { stage: "precondition", reason: failure });
  throw new ApiError("INVALID_REQUEST", { logReason: `passkey challenge ${failure}` });
}
```

400 `INVALID_REQUEST` is what Better Auth's `CHALLENGE_NOT_FOUND` (400)
maps to today, so a client sees no difference.

### 4.3 `package.json`

Add `"better-call": "1.4.0"` to `dependencies`. The exact version Better
Auth 1.7.7 already pins is in the lockfile, so nothing new is downloaded.
This makes the parser import explicit rather than relying on hoisting. The
lockfile root entry changes; the Builds `npm ci` verifies it.

### 4.4 `src/client/lib/passkeys.ts`

- `postJson<T>(path, body)`, a sibling of `getJson`: `POST`,
  `credentials: "same-origin"`, `content-type: application/json`, the same
  error mapping.
- `signInWithPasskey(turnstileToken: string)`: options via `postJson(…, { turnstileToken })`;
  ceremony and verify unchanged. `addPasskey` unchanged.

### 4.5 `src/client/pages/Login.tsx`

- Render the widget when `config.turnstileSiteKey` is set and
  (`providers.length > 0 || config.passkeys`). Today it renders only with
  providers.
- `passkey()`: with no token, show the existing "Just a moment while we
  verify your browser." and return. Otherwise call
  `signInWithPasskey(turnstileToken)`. In `finally`, call `setBusy(null)`
  and `resetTurnstile()` on every outcome: the options request spent the
  token.
- With passkeys enabled but no site key configured (misconfiguration),
  show the existing load error instead of an endless wait.
- No new strings beyond these; `TURNSTILE_FAILED` already reads "Human
  verification failed. Please try again."

## 5. Security requirements (acceptance criteria)

1. An options request without a passing Siteverify (action `login`,
   expected hostname, fresh, not reused) makes **no** Durable Object call,
   no D1 write and sets no cookie.
2. Options requests pass the router's exact-origin check before any route
   logic.
3. A verify request without a correctly signed, unexpired, unconsumed
   challenge makes **no** Durable Object call and **no** D1 write.
4. The pre-check never refuses a request Better Auth would accept (same
   cookie name, parser, signature format, secret and identifier storage).
5. Better Auth alone consumes challenges (atomic) and decides the result.
6. Siteverify unavailable → 403; D1 unavailable → 500; neither admits to
   the Durable Object.
7. Valid users keep 20 / 60 s per IP, with options and verify sharing
   `passkey_login`.
8. No token, cookie value, secret or challenge in logs.
9. Registration, OAuth, sessions, cookies and r4 behave as before.

## 6. Tests (all run by `npm run ci:cloudflare` on Workers Builds)

Helper: `tests/helpers/auth.ts` `FakeProviders.turnstile` gains
`"unavailable"` (HTTP 503) and `"real"` (a non-test result:
`{ success: true, hostname, action, challenge_ts: now }`, with
`turnstileHostname` / `turnstileAction` overrides).

`tests/integration/auth-rate-limit.test.ts` (M3a/M3b, new or moved):

1. 21 options POSTs with a failing token → 21 × 403; Siteverify 21; then 20
   valid requests succeed (no admissions used); no challenge rows written.
2. Valid token: 20 × 200, the 21st 429 with `Retry-After`, no row, no cookie
   (the existing case, now POST).
3. Foreign Origin / text body / extra field / missing token → 403 / 415 /
   400 / 400; Siteverify 0; admissions 0.
4. `GET` options → 405 `Allow: POST`.
5. Unidentifiable client → 429 before Siteverify.
6. `turnstile = "unavailable"` → 403; admissions 0.
7. `turnstile = "real"`: hostname `localhost`, action `login` → 200; action
   `signup` → 403; hostname `evil.example` → 403 (the endpoint really
   enforces action and hostname).
8. verify with no cookie, malformed value, wrong signature (another secret)
   or a 43-character signature → 400; admissions 0.
9. verify with a correctly signed cookie for a token with no row → 400;
   admissions 0. With an expired row → 400; admissions 0; **the expired rows
   are still present afterwards** (proves no cleanup write).
10. Replay: complete a passkey sign-in, then resend the same cookie → 400,
    admissions unchanged.
11. Concurrency: 5 parallel verifies with one live challenge → exactly one
    200, four 400, at most 5 admissions.
12. Duplicate cookie names (`a; a`) → the pre-check and Better Auth select
    the same value (accepted when the first is live, refused when the first
    is forged).
13. verify with a live challenge on an exhausted address → 429 (the T4 case,
    now with a real cookie).

`tests/unit/passkey-challenge.test.ts`: `signedCookieToken` against a value
produced by `better-call`'s `serializeSignedCookie` (format pin), wrong
secret, empty token, missing dot, bad base64, wrong length; a cookie name
pin (`createAuthCookie("better-auth-passkey")`) for http and https
(`__Secure-` prefix).

`tests/integration/passkeys.test.ts`, `hardening.test.ts`, `auth.test.ts`:
options calls become `POST` with `{ turnstileToken }` and `origin`; every
existing assertion is kept (no test is deleted).

`tests/client/ui.test.tsx`: `signInWithPasskey` sends `POST` JSON with the
token (`fetch` and `@simplewebauthn/browser` mocked); the Login widget
condition (pure helper `turnstileNeeded(config)`, rendered and asserted
without a browser).

Static: the existing configuration and migration pins pass unchanged (no
migration). `p1-bounded-tests.test.ts` is unchanged: it pins the P1
record, not the server.

Expected totals: about 46 → 47 files and 1,075 → ~1,105 tests (reported
exactly from the log).

## 7. Staged Cloudflare-hosted validation

| Gate | Action | Evidence | Approval |
|---|---|---|---|
| I0 | Implement locally on `m3/passkey-turnstile` (edits only; `bash -n`/`git diff` only) | diff review | **implementation authorization** |
| I1 | Push `m3/passkey-turnstile`; operator temporarily sets the Builds production branch to it (Deploy command untouched: dry run) | build ID, full log: r4, `tsc`, totals, the new tests by name, `test:build`, deploy-command sha256 `73fda913…`, `--dry-run: exiting now.`; live unchanged | push + branch switch |
| I2 | Operator restores the production branch to `deploy/staging` | screenshot | — |
| I3 | Fast-forward `deploy/staging` to the M3 head, push (dry-run build) | log, same checks | separate |
| U3 | Inactive upload: a docs-only commit pushed while the upload command is saved (Retry reuses the old command); restore the dry run | version ID at 0%, deploy-command sha256 `795220c2…` style check, carrier 100% | separate |
| P2.0 | Preflight: carrier 100%, 0 DO objects, no pending D1, previews off, test passkeys registered for each browser (on the carrier: registration is unchanged) | API reads | separate (registration writes D1) |
| P2 | Bounded activation ≤ 30 min, mandatory rollback to `7750a63c` | below | separate |

P2 live checks:

- Scripted (new `scripts/p2-bounded-tests.sh` with a static test like P1's;
  invalid tokens only, ≤ 50 requests): 21 × POST options with an invalid
  token → 403; GET → 405; 21 × verify with no cookie → 400; 1 × forged
  signed-looking cookie → 400. **Durable Object requests in analytics
  unchanged across the script**, plus `wrangler tail` (best effort; it drops
  events).
- Operator browsers: Safari/macOS, Safari/iOS, Chrome desktop, and Edge and
  Firefox where an authenticator is available. Each does passkey sign-in →
  dashboard → sign-out; one also does Google sign-in. Cookie flags checked;
  0 CSP violations; 0 exceptions or 5xx.
- The 20 / 60 s count on options cannot be scripted live (it needs real
  tokens; staging refuses test keys). It is covered by test 2.

Cloud browser automation (for example Browser Rendering) cannot pass the
staging Turnstile or present a real authenticator. The matrix is therefore
operator-run in real browsers, the same way as P1's T6. An automated cloud
browser path would need its own approved design.

## 8. Rollback

The M3 version adds no binding, migration or settings change. Rollback is the
dashboard rollback to `7750a63c` (or a `versions deploy` from a staging
build of the same commit). Pages opened under the other version get 405 on
the options call until refreshed; this is benign.

## 9. Durable Object and SQLite effect

| Request | Today | M3 |
|---|---|---|
| Anonymous options (no or invalid token) | 1 DO request, ~2 rows written, 1 D1 row, cookie | 0 DO, 0 D1 writes, 1 Siteverify |
| Anonymous verify (no or forged cookie) | 1 DO request, ~2 rows written | 0 DO, 0 D1 |
| Replayed genuine cookie | 1 DO request | 0 DO, 1 D1 read |
| Real passkey sign-in | 2 DO requests | 2 DO requests + 1 D1 read |

Residual (unchanged by M3): clients that solve Turnstile from many
addresses can still spend the account-wide allowance → M5.

## 10. M5: passkey RP ID migration

Workers.dev passkeys will **not** work on the custom domain: a credential is
bound to its RP ID, and related-origin requests would need
`/.well-known/webauthn` on workers.dev, which we cannot serve. Planned user
path:

1. Cutover version: `PUBLIC_ORIGIN`, `PASSKEY_RP_ID`, Turnstile hostnames
   and widget hostname list, OAuth redirect URIs (Google, GitHub) and
   trusted origins change together; the workers.dev host only redirects
   to the custom domain.
2. User opens the custom domain and signs in with Google or GitHub
   (provider identities are domain-independent, so accounts are unchanged).
3. The Security page explains that passkeys created before the cutover date
   no longer work. The user adds a new passkey, then removes the old ones.
   Showing which keys are old by date needs no schema change; storing the RP
   ID per passkey would be a migration (separate approval).
4. After a transition period: `workers_dev: false`, so the WAF rule cannot
   be bypassed. Staging rehearses all of this first.

## 11. Approvals required, in order

1. Implementation authorization (I0).
2. Push of `m3/passkey-turnstile` and the temporary production-branch switch (I1–I2).
3. Merge into `deploy/staging` (I3).
4. U3 inactive upload.
5. P2.0 test passkey registration, then the P2 activation window (rollback mandatory).
6. Separately: authoritative `security_write`; `recovery` and `provision`
   with their endpoints; M5 (zone, DNS, WAF, possible billing).
