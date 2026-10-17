# M3: Turnstile before the limiter on passkey sign-in (design, not approved)

Status: proposal for review, 2026-10-17. Nothing here is implemented. Each
step in "Gates" needs its own approval.

Base: `deploy/staging` = `6f570c6` (remote) + local docs `bea9728`, `b690ccf`.
Live: carrier `7750a63c` 100% (deployment `b64a2fa9`); F1 `6b397259` 0%.

## 1. Problem

Today an anonymous client with no Turnstile token can still spend the shared
quotas through both passkey sign-in endpoints:

| Request (anonymous, no browser) | Durable Object | D1 | Other |
|---|---|---|---|
| `GET /passkey/generate-authenticate-options` | 1 `admit` (row INSERT; cleanup DELETE; alarm at most once per 5 min per counter) | 1 `verification` INSERT (challenge, 300 s) | signed `better-auth-passkey` cookie |
| `POST /passkey/verify-authentication` with no or a forged challenge cookie | 1 `admit` | none (Better Auth refuses: `CHALLENGE_NOT_FOUND`) | none |

The per-IP limit (20 / 60 s) bounds one address. It does not bound the
account-wide allowance (Workers Free: 100k DO requests and 100k rows written
per day, fail closed) against a client that rotates addresses. P1 T3/T4
showed both requests reaching the counter with no browser at all.

Turnstile on the options request alone is **not enough**. The verify
endpoint would stay an anonymous path to the Durable Object, because
reaching the limiter only needs a challenge cookie to be present. M3
therefore has two parts.

## 2. Proposed design

### M3a: options request: Turnstile, then the limiter

`generate-authenticate-options` becomes `POST` in the gateway, with body
`{ "turnstileToken": "…" }` (strict schema, 1–2048 characters, as for
sign-in). The gateway calls Better Auth with a rebuilt **GET** without a
body, so Better Auth's behaviour and response are unchanged.

POST rather than a GET carrying a header or query parameter, because:

- the request writes D1 and sets a cookie, so it is state-changing; as a
  POST it passes the router's exact-origin check (`checkOrigin`) before any
  route logic;
- tokens stay out of URLs and logs.

Order (the same as `signInSocial`):

```
router: exact Origin (403 FORBIDDEN)                      no Siteverify, no DO
 └ content type / bounded body / schema (415/413/400)     no Siteverify, no DO
    └ client unidentifiable → limiter refuses, no counter (429)
       └ Turnstile Siteverify, action "login" (403 TURNSTILE_FAILED)   no DO, no D1
          └ authoritative passkey_login limit, per IP (429 + Retry-After)   no D1
             └ Better Auth GET: options 200 + Set-Cookie challenge + D1 row
```

### M3b: verify request: a live challenge before the limiter

Before `enforceRateLimit` in `passkeyVerifyAuthentication`, a precondition
decided without the Durable Object (the same approach as M2 for OAuth
callbacks):

1. The `better-auth-passkey` cookie (name from Better Auth's
   `createAuthCookie`, as in M2) is present.
2. Its value is `token.signature` and the signature is a valid
   HMAC-SHA-256 under Better Auth's secret (`crypto.subtle.verify`, which
   compares in constant time). This is the format better-call 1.4.0 signs
   with. Its helper is not a package export, so a small local function
   does the check, and a test pins it against a cookie really issued by
   Better Auth.
3. The `verification` row for that token exists and has not expired
   (`internalAdapter.findVerificationValue`: one indexed D1 read, no write).

Any failure gives the answer Better Auth would give (400 `INVALID_REQUEST`)
without spending a limiter request. Better Auth still does its own full
checks afterwards, including single use (`consumeVerificationValue`).

Effect: only a challenge issued after a passed Turnstile and the limiter,
and not yet used, can reach the counter. A replayed cookie fails at step 3
once Better Auth has consumed the row. A forged cookie fails at step 2.

Step 3 is the part that touches Better Auth internals; 1.7.7 is pinned
exactly. If you prefer the smallest change, steps 1–2 alone stop forged
cookies, but a genuine cookie could still be replayed into the counter
until its challenge expires (bounded per IP). Recommendation: all three.

### What stays unchanged

- Better Auth configuration, passkey plugin, RP ID and origin, and the
  verify-authentication body and response.
- Passkey **registration** (`generate-register-options`,
  `verify-registration`): signed-in principal first, then `security_write`
  per user. Anonymous requests never reach a counter there.
- Origin/CSRF checks, session cookies, `RATE_LIMIT_POLICIES` limits (20 /
  60 s), the `AuthRateLimiter` class, binding and migration. No migration,
  no new binding, no configuration change, so Free and Paid alike.
- Provisioning r4 (`protocol/`, digest `454066f8…29a43`), Lightagent, W2.

## 3. Files

| File | Change |
|---|---|
| `src/worker/auth/gateway.ts` | route `POST /passkey/generate-authenticate-options`; `PasskeyAuthOptionsBody`; Turnstile step shared with `signInSocial` (small private helper, same verifier and options); M3b precondition call; header comment table |
| `src/worker/auth/passkey-challenge.ts` (new) | `passkeyChallengePrecondition(ctx, services)` → `null` or a reason; signed-cookie check |
| `src/client/lib/passkeys.ts` | `signInWithPasskey(turnstileToken)`: POST JSON for options; rest unchanged |
| `src/client/pages/Login.tsx` | render the widget when passkeys **or** providers are enabled (today only with providers); passkey button waits for a token like OAuth; reset the widget after every passkey attempt (the token is spent by the options request) |
| `tests/integration/auth-rate-limit.test.ts`, `passkeys.test.ts`, `hardening.test.ts`, `auth.test.ts` | options calls become POST with a token; new cases below |
| `tests/unit/` | precondition and signed-cookie unit tests |
| `docs/AUTHENTICATION.md`, `SECURITY_MODEL.md`, `RATE_LIMITER_RUNBOOK.md`, `DEPLOYMENT.md` | endpoint table, threat notes, runbook, record |

No change to CSP (the Turnstile origin is already allowed on `/login`), to
`wrangler.jsonc`, `migrations/` or `protocol/`.

## 4. Turnstile token lifecycle

```
/login loads ─ widget (action "login", interaction-only) ─ token T (valid 300 s, single use)
  │
  ├─ "Continue with Google/GitHub" → POST /sign-in/social {T}     (unchanged)
  │
  └─ "Continue with passkey"
        POST /passkey/generate-authenticate-options {T}
          Siteverify(T, remoteip, idempotency_key=requestId) → T is spent
          → 200 options + challenge cookie (300 s)  │  403 / 429
        widget.reset() → new token T' for the next attempt (always, also on failure or cancel)
        navigator.credentials.get(options)  (user gesture → authenticator)
        POST /passkey/verify-authentication {response} + challenge cookie
          M3b precondition → limiter → Better Auth (consumes the challenge) → session cookie
```

The expired and error callbacks clear the token (existing behaviour); the
widget refreshes an expired token automatically. One widget and one action
serve both flows. A token is single use whichever flow spends it, so sharing
gives no amplification. A separate `passkey_login` action would need a
second widget for an analytics split only.

## 5. Expected HTTP behaviour

| Request | Response | Siteverify | DO | D1 write |
|---|---|---|---|---|
| `GET …/generate-authenticate-options` | 405, `Allow: POST` | no | no | no |
| POST, foreign or missing Origin | 403 `FORBIDDEN` | no | no | no |
| POST, not JSON / too large / bad body / no token | 415 / 413 / 400 | no | no | no |
| POST, client unidentifiable | 429 | no | no | no |
| POST, invalid, reused, stale, wrong host or action token; Siteverify down | 403 `TURNSTILE_FAILED` (fails closed) | yes | **no** | no |
| POST, valid token, over 20 / 60 s for this IP | 429 + `Retry-After` | yes | yes | no |
| POST, valid token, within the limit | 200 options + challenge cookie | yes | yes | 1 |
| verify, no, malformed, forged or used challenge | 400 `INVALID_REQUEST` | no | **no** | no |
| verify, live challenge, over the limit | 429 + `Retry-After` | no | yes | no |
| verify, live challenge | Better Auth result (200 session / 401 / 400 …) | no | yes | as today |

## 6. Security and abuse considerations

- Turnstile raises the cost per request; it does not stop solver services,
  human farms or a botnet of real browsers. The per-IP limit stays, and the
  account-wide allowance can still be spent by clients that solve Turnstile
  from many addresses. M5 (edge rate limiting before the Worker) remains
  needed before public production.
- New availability dependency: if Siteverify is unreachable, passkey
  sign-in fails closed (403), as OAuth start already does. Decision for
  you: accept this. Failing open would remove M3's protection.
- Siteverify is a subrequest per attempt (free; well within the Free
  plan's 50 subrequests per request).
- The M3b D1 read happens only for a correctly signed cookie, which needs a
  passed Turnstile; at most one read per Worker request.
- Passkeys are bound to the RP ID (`PASSKEY_RP_ID` = the workers.dev host).
  M3 does not change this; M5 does (see below).
- Latency: Siteverify adds about 100–300 ms before the options response.
  Some browsers require the WebAuthn call to follow a user gesture closely;
  the operator browser test (P2) must include Safari/iOS if that is a target.
- Old open tabs during a switch: an old page sends GET → 405 and a refresh
  fixes it. After a rollback, a new page sends POST → 405, which is also benign.
  Client and Worker ship in one version, so a fresh page always matches.

## 7. Automated tests (run in Workers Builds only)

Integration (workerd, Siteverify stubbed as in `tests/helpers/auth.ts`):

1. 21 options POSTs with a failing token → 21 × 403, Siteverify called 21
   times, **no admissions used** (then 20 valid requests still succeed).
2. Valid token: 20 × 200, the 21st 429, no challenge row and no cookie on
   the 429 (the existing case, moved to POST).
3. Foreign Origin, wrong content type, extra body field, missing token →
   403 / 415 / 400 / 400, Siteverify 0, admissions 0.
4. `GET` → 405 with `Allow: POST`.
5. Unidentifiable client → 429 before Siteverify.
6. Siteverify unavailable (stub 5xx / timeout) → 403, admissions 0.
7. verify with no cookie, a forged signature, a malformed value or a
   consumed challenge → 400, admissions 0. Then 20 options still succeed.
8. verify with a live challenge shares the counter → 429 when exhausted
   (the current T4 case, with a real challenge cookie).
9. Full passkey sign-in end to end (`passkeys.test.ts`, `hardening.test.ts`)
   with the token, including account-policy denial (`ACCOUNT_DISABLED`).
10. Registration unaffected (existing tests unchanged).

Unit: the signed-cookie check against a cookie issued by Better Auth (pins
the better-call format), and wrong secret, truncated or empty signature, and
non-base64 values. Client (`tests/client`): Login renders the Turnstile
container when only passkeys are enabled.

Static (existing, unchanged): staging configuration and migrations pinned;
no new migration.

## 8. Durable Object and SQLite impact

| | Today | After M3 |
|---|---|---|
| Anonymous options request (no token / invalid) | 1 DO request, about 2 rows written, 1 D1 row | 0 DO, 0 D1 writes, 1 Siteverify |
| Anonymous verify request (no valid challenge) | 1 DO request, about 2 rows written | 0 DO; 0–1 D1 read |
| Real passkey sign-in | 2 DO requests (options + verify) | unchanged |

P1's T3/T4 pattern (22 scripted requests, all counted) would cost 0 Durable
Object requests under M3. The amortised costs per counter from M4 are
unchanged.

## 9. Hosted validation and rollout

| Gate | What | Who |
|---|---|---|
| G0 | approve this design (and the M3b scope choice) | you |
| G1 | implement on local branch `m3/passkey-turnstile` from `deploy/staging`; no local builds or tests | Claude |
| G2 | push that branch; Builds production branch temporarily set to it (F1 precedent), Deploy command stays the dry run; review the log; restore `deploy/staging` | you approve the push and switch |
| G3 | fast-forward `deploy/staging`, push (dry-run build), review the log | separate approval |
| G4 (U3) | inactive upload: a docs-only commit pushed while the upload command is saved (not Retry), then restore the dry run | separate approval |
| G5 (P2) | bounded activation, mandatory rollback, ≤ 30 min | separate approval |

P2 live checks (scripted cases use invalid tokens only; staging refuses test keys):

- 21 × POST options with an invalid token → 403; DO requests in analytics
  unchanged across the run.
- `GET` options → 405; 21 × verify with no cookie → 400; DO unchanged.
- Operator browser: passkey sign-in end to end (needs a passkey registered
  on staging first, from the Security page, a separate step to approve);
  Google sign-in, dashboard, sign-out; cookie flags.
- The 20 / 60 s count on the options path cannot be scripted live, since it
  needs real tokens. It is covered by the hosted tests; live, only
  "Turnstile before the DO" and the browser flow are checked.

Browser automation in the cloud (for example Browser Rendering with a
virtual authenticator) would still meet a real Turnstile challenge. It is
a later, separately approved option, not a silent substitute for the
operator browser.

Rollback: dashboard rollback to `7750a63c` (or to `6b397259` if it is ever
activated). No migration or binding change, so it is always allowed.

## 10. Later gates (each separately approved)

**Authoritative `security_write`.** Used by passkey registration and the
`api/security.ts` writes (7 call sites), keyed by user after a session
check, so anonymous clients cannot reach it. Add `authoritative: { limit: 20 }`
(equal to `RL_SECURITY_WRITE`; the static test enforces equality). Cost:
one DO request per security change by a signed-in user. Tests: 21st write
429 per user; another user unaffected; the limiter failing → deny. No
migration (same class, new counter names).

**Authoritative `recovery`.** No recovery endpoint exists yet
(`RL_RECOVERY` 3 / 60 s is unused). Gate this with the endpoint's own
design. Expected shape: Turnstile (`recovery` action, already in
`TurnstileAction`) → limit keyed by IP and by target account → uniform
response (no account enumeration).

**Authoritative `provision`.** Also unused in code (`RL_PROVISION` 5 / 60 s).
It belongs to the provisioning endpoints of the W2 workstream; key by
account/user. It must not touch the r4 contract (schemas, signatures,
fixtures, checksums).

**M5: custom domain and WAF.** A zone on the account; a Worker custom
domain; a WAF rate-limiting rule for `/api/auth/*` (plan-dependent: Free
has a single basic rule); then `workers_dev: false` so the edge rule
cannot be bypassed through workers.dev. Breaking change: `PUBLIC_ORIGIN`,
`PASSKEY_RP_ID`, Turnstile hostnames and OAuth redirect URIs move to the
new host, and passkeys registered for the workers.dev RP ID stop working.
Plan a re-registration or a staged cutover. DNS, zone and possibly billing
are your decisions.
