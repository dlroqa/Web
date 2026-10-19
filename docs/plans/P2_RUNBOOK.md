# P2: bounded live validation of M3 on staging (runbook, not approved)

Status: prepared 2026-10-19. Nothing here has been run. Each step marked
**[approval]** needs its own explicit approval; the activation window needs a
separate approval naming its start time.

| | |
|---|---|
| Worker | `lightagent-control-staging` (Workers Free) |
| Candidate | M3 `8137e138-f6e4-41a9-a0da-c90ae04c6d78` (#24, uploaded by U3, 0%) |
| Rollback target | carrier `7750a63c-fd3d-424e-a2c7-feb062cd4633` (same migration tag `v1-auth-rate-limiter`: rollback allowed) |
| Not involved | F1 `6b397259` (0%); production; billing; migrations |
| Window | 30 minutes from promotion, of which the last 8 are reserved for rollback and checks |
| After the test | carrier back at 100%, mandatory, whatever the outcome |

## 1. Prerequisites (before any window)

1. **P2.0a [approval]**: push the P2 script, its offline test, the P2
   sequence test and this runbook to `deploy/staging` (dry run). Hosted
   evidence required: `tests/static/p2-bounded-tests.test.ts` (7) and
   `tests/integration/p2-sequence.test.ts` (1) pass, totals 50 files /
   1,115 tests, guarded dry run, no upload.
2. **P2.0b [approval]**: test passkeys registered (section 2), on the
   carrier, before the window, so the window is spent testing.
3. The operator has the browsers in section 4 ready, signed in to the Apple
   ID / profiles used in P2.0b, and the dashboard open on Deployments.
4. The client IPv4 for the scripted part is known (`EXPECT_IP`), and the
   operator's browsers' egress addresses are noted (for log attribution).

## 2. Test-passkey registration plan (P2.0b, not yet approved)

**Account.** The operator's existing staging account (Google sign-in, status
`active`), as used for P1 T6. Registration requires an active account and a
fresh session (Better Auth `freshAge`): sign in with Google immediately
before registering. No new account, no status change.

**Where.** On the carrier (`7750a63c`): passkey registration is unchanged by
M3 (session first, then `security_write` per user, then Better Auth), so
registering before the window keeps the window short and the credentials
valid under M3.

**Credentials (independent vs synced).**

| # | Browser / authenticator | Credential | Server row |
|---|---|---|---|
| 1 | Safari on macOS, iCloud Keychain | new, synced | 1 |
| 2 | Safari on iOS (same Apple ID, iCloud Keychain on) | **the same** credential as #1, synced: register nothing | none |
| 3 | Chrome desktop on macOS | reuse #1 if Chrome offers the iCloud Keychain passkey; otherwise a new Google Password Manager passkey | 0 or 1 |
| 4 | Edge / Firefox (Windows Hello or the platform authenticator) | new, independent, only if such a device is available | 0–2 |

At most 4 passkey rows; typically 1–2.

**Procedure (each new credential).** `/login` → Continue with Google →
Security → Add passkey → name it `P2 test – <browser/authenticator>` →
confirm with the authenticator → it appears in the Security list.

**Expected D1 writes per registration** (no Durable Object request:
`security_write` is binding-only): the challenge row (insert, then deleted by
verification), one `passkey` row, one `auth.passkey.add` audit row, plus the
Google sign-in before it (session, account update, `auth.login.success`
audit). About 10 rows written per registration, under 50 in total.

**Verification.** Security page lists the passkey with its name; the activity
list shows `auth.passkey.add`; a read-only D1 count of the operator's passkey
rows matches the table above.

**Not disturbing personal passkeys.** The credential's RP ID is the staging
host (`lightagent-control-staging.eddelaroca.workers.dev`), so it is a new,
separate entry in the keychain and touches no other site's passkey. Never
remove or rename existing entries; name the new ones as above.

**Cleanup or retention (decision for the operator).** Recommended: keep the
`P2 test – …` passkeys until P2 is recorded, then remove them from the
Security page (needs a fresh session; deletes the server row) and delete the
keychain entry for the staging host on each device. Alternatively keep them
for later staging tests and record that.

**If registration fails.**

- `REAUTH_REQUIRED`: sign in with Google again, retry.
- Cancelled or timed out prompt: nothing is stored; retry.
- Any other error: stop; no partial state remains (an unused challenge
  expires after 5 minutes; `npm run operator -- purge-verifications` removes
  expired rows). Report the request id shown in the error.

## 3. Baseline (read-only, within 1 hour before the window)

- Deployments: latest `b64a2fa9`, `7750a63c` 100%; versions: `8137e138`
  newest at 0%.
- Builds: production branch `deploy/staging`, dry-run Deploy command
  (`73fda913…`); no build running.
- Script settings: logpush false, no tail consumers, observability on.
- `previews_enabled: false`; no pending D1 migration; Durable Object
  namespace `f66cf65b` with no stored data.
- Usage so far today (Worker requests, Durable Object requests and rows
  written, D1 rows written), with spaced-out analytics queries (the GraphQL
  budget is small).

## 4. Window schedule (T = promotion time)

| T + min | Step |
|---|---|
| −2 | Start an **unfiltered** `wrangler tail lightagent-control-staging --format json` saved to a file. Requests are attributed by client IP and time; Durable Object invocations carry no IP, so an `--ip` filter would hide them. The tail drops events under load (P1: 14 of 29 Durable Object events), so it supports, never proves |
| 0 | **[approval: window]** Dashboard → Workers & Pages → `lightagent-control-staging` → Deployments → version `8137e138` (#24) → Deploy / Promote at 100%, message `P2 M3 8137e138`. Confirm with the deployments API (not the dashboard's Traffic % column) |
| 0–2 | Smoke: `GET /` 200 and `GET /api/me` 401, served by `8137e138` in the tail |
| 2–5 | Scripted: `EXPECT_IP=<ipv4> bash scripts/p2-bounded-tests.sh` (50 requests, about 1 minute). Expected `DONE: 50 requests` |
| 5–20 | Browsers, in priority order (below) |
| 20–22 | Edge / Firefox only if they are ready and time allows; otherwise **deferred** (no window extension) |
| 22 | **Rollback, whatever the state**: Deployments → Rollback to `7750a63c` (or `npx wrangler versions deploy 7750a63c-fd3d-424e-a2c7-feb062cd4633@100% --name lightagent-control-staging --message "P2 rollback" --yes` from a staging build) |
| 22–28 | Post-rollback checks (section 7) |
| 30 | Hard deadline: carrier at 100% |

**Browser sequence**, each: open a **new** tab on `/login` (an old tab gets
405 on the options call), wait for the widget, Continue with passkey →
authenticator → dashboard → Security → sign out.

1. Safari macOS (#1): the full sequence; once, cancel the prompt first:
   expect the "No passkey was used…" message, then retry successfully (a
   fresh token after the widget reset).
2. Safari iOS (#2, synced #1): the full sequence.
3. Chrome desktop (#3): the full sequence; once, also Continue with Google
   (M1 regression) and sign out.
4. Edge / Firefox (#4): the full sequence, if not deferred.

Each browser: DevTools (where available) shows the options request as
`POST … 200` and the verify request as `POST … 200`; session cookie
`HttpOnly; Secure; SameSite=Strict`; 0 CSP violations.

## 5. Budgets (Workers Free; whole window)

| Resource | Expected | Hard stop |
|---|---|---|
| Worker requests | ~150 (script 50, browsers ~15–20 each) | 400 |
| Durable Object requests | 0 from the script; 2 per passkey sign-in, 2 per Google sign-in, ~1 cleanup alarm per counter: ~15–25 | 100 |
| Durable Object rows written | ~50 | 300 |
| D1 rows written | sessions, audits, challenges: < 200 | 1,000 |
| Siteverify calls | script 22, browsers 1 per attempt | — |

Daily Free allowances (100k each for Worker requests, Durable Object
requests and rows written, D1 rows written) are not approached.

## 6. Stop conditions (immediate rollback)

- Any HTTP 5xx, Worker exception, `ratelimit.authoritative_failed` or
  `auth.passkey.precheck_failed`.
- Any unexpected answer in the script (it stops itself), in particular a 429
  in S3 or S4 (a rejected request reached the limiter).
- In the tail, a Durable Object invocation during the scripted phase (the
  script runs alone for about a minute; account analytics alone do not
  attribute).
- A valid browser sign-in refused (403, 429, 400) other than by the
  operator's own cancellation.
- Budget hard stop reached, or T + 22 minutes.

## 7. Post-rollback verification

- Deployments API: new deployment with `7750a63c` at 100%; `8137e138`
  and `6b397259` at 0%.
- Tail: `GET /` 200 and `GET /api/me` 401 served by `7750a63c`.
- A fresh `/login` loads; Google sign-in works on the carrier (optional,
  one attempt).
- Durable Object namespace: alarms drain and objects return to no stored
  data (within about 5 minutes after the last admission, M4).
- Usage deltas recorded against the baseline; tail capture saved; audit rows
  for the browser sign-ins present.
- Record P2 in `docs/DEPLOYMENT.md` (one docs commit; its push runs a dry
  run) **[approval]**.

## 8. Evidence attribution

Account-wide Durable Object and Worker analytics include unrelated activity
(other Workers on the account share the Durable Object allowance) and lag by
minutes. They support but never prove endpoint behaviour. The evidence for
"rejected requests never reach the limiter" is, in order:

1. the hosted `tests/integration/p2-sequence.test.ts` (zero admissions for
   the exact sequence, in workerd);
2. the script's 21-request checks (no 429 where the limiter would answer 429);
3. the unfiltered tail: no Durable Object invocation between the script's
   first and last request (best effort: the tail can drop events).
