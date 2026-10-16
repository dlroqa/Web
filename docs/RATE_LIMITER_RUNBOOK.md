# Authoritative rate limiter: operations runbook

Operating the `AuthRateLimiter` Durable Object (see
[SECURITY_MODEL.md](SECURITY_MODEL.md#rate-limiting)) on Cloudflare Workers
Free and Paid. One implementation serves both plans: nothing in the code
reads or depends on the billing plan, and nothing activates on a plan
change. Activation is always a separately approved `versions deploy`.

Plan figures below are from Cloudflare's documentation as of 2026-10-16
([Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/),
[Workers limits](https://developers.cloudflare.com/workers/platform/limits/),
[Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/),
[Budget alerts](https://developers.cloudflare.com/billing/manage/budget-alerts/));
check them again before relying on them.

## Plan limits that matter

| | Workers Free | Workers Paid |
|---|---|---|
| Worker requests | 100,000 / day, then error 1027 | 10 M / month included, then metered |
| Durable Object requests (alarms count) | 100,000 / day | 1 M / month included, then metered |
| Durable Object rows written (`setAlarm` = 1, deletes count) | 100,000 / day | 50 M / month included, then metered |
| Durable Object rows read | 5 M / day | 25 B / month included, then metered |
| D1 rows written / read | 100,000 / 5 M per day | 50 M / 25 B per month included |
| Behaviour at the limit | operations of that type **fail** until 00:00 UTC | nothing fails; usage is **billed** |
| Durable Object backend | SQLite only (what we use) | SQLite or key-value |

All limits are **per account**, not per Worker: every Worker and database
in the account (including the unrelated `torvid` resources) draws on the
same daily allowances. Traffic to any of them brings the others closer to
the Free limits.

## What exhaustion does

- A Durable Object refusing because of a quota is an error to the limiter,
  which fails closed: every `login`, `passkey_login` and `signup` check
  returns `429 RATE_LIMITED` until 00:00 UTC. Sign-in is unavailable for
  everyone; already signed-in sessions keep working. Logged as
  `ratelimit.authoritative_failed`.
- Worker request exhaustion (Free) takes the whole Worker down (error
  1027), with or without the limiter. That is the floor any public Free
  deployment already has.
- D1 exhaustion (Free) breaks every route that reads or writes D1.

## Remaining quota-exhaustion risk (after F1)

- Sign-in start reaches the Durable Object only with a valid, single-use
  Turnstile token (M1). OAuth callbacks reach it only with a `state` and the
  state cookie (M2). Passkey options and verification reach it without
  Turnstile (M3, before public production).
- Each Durable Object call is one request; a refusal writes nothing. An
  admission costs 2 to 3 billable writes (under 2 for a counter busy at
  its limit, the abusive case; 3 for slow traffic, as before F1). Each
  alarm is one more request: about one per period for a busy counter, up
  to one per admission for traffic every 30–60 s, one per lifetime for
  slower traffic. Writes per admission always exceed requests per
  admission, so on Free the rows-written allowance is still the one that
  runs out first. On Paid the worst case (traffic every 30–60 s) costs
  about 5% more than before F1 (one extra request, $0.15/M, per
  admission); a busy counter costs about a third less.
- A client rotating IP addresses creates a new counter per address (up to
  about 2 Durable Object requests and 5 writes per first request). Rough
  Free-plan reach: about 50,000 such requests exhaust the Durable Object
  request allowance, below the Worker's own 100,000. That is an auth-only
  outage until 00:00 UTC, shared with the rest of the account. It is
  accepted (or not) at the activation gate; the remedy on staging is the
  rollback below.
- On Paid the same traffic is billed instead of refused. Cost is bounded
  by M1/M4, not by alerts.

## Upgrading to Workers Paid

A billing change made by the operator in the dashboard; no code,
configuration, binding, migration or redeploy. Resources (Worker, D1,
Durable Object namespace and its SQLite storage) belong to the account and
are not migrated. Because we use only SQLite-backed Durable Objects, a later
downgrade stays possible.

Before and after, record: the subscription page showing Workers Paid; the
`AuthRateLimiter` object count; the D1 table fingerprint; the active
deployment (`7750a63c` at 100% while P1 is not authorized). The upgrade
never changes which version serves traffic.

Then set, on Paid (Pay-as-you-go): a budget alert, and usage notifications
for Workers and Durable Objects where available.

**Budget alerts are not spending caps.** They are informational e-mails,
evaluated on the previous day's usage (about a day late), exclude the plan
fee, and do not pause or limit anything. Cloudflare offers no hard spending
limit for Workers usage. The only hard ceilings are the Free plan's daily
limits.

## Metrics and logs

| Signal | Where |
|---|---|
| Durable Object requests, rows written / read, errors | Dashboard → Durable Objects → `AuthRateLimiter` metrics; GraphQL Analytics API (account analytics read) |
| Worker requests, errors, 5xx | Dashboard → Worker → Metrics |
| D1 rows read / written | Dashboard → D1 → `lightagent-control-staging` → Metrics |
| `ratelimit.authoritative_failed`, `ratelimit.authoritative_missing` | Workers Logs (observability is on) or `wrangler tail` |
| `ratelimit.client_unidentified`, `ratelimit.exceeded` (`layer: authoritative`) | same |
| `auth.oauth.callback.failure` (`stage: precondition`) | same; callbacks refused before the limiter |
| Free-plan quota exhaustion | Durable Object errors in the metrics, `ratelimit.authoritative_failed` bursts, 429s for clients that made no prior attempt |

Without automated alerts (Free), check by hand: before activation, at
+15 min, +1 h and +24 h, and daily while active on Free.

## Activation preflight (P1; separately authorized)

1. The candidate (U2, uploaded inactive by Workers Builds from an approved
   commit) passed `npm run ci:cloudflare` and the staging dry run on
   Workers Builds; its build log is recorded.
2. Live state read back: `7750a63c` at 100%, candidate at 0%,
   `previews_enabled=false`, no pending D1 migration, migration tag
   `v1-auth-rate-limiter`, no production Worker.
3. Rollback (below) prepared and its Deploy command text checked.
4. Monitoring open: Workers Logs / `wrangler tail` filtered on
   `ratelimit.*` and `auth.*`, Durable Object and D1 metrics noted.
5. Test budget agreed: at most 150 auth requests, 300 Durable Object
   requests, 1,000 Durable Object rows written, 30 minutes, one tester
   address.
6. Stop conditions agreed (any one → roll back): any
   `ratelimit.authoritative_failed` or `_missing`; any 5xx on
   `/api/auth/*`; a 429 for a fresh client; a failed real Google sign-in;
   a CSP violation; the test budget exceeded.

## Emergency rollback to the carrier `7750a63c`

The carrier (`7750a63c-fd3d-424e-a2c7-feb062cd4633`) carries the
`AuthRateLimiter` class and migration but never calls it. Rolling back to
it is allowed (no Durable Object lifecycle change since). Versions before
it cannot be rolled back to.

- **Dashboard rollback** (fastest; no build, no local configuration):
  Worker → Deployments → the `7750a63c` version → Rollback. It moves
  traffic only. Confirm afterwards (read-only) that observability, logpush
  and tail settings are unchanged.
- **`wrangler versions deploy`** (reproducible, recorded): also re-sends
  non-versioned settings (logpush, tail consumers, observability) from the
  `wrangler.json` it is run with. Run it only from a staging build of the
  serving commit, through Workers Builds: Deploy command = staging guard,
  then
  `npx wrangler versions deploy 7750a63c-fd3d-424e-a2c7-feb062cd4633@100% --env staging --message "rollback to carrier" --yes`,
  on `deploy/staging`. Restore the dry-run Deploy command straight after.
  Never from an unverified local build.

After either: confirm `7750a63c` at 100% and the candidate at 0%, run the
staging smoke test, and record the deployment id.

## Human checkpoints

| Step | Who | Gate |
|---|---|---|
| F1 code (M1, M2, M4, M0) on an isolated branch | Claude | authorized; merge not authorized |
| Hosted CI of the F1 branch (temporary Builds branch switch) | operator changes the dashboard | separate approval |
| U2 inactive upload | operator + Claude | separate approval |
| Workers Paid upgrade (optional) | operator | operator's decision; never activates anything |
| P1 activation | operator | separate approval, against the preflight above |
| Rollback | operator or Claude | pre-approved for the stop conditions above |
| Public production (M3, M5, other policies) | operator | separate approval |
