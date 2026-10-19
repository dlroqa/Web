#!/usr/bin/env bash
# P2 bounded live tests (S1–S7) against staging with M3 active. Sequential, IPv4 only,
# fixed request counts (50 requests; 50 at most), no loops beyond the counts below.
# Invalid inputs only: no Turnstile token or challenge cookie sent here can succeed,
# and no credential of any kind is used.
# Stops at the first unexpected response (stop condition -> dashboard rollback).
#
# Live traffic: run only inside an approved P2 window (docs/plans/P2_RUNBOOK.md).
#
# Endpoint-level evidence that rejected requests never reach the authoritative
# limiter (20 / 60 s per address): S3 and S4 each send 21 requests from one
# address and expect no 429. If the limiter counted them, the 21st would be 429.
set -u
H=https://lightagent-control-staging.eddelaroca.workers.dev
EXPECT_IP=${EXPECT_IP:?set to the IPv4 address Cloudflare sees for this machine}
C=(curl -4 -sS --max-time 15 -o /dev/null)
MAX_REQUESTS=50
OPTIONS=$H/api/auth/passkey/generate-authenticate-options
VERIFY=$H/api/auth/passkey/verify-authentication
# Better Auth's challenge cookie on staging (HTTPS: __Secure- prefix, cookie prefix lightagent).
CHALLENGE=__Secure-lightagent.better-auth-passkey
# Shaped like a signed challenge (a 44-character signature) but signed by nobody.
FORGED=p2-forged-token.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
MALFORMED=p2-malformed-token
sent=0
out=
fail() { echo "STOP: $*  (requests sent: $sent)"; exit 1; }
# One request to staging; curl's output is left in $out. Call it directly,
# never inside $(…): a command substitution runs in a subshell, which loses
# the count.
req() {
  [ "$sent" -lt "$MAX_REQUESTS" ] || fail "request budget of $MAX_REQUESTS reached"
  sent=$((sent + 1))
  out=$("${C[@]}" "$@")
}

ip=$(curl -4 -s --max-time 8 https://www.cloudflare.com/cdn-cgi/trace | sed -n 's/^ip=//p')
[ "$ip" = "$EXPECT_IP" ] || fail "client IPv4 is $ip, expected $EXPECT_IP"
echo "client IPv4 $ip"

# S1 (M3a): passkey options are POST only -> GET is 405.
req -w '%{http_code}' "$OPTIONS"
[ "$out" = 405 ] || fail "S1: HTTP $out (expected 405)"
echo "S1 ok: GET options 405"

# S2 (M3a): a foreign Origin, and no Origin, are refused by the router -> 403.
req -w '%{http_code}' -X POST "$OPTIONS" -H 'origin: https://evil.example' -H 'content-type: application/json' --data '{"turnstileToken":"invalid"}'
[ "$out" = 403 ] || fail "S2a: HTTP $out (expected 403)"
req -w '%{http_code}' -X POST "$OPTIONS" -H 'content-type: application/json' --data '{"turnstileToken":"invalid"}'
[ "$out" = 403 ] || fail "S2b: HTTP $out (expected 403)"
echo "S2 ok: foreign and missing Origin 403"

# S3 (M3a): 21 options requests with an invalid token -> all 403, never 429.
for i in $(seq 1 21); do
  req -w '%{http_code}' -X POST "$OPTIONS" -H "origin: $H" -H 'content-type: application/json' --data '{"turnstileToken":"invalid"}'
  [ "$out" = 403 ] || fail "S3 attempt $i: HTTP $out (expected 403 TURNSTILE_FAILED)"
done
echo "S3 ok: 21 x 403"

# S4 (M3b): 21 verifications without a challenge cookie -> all 400, never 429.
for i in $(seq 1 21); do
  req -w '%{http_code}' -X POST "$VERIFY" -H "origin: $H" -H 'content-type: application/json' --data '{"response":{}}'
  [ "$out" = 400 ] || fail "S4 attempt $i: HTTP $out (expected 400)"
done
echo "S4 ok: 21 x 400"

# S5 (M3b): a forged and a malformed challenge cookie -> 400 each.
req -w '%{http_code}' -X POST "$VERIFY" -H "origin: $H" -H 'content-type: application/json' -H "cookie: $CHALLENGE=$FORGED" --data '{"response":{}}'
[ "$out" = 400 ] || fail "S5a: HTTP $out (expected 400)"
req -w '%{http_code}' -X POST "$VERIFY" -H "origin: $H" -H 'content-type: application/json' -H "cookie: $CHALLENGE=$MALFORMED" --data '{"response":{}}'
[ "$out" = 400 ] || fail "S5b: HTTP $out (expected 400)"
echo "S5 ok: forged and malformed challenge 400"

# S6 (M1): sign-in start with an invalid token -> 403 before the limiter.
req -w '%{http_code}' -X POST "$H/api/auth/sign-in/social" -H "origin: $H" -H 'content-type: application/json' --data '{"provider":"google","turnstileToken":"invalid"}'
[ "$out" = 403 ] || fail "S6: HTTP $out (expected 403 TURNSTILE_FAILED)"
echo "S6 ok: sign-in start 403"

# S7 (M2): callbacks that cannot succeed -> 302 to /login?error=…, before the limiter.
req -w '%{http_code} %{redirect_url}' "$H/api/auth/callback/google?code=x"
[ "$out" = "302 $H/login?error=state_not_found" ] || fail "S7a: $out"
req -w '%{http_code} %{redirect_url}' "$H/api/auth/callback/google?code=x&state=y"
[ "$out" = "302 $H/login?error=state_mismatch" ] || fail "S7b: $out"
echo "S7 ok: state_not_found, state_mismatch"
echo "DONE: $sent requests"
