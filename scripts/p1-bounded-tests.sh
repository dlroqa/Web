#!/usr/bin/env bash
# P1 bounded live tests (T1–T5) against staging. Sequential, IPv4 only,
# fixed request counts (46 requests; 49 at most), no loops beyond the counts below.
# Stops at the first unexpected response (stop condition -> dashboard rollback).
#
# Live traffic: run only inside an approved activation window (see
# docs/DEPLOYMENT.md, P1). Record of the 2026-10-17 run there.
set -u
H=https://lightagent-control-staging.eddelaroca.workers.dev
EXPECT_IP=${EXPECT_IP:?set to the IPv4 address Cloudflare sees for this machine}
C=(curl -4 -sS --max-time 15 -o /dev/null)
MAX_REQUESTS=49
sent=0
out=
fail() { echo "STOP: $*  (requests sent: $sent)"; exit 1; }
# One request to staging; curl's output is left in $out. Call it directly,
# never inside $(…): a command substitution runs in a subshell, which loses
# the count (the 2026-10-17 run reported 1 request for 46 sent).
req() {
  [ "$sent" -lt "$MAX_REQUESTS" ] || fail "request budget of $MAX_REQUESTS reached"
  sent=$((sent + 1))
  out=$("${C[@]}" "$@")
}

ip=$(curl -4 -s --max-time 8 https://www.cloudflare.com/cdn-cgi/trace | sed -n 's/^ip=//p')
[ "$ip" = "$EXPECT_IP" ] || fail "client IPv4 is $ip, expected $EXPECT_IP"
echo "client IPv4 $ip"

# T1 (M1): 21 sign-in starts with an invalid Turnstile token -> all 403, never 429.
for i in $(seq 1 21); do
  req -w '%{http_code}' -X POST "$H/api/auth/sign-in/social" \
    -H "origin: $H" -H 'content-type: application/json' \
    --data '{"provider":"google","turnstileToken":"invalid"}'
  s=$out
  [ "$s" = 403 ] || fail "T1 attempt $i: HTTP $s (expected 403 TURNSTILE_FAILED)"
done
echo "T1 ok: 21 x 403"

# T2 (M2): callbacks that cannot succeed -> 302 to /login?error=…, before the limiter.
req -w '%{http_code} %{redirect_url}' "$H/api/auth/callback/google?code=x"
loc=$out
[ "$loc" = "302 $H/login?error=state_not_found" ] || fail "T2a: $loc"
req -w '%{http_code} %{redirect_url}' "$H/api/auth/callback/google?code=x&state=y"
loc=$out
[ "$loc" = "302 $H/login?error=state_mismatch" ] || fail "T2b: $loc"
echo "T2 ok: state_not_found, state_mismatch"

# T3: 21 passkey sign-in options -> 20 x 200, then 429 with Retry-After 1..60.
for i in $(seq 1 20); do
  req -w '%{http_code}' "$H/api/auth/passkey/generate-authenticate-options"
  s=$out
  [ "$s" = 200 ] || fail "T3 request $i: HTTP $s (expected 200)"
done
req -D - "$H/api/auth/passkey/generate-authenticate-options"
hdr=$out
s=$(printf '%s' "$hdr" | head -1 | awk '{print $2}')
ra=$(printf '%s' "$hdr" | tr -d '\r' | sed -n 's/^retry-after: *//Ip')
[ "$s" = 429 ] || fail "T3 request 21: HTTP $s (expected 429)"
[ "${ra:-0}" -ge 1 ] && [ "${ra:-0}" -le 60 ] || fail "T3 Retry-After '$ra'"
echo "T3 ok: 20 x 200, then 429 Retry-After $ra"

# T4: passkey verification shares the counter -> 429 before the body is read.
req -w '%{http_code}' -X POST "$H/api/auth/passkey/verify-authentication" \
  -H "origin: $H" -H 'content-type: application/json' --data '{}'
s=$out
[ "$s" = 429 ] || fail "T4: HTTP $s (expected 429)"
echo "T4 ok: 429"

# T5: after Retry-After + 1 s, the oldest slot has expired -> 200.
sleep $((ra + 1))
req -w '%{http_code}' "$H/api/auth/passkey/generate-authenticate-options"
s=$out
[ "$s" = 200 ] || fail "T5: HTTP $s (expected 200)"
echo "T5 ok: 200 after the window moved"
echo "DONE: $sent requests"
