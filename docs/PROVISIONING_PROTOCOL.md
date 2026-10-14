# LA-WEB-PROVISIONING/1: provisioning protocol

| | |
|---|---|
| Protocol identifier | `LA-WEB-PROVISIONING/1` |
| Revision | `la-web-provisioning-1/r2` (changes from r1: §18) |
| Status | **Candidate.** It is not frozen until Web and Lightagent both record acceptance of the same compatibility digest in `protocol/la-web-provisioning-1/ACCEPTANCE.md`. |
| Owner | Web (`lightagent-control`). Lightagent mirrors a byte-identical copy. |
| Fixtures | `protocol/la-web-provisioning-1/` (listed in `MANIFEST.json`) |
| Reference codec | `tests/contracts/provisioning/reference.ts` (test-only; not imported by the Worker) |

This document is normative. The key words MUST, MUST NOT, SHOULD and MAY are
used as in RFC 2119. Section numbers (§n) are stable within a revision.
Wherever this text and a fixture disagree, the disagreement is a defect in
the revision, and neither side may ship until it is fixed. Neither side may
silently prefer one of the two.

The status line above is deliberately not changed when the protocol is
accepted, because the file is hashed. Acceptance is recorded in
`ACCEPTANCE.md`, which is outside the manifest.

## 1. Scope and frozen decisions

`LA-WEB-PROVISIONING/1` carries Ed25519-signed control commands from the Web
Worker to one registered Lightagent harness. It does three things:

| Operation | Effect on the harness |
|---|---|
| `profile.create` | Create the profile `agt_…` and bind it to the local principal derived from `(issuer, subject)`, through Lightagent's existing `ProvisioningService::provision` |
| `profile.status` | Read one operation's state. Read-only |
| `profile.revoke` | Irreversibly remove the owner binding of a completed operation (`ProvisioningService::revoke`). The profile data stays with the harness operator |

Frozen for v1:

1. Web signs. Lightagent verifies the signature **and** independently applies
   its own registered `{provision}`-only authority (§10.2). A valid signature
   grants nothing by itself.
2. Polling only. The harness never sends a request to Web. There are no
   callbacks, no callback URL, and no outbox.
3. `profile.disable` and `profile.enable` are not v1 operations. A harness
   refuses them (`UNSUPPORTED_OPERATION`). Web never sends them.
4. Revocation is addressed by the **operation id** that `profile.create`
   returned, as in Lightagent today. It is terminal.
5. Display names are 1–64 Unicode scalar values (§8.1).
6. Web `agt_` ids are Lightagent profile ids unchanged. Lightagent derives its
   principal from `(issuer, subject)`. The body never carries a principal,
   owner, role or permission.
7. No revocation-version counter in v1. Ordering safety comes from Lightagent's
   operation ledger and Web rules R1–R6 (§13). Analysis: §13.8.
8. A profile id is never assigned to a second Web profile, and is never
   provisioned again after it was revoked. A network timeout is never
   evidence of failure.
9. The browser never talks to a harness. Only the Worker sends commands.
10. Runtime invocation, sessions, tools and permissions are out of scope.

## 2. Roles and trust

| Party | Owns | Trusted for |
|---|---|---|
| Web Worker | Users, sessions, account status, `agt_` placement, desired state, D1 jobs, the signing key | Asserting `(issuer, subject)` for users it authenticated, and its intent |
| Lightagent harness | Local principals, the operation ledger, profiles, ownership bindings, runtime isolation | Executing or refusing commands under its own authority, and reporting operation state |
| Harness operator | The trusted-key list, the key → local credential mapping, the provisioner registration (issuers, template, quota) | Deciding whether Web may provision at all |

Neither side reads or writes the other's database or filesystem. The
`(issuer, subject)` pair is Web's assertion, and Lightagent trusts it only
because an operator registered that issuer for the provisioner that the
signing key maps to (§10.2).

## 3. Transport

| Item | Rule |
|---|---|
| URL | `{endpoint}/la-web-provisioning/1/commands`, where `{endpoint}` is `harnesses.endpoint` without a trailing `/`. One URL for all three operations. The operation is inside the signed body, never in the path or query |
| Method | `POST` only. Anything else: `405 METHOD_NOT_ALLOWED` |
| Request headers | `Content-Type: application/json` (exact string, no parameters; otherwise `415 UNSUPPORTED_MEDIA_TYPE`), `Accept: application/json`. No `Authorization` header and no cookies. The signature is the only provisioning credential. Only one other pair of headers is allowed: `CF-Access-Client-Id` and `CF-Access-Client-Secret`, when the endpoint sits behind a Cloudflare Access service-token policy (§12.5). Cloudflare consumes them, and the harness MUST NOT treat them, or the `Cf-Access-Jwt-Assertion` header that Access adds, as provisioning authority |
| Body | At most **8192 bytes** (`MAX_MESSAGE_BYTES`). A harness MUST stop reading after 8192 bytes and answer `413 PAYLOAD_TOO_LARGE`, whatever `Content-Length` says |
| TLS | `https://` with certificate validation by the Workers runtime, to an ingress that meets §12.5. `http://` only for `environment = 'development'`, as the `harnesses` CHECK already enforces |
| Redirects | Never followed (`fetchWithTimeout` uses `redirect: "manual"`). A 3xx is an *uncertain* outcome (§12.4) |
| Timeout | Web SHOULD use 10 s per transmission. A timeout is an *uncertain* outcome |
| Response | `application/json`, at most 8192 bytes, schemas in §12. Web reads at most 8192 bytes |
| Who calls | Only the Worker, from server code. Endpoint and harness come from the administrator-controlled `harnesses` row, never from a request |

## 4. Message encoding

### 4.1 Text

A message is UTF-8 (RFC 3629) without a byte order mark. Invalid UTF-8,
overlong forms, encoded surrogates, and a leading `EF BB BF` are
`MALFORMED_JSON`.

### 4.2 Strict JSON

The body MUST be one JSON text (RFC 8259) with the I-JSON restrictions of
RFC 7493. A verifier MUST use a parser that:

- rejects any syntax error, trailing data, a raw control character inside a
  string, and a `\u` escape that is a lone surrogate (`MALFORMED_JSON`);
- rejects nesting deeper than **16** levels (`MALFORMED_JSON`);
- detects **duplicate member names at every level**, compared after
  unescaping (`"nonce"` and `"nonce"` are the same name). It reports
  `DUPLICATE_KEY` only after the whole text is known to be well formed, so
  that a malformed text is always `MALFORMED_JSON`;
- keeps each number's exact lexeme, because the value profile (§4.3) is a
  lexical rule.

`JSON.parse`, `serde_json::from_slice` with default settings and similar
general-purpose parsers keep the last duplicate silently and lose number
lexemes. They MUST NOT be the first stage. The reference uses a small
dedicated parser (`parseStrictJson`). A Rust implementation SHOULD do the
same, or use a streaming tokenizer that exposes raw number text and every
member name.

### 4.3 Command value profile

After parsing, every value in a command MUST be one of:

| JSON type | Allowed form |
|---|---|
| object | members as in §7–§8 |
| string | §4.5, §4.6 |
| number | non-negative integer, lexeme `0` or `[1-9][0-9]*`, value ≤ 2^53 − 1 |

`null`, `true`, `false`, arrays, fractions (`1.0`), exponents (`1e3`), signs
(`-0`, `-1`) and values above 2^53 − 1 are `INVALID_JSON_VALUE`. Leading
zeros and `+` are not JSON, so they are `MALFORMED_JSON`. There is no null
handling in commands, because a field is either present with a valid value or
the command is refused. Responses (§12) use `null` and booleans in named
places only.

### 4.4 Field encodings (C9)

Each field has exactly one encoding. A value in another encoding of the same
bytes is `INVALID_FIELD`.

| Field | Encoding |
|---|---|
| `signature` | base64url (RFC 4648 §5), **no padding**, 64 bytes → exactly 86 characters, last character in `[AQgw]` (zero padding bits) |
| `nonce` | base64url, no padding, 32 random bytes → exactly 43 characters, last character in `[AEIMQUYcgkosw048]` |
| Ed25519 public key (harness configuration, `keys.json`) | base64url, no padding, 32 raw bytes (RFC 8032 encoding) → 43 characters |
| `keyId` | `^[a-z0-9][a-z0-9._-]{2,63}$` (a subset of D1 `harnesses.key_id`) |
| timestamps | integer Unix seconds, 10 digits (1000000000–9999999999). Milliseconds are refused |
| fixture bytes | lowercase hex (fixture files only, never on the wire) |

D1 `harnesses.public_key` (standard base64 with padding, 44 characters) is
reserved for a future harness response key (§12.1). It is not used in v1, and
no v1 field shares its encoding.

### 4.5 Identifier formats

| Field | Pattern | Source |
|---|---|---|
| `commandId` | `^cmd_[a-z0-9]{8,60}$` | Web `randomId("cmd")`, new per transmission |
| `jobId` | `^prv_[a-z0-9]{8,60}$` | `provisioning_jobs.id` |
| `requestId` | `^req_[a-z0-9]{8,60}$` | `provisioning_jobs.request_id` |
| `audience` | `^hns_[a-z0-9]{8,60}$` | `harnesses.id`, the target harness |
| `profileId` | `^agt_[a-z0-9]{8,60}$` | `agent_profiles.id` (also satisfies Lightagent `^[a-z0-9][a-z0-9_-]{0,63}$`, and is never `default`) |
| `subject` | `^usr_[a-z0-9]{8,60}$` | `user_profiles.id`: immutable, never the Better Auth id, never an email |
| `issuer` | `https://` + lowercase DNS host + optional `:port` (1–65535), no path, no trailing `/`, no userinfo, query or fragment, ≤ 256 bytes | Web's configured issuer identifier. Compared byte for byte with the operator registration. A subset of Lightagent's issuer rule |
| `idempotencyKey` | `^[A-Za-z0-9_-]{16,128}$` | `provisioning_jobs.idempotency_key` (a subset of Lightagent's 8–128 `[A-Za-z0-9._:-]`) |
| `operationId` | `^[0-9a-f]{32}$` | Returned by the harness |
| `principalId` (responses) | `^[a-z0-9][a-z0-9_-]{0,63}$` | Lightagent `PrincipalId`. Opaque to Web: stored, never interpreted |

### 4.6 Unicode policy

- Every string except `displayName` is ASCII by its pattern.
- `displayName` MUST already be in Unicode Normalization Form C. A verifier
  checks `NFC(s) == s` and MUST NOT normalize on the receiver side, because
  normalizing after verification would change bytes that were signed.
- Lengths count **Unicode scalar values** (JavaScript `[...s].length`, Rust
  `s.chars().count()`), never UTF-16 code units (`s.length`) or bytes.
- Unpaired surrogates cannot occur. They are refused at parse time (§4.2).
- No other normalization, case folding or confusable mapping is applied to
  any field.
- **Unicode data versions.** Normalization tables follow each side's Unicode
  version: V8/ICU in workerd on Web, and ICU4X `icu_normalizer` (already
  compiled into every Lightagent binary) on the harness. NFC is stable for
  characters assigned in both versions, so the two sides can only disagree
  about characters assigned in one version and not the other. Such a
  disagreement yields `INVALID_DISPLAY_NAME`, a `payload`-class refusal that
  is final and has no effect (§13.2 R2). It never produces a wrong binding.
  Web MAY refuse, before signing, names containing unassigned code points in
  its own engine (`/\p{Cn}/u`). The conformance results of each side SHOULD
  record the Unicode version they used.

## 5. Canonical form

The canonical form of a JSON value is its **JSON Canonicalization Scheme**
serialization (RFC 8785, JCS). Inside the §4.3 profile, JCS reduces to:

- objects: members sorted by name in UTF-16 code-unit order. Every v1 member
  name is ASCII, so this is byte order. No whitespace anywhere;
- strings: `"` and `\` escaped as `\"` and `\\`; U+0008, U+0009, U+000A,
  U+000C and U+000D as `\b \t \n \f \r`; other characters below U+0020 as
  `\u00xx` with lowercase hex; **every other character as raw UTF-8**,
  including `/`, U+007F, U+2028 and non-ASCII. Since the valid v1 strings
  contain no control characters, a valid canonical body never contains a
  `\u` escape;
- numbers: the decimal digits of the integer.

A JCS library may be used if it produces identical bytes for every fixture.
Implementing the profile directly (about 40 lines) is also acceptable. Plain
`JSON.stringify` (insertion order) and `serde_json::to_vec` are not
canonicalizers. The fixture `signature-over-json-stringify` shows the
difference.

**The wire body MUST be the canonical form of the complete command, including
`signature`.** A verifier re-serializes the parsed command and compares the
bytes exactly. A difference is `NON_CANONICAL`, whether it is whitespace,
member order, an escape such as `é`, `\/` or `C`, a trailing
newline or a leading space. One accepted byte form per command removes
parser-differential ambiguity: what was signed is what was sent, minus the
signature member.

## 6. Signature

### 6.1 Signed bytes

```text
signingInput = SIGNING_CONTEXT ‖ UTF-8( JCS( command without the "signature" member ) )

SIGNING_CONTEXT = "LA-WEB-PROVISIONING/1" 0x00 "provisioning-command" 0x00
                = 4c412d5745422d50524f564953494f4e494e472f31 00
                  70726f766973696f6e696e672d636f6d6d616e64 00
```

The context binds the protocol version and the message purpose outside the
JSON, so a signature made for another purpose (for example the reserved
`provisioning-response`, or a future `agent-invocation`) can never verify as a
command, even under the same key. The same values also appear inside the JSON
(`protocol`, `purpose`) and are checked there (§10), so a confused purpose is
reported as `WRONG_PURPOSE` rather than as a bare signature failure.

`0x00` cannot occur in JCS output, so the concatenation is unambiguous.

### 6.2 Algorithm

- **Ed25519** (RFC 8032 §5.1, "pure" Ed25519: no prehash, no context
  parameter). Ed25519ph and Ed25519ctx are not used, because Web Crypto in
  workerd offers only pure Ed25519.
- Verification MUST reject a signature whose scalar `S` is not below the
  group order `L` (RFC 8032 §5.1.7). The reference checks this explicitly
  and does not rely on a library default. Fixture: `signature-noncanonical-s`.
- The signature is over `signingInput` exactly, never over a hash of it.
- Ed25519 is deterministic: the same key and bytes always give the same
  signature. The fixtures depend on this.

### 6.3 Worked example (`valid-create-basic`)

`JCS(command without signature)`, 647 bytes (the signing input adds the 43-byte context: 690 bytes):

```json
{"audience":"hns_fixtureharnessalpha0000001","commandId":"cmd_430fe33cce765249e22be19eb9","expiresAt":1791000060,"issuedAt":1791000000,"jobId":"prv_fixturejobcreate000000001","keyId":"web-test-active","nonce":"uJwbU6ZT_YxFgSeatXYQM0aiQ3ZZwhRq6c1hwVY5sog","operation":"profile.create","payload":{"displayName":"Research assistant","idempotencyKey":"idk_fixturecreate00000000001","issuer":"https://lightagent-control.example","profileId":"agt_fixtureprofile000000000001","subject":"usr_fixtureuser00000000000001","template":"assistant"},"protocol":"LA-WEB-PROVISIONING/1","purpose":"provisioning-command","requestId":"req_fixturerequest00000000001"}
```

Signed with the test-only key `web-test-active` (public key
`e_ezzMPOYjkP-vj8ROC_HIkvz6wHTM2zMLNFjNdTGwQ`), the signature is

```text
mTaD9VRZ89cf2gwes4YUoJWXfH15uOrbmYl6GMpQ85CbKXj7HWB7RtTNyR4gPe1nl3uTQEujsua9QMd1HEv0AA
```

and the wire body (748 bytes) is the JCS form of the command with
`"signature"` inserted in sorted position, between `"requestId"` and the
closing brace. The exact bytes are `bodyHex` in `commands-valid.json`.

### 6.4 Keys, rotation and revocation

- Web holds the Ed25519 private key as a Cloudflare secret. It is never in
  `wrangler.jsonc`, never in a `VITE_*` or `LIGHTAGENT_PUBLIC_*` variable,
  never in D1 and never in the client bundle. L0 creates no key.
- Each harness operator configures a **trusted-key list**:
  `{ keyId, publicKey, status: "active" | "revoked" }`. `keyId` is chosen by
  Web and is unique per Web environment. Staging and production never share
  a key.
- A `keyId` that is not in the list is `UNKNOWN_KEY`. One with status
  `revoked` is `KEY_REVOKED`, even when the signature is valid.
- **Rotation:** (1) the operator adds the new key as `active` (overlap);
  (2) Web starts signing with it; (3) once no command signed by the old key
  can still be accepted (wait ≥ 120 + 30 s), the operator removes the old key,
  which then gives `UNKNOWN_KEY`, or marks it `revoked`. Redeliveries may
  change `keyId` across a rotation (§9.1). Fixtures:
  `valid-create-rotated-key`, `valid-status-after-rotation`,
  `key-rotated-away`.
- **Compromise:** mark the key `revoked` at once on every harness. Lightagent
  can additionally revoke the mapped local credential (§10.2), which stops
  every key mapped to it.
- **Every trusted `keyId` for one Web environment MUST map to the same local
  provisioner principal** (§10.2). Idempotency is scoped to the provisioner,
  so a redelivery under a rotated key must reach the same scope.

## 7. Command envelope

Schema identifiers: `LA-WEB-PROVISIONING/1#command/profile.create`,
`…#command/profile.status`, `…#command/profile.revoke`.

A command is a JSON object with **exactly** these 13 members. All are
required. Any other member is `UNKNOWN_FIELD`, and a missing one is
`MISSING_FIELD`.

| Member | Type | Rule | Identity role (§9.1) |
|---|---|---|---|
| `protocol` | string | exactly `LA-WEB-PROVISIONING/1` | logical |
| `purpose` | string | exactly `provisioning-command` | logical |
| `operation` | string | `profile.create`, `profile.status` or `profile.revoke` | logical |
| `commandId` | string | §4.5. Unique per transmission. Echoed in the response | per transmission |
| `jobId` | string | §4.5. The D1 job this transmission serves (a status poll uses the job it reconciles) | logical |
| `requestId` | string | §4.5. The originating API request of that job, for log correlation | logical |
| `audience` | string | §4.5. The target harness id. MUST equal the verifier's own configured harness id | logical |
| `keyId` | string | §4.4 | may change on rotation |
| `issuedAt` | integer | §4.4. Web's clock at signing | per transmission |
| `expiresAt` | integer | §4.4. `1 ≤ expiresAt − issuedAt ≤ 120` (otherwise `INVALID_LIFETIME`). Web SHOULD use 60 | per transmission |
| `nonce` | string | §4.4. 32 bytes from a CSPRNG, new per transmission | per transmission |
| `payload` | object | §8, closed per operation | logical |
| `signature` | string | §4.4, §6 | per transmission |

The external identity is carried in the `profile.create` payload as `issuer`
and `subject`. The envelope has no separate signer-issuer field: the signer
is identified by `keyId`, and the harness operator binds `keyId` to a local
credential (§10.2).

## 8. Payloads

### 8.1 `profile.create`

Exactly these members:

| Member | Rule | Error |
|---|---|---|
| `profileId` | §4.5 | `INVALID_PROFILE_ID` |
| `issuer` | §4.5 | `INVALID_ISSUER` |
| `subject` | §4.5 | `INVALID_SUBJECT` |
| `displayName` | NFC; 1–64 Unicode scalar values; no character of general category Cc (U+0000–U+001F, U+007F–U+009F); first and last character not Unicode `White_Space` (U+0009–U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000) | `INVALID_DISPLAY_NAME` |
| `template` | exactly `assistant` | `INVALID_TEMPLATE` |
| `idempotencyKey` | §4.5 | `INVALID_IDEMPOTENCY_KEY` |

The display-name rule is Lightagent's (`chars().count()`, `char::is_control`,
`str::trim`) plus NFC. JavaScript's `String.prototype.trim` uses a different
set: it strips U+FEFF and does not strip U+0085. It MUST NOT be used.
Fixtures pin the difference (`valid-create-leading-bom-char`,
`display-name-control-c1`). Web MAY apply a stricter name policy in its UI.
It MUST NOT sign a name that fails this rule.

### 8.2 `profile.status` and 8.3 `profile.revoke`

Exactly `{ "operationId", "profileId" }`. `operationId` is the value a
`profile.create` returned. `profileId` MUST be that operation's profile. A
harness answers a mismatch exactly like an unknown operation
(`UNKNOWN_OPERATION`), so the field is a consistency check and not an
oracle. Neither operation takes an idempotency key: status is read-only, and
revoke is idempotent by operation.

### 8.4 Forbidden content

No v1 payload may carry permissions, tool grants, toolsets, approval policy,
model, provider, base URL, endpoint, callback URL, filesystem path, `cwd`,
workspace, principal id, owner, role, capability, credential, token,
revocation version, or any configuration. Because the schemas are closed,
each of these is `UNKNOWN_FIELD`. Web's `permissions_json` is a Web-side
ceiling and grants nothing on the harness (C8). The `template` name is the
only lever, and the harness defines what it means.

`profile.disable`, `profile.enable`, `agent.*`, `profile.lookup` and any other
operation name are `UNSUPPORTED_OPERATION`.

## 9. Identity, retries, replay and time

### 9.1 Logical command and transmission

A **logical command** is one D1 job's intent. A **transmission** is one signed
HTTP request for it. Every transmission of one logical command:

- repeats `protocol`, `purpose`, `operation`, `jobId`, `requestId`, `audience`
  and the **byte-identical canonical `payload`**, and therefore the same
  `idempotencyKey`;
- renews `commandId`, `nonce`, `issuedAt`, `expiresAt` and `signature`;
- may change `keyId` only across a key rotation (§6.4).

`commandId` is therefore a per-transmission correlation id (logs, response
binding). The retry identity is `(jobId, operation, payloadHash)`, and the
harness's side-effect fence is its idempotency ledger `(provisioner,
idempotencyKey)`.

```text
payloadHash = lowercase hex SHA-256( "LA-WEB-PROVISIONING/1" 0x00 "payload" 0x00 operation 0x00 ‖ JCS(payload) )
```

`payloadHash` is the value Web stores as `provisioning_jobs.request_hash`. A
transmission whose `payloadHash` differs from its job's is a Web defect and
MUST NOT be sent. If one is sent anyway, Lightagent answers
`IDEMPOTENCY_CONFLICT` and nothing changes. Fixtures: `redelivery.json`.

### 9.2 Nonces

- The harness records each accepted nonce **before** local admission and
  before any side effect, atomically (insert-if-absent), and keeps it at least
  until `expiresAt + 30` s. A nonce already present is `REPLAY_DETECTED`.
- Nonces are scoped to the harness: one ledger across all keys.
- If the nonce store cannot be read or written, the harness refuses with
  `NONCE_STORE_UNAVAILABLE`. It never skips the check.
- Commands refused before the nonce step (§10 steps 1–12) are not recorded,
  so unauthenticated traffic cannot fill the ledger.
- The nonce ledger blocks byte replay only. Exactly-once effects come from the
  idempotency ledger (create) and terminal operation states (revoke).
  Persisting nonces across a harness restart is SHOULD, not MUST: a replay
  after a restart can only repeat an idempotent outcome.

### 9.3 Time

| Constant | Value |
|---|---|
| Maximum lifetime `expiresAt − issuedAt` | 120 s (Web uses 60 s) |
| Maximum clock skew `MAX_CLOCK_SKEW_SECONDS` | 30 s |
| Admission window (§10 step 12) | `issuedAt − 30 ≤ now < expiresAt + 30`, harness clock |
| `NOT_YET_VALID` | `issuedAt > now + 30` at step 12 |
| `EXPIRED` | `now ≥ expiresAt + 30` at step 12, or, for `profile.create`, at step 14 |
| **Execution deadline** (`profile.create`) | `expiresAt + 30`, on the harness clock, read **after** the ledger lock is acquired (§10 step 14) |
| **Acceptance horizon** of a transmission (a value on Web's clock) | `expiresAt + 60` (§13.2 R3) |

Admission-time expiry and execution-time expiry are separate checks with
separate meanings:

- **Step 12 (admission)** bounds when a copy can be *admitted*. An admitted
  create may then wait an unbounded time for the ledger lock: PR #26 takes an
  in-process mutex and then a blocking file lock, and reads its clock before
  either. Step 12 alone therefore bounds nothing about execution.
- **Step 14 (execution deadline)** bounds when an admitted create can *start*
  executing. No idempotency lookup, ledger read for the key, or provisioning
  write happens at or after `expiresAt + 30` on the harness clock.
- **Neither check bounds when a started execution completes.** A create that
  passed step 14 holds the ledger lock until its outcome is durable, however
  long that takes (§10.4 P2). Expiry is never evidence that a started create
  did not commit.

Web's conclusions (§13.2) rest on the start bound plus serialization, never on
elapsed time alone. Command expiry never tells Web what happened to a copy.

The harness MUST use the same wall clock at steps 12 and 14, and SHOULD
discipline it so that it does not step backwards (slew rather than step). A
backward step larger than `MAX_CLOCK_SKEW_SECONDS` while creates are waiting
for the lock voids the §13.2 R3 guarantee for those creates. This is a
residual risk (§17).

## 10. Verification and execution order

A harness MUST apply these steps in order and answer with the first failing
step's code.

- Steps 1–12 are the protocol layer, which every fixture in `commands-*.json`
  exercises.
- Steps 13–16 run inside Lightagent's provisioning service, reached only after
  the protocol layer passes. Step 14 is a check that r2 adds (§10.4).

Nothing may have a side effect before step 12. No provisioning side effect may
happen before step 14 passes.

| # | Step | Code on failure |
|---|---|---|
| 1 | `POST`, exact `Content-Type`, body ≤ 8192 bytes | `METHOD_NOT_ALLOWED`, `UNSUPPORTED_MEDIA_TYPE`, `PAYLOAD_TOO_LARGE` |
| 2 | UTF-8 and strict JSON (§4.1, §4.2) | `MALFORMED_JSON` |
| 3 | No duplicate member names at any depth | `DUPLICATE_KEY` |
| 4 | Value profile (§4.3), over the whole document | `INVALID_JSON_VALUE` |
| 5 | Top level is an object whose `protocol` member is a string; then the string equals `LA-WEB-PROVISIONING/1` | `INVALID_ENVELOPE`; `UNSUPPORTED_PROTOCOL` |
| 6 | Closed envelope: no unknown member, then no missing member | `UNKNOWN_FIELD`, `MISSING_FIELD` |
| 7 | `purpose` (string, then value); `operation` (string, then v1 set); then the other envelope members in JCS name order (`audience`, `commandId`, `expiresAt`, `issuedAt`, `jobId`, `keyId`, `nonce`, `payload`, `requestId`, `signature`) | `INVALID_FIELD`, `WRONG_PURPOSE`, `UNSUPPORTED_OPERATION`, `INVALID_FIELD` |
| 8 | Closed payload for the operation (unknown, then missing), then payload members in JCS name order; then lifetime | `UNKNOWN_FIELD`, `MISSING_FIELD`, the field's code (§8), `INVALID_LIFETIME` |
| 9 | Body bytes equal `JCS(parsed command)` (§5) | `NON_CANONICAL` |
| 10 | `keyId` is trusted and not revoked (§6.4) | `UNKNOWN_KEY`, `KEY_REVOKED` |
| 11 | `S < L`, and Ed25519 verifies `signature` over `signingInput` (§6) | `BAD_SIGNATURE` |
| 12 | `audience` equals this harness id; time window (§9.3); nonce recorded once (§9.2) | `WRONG_AUDIENCE`; `NOT_YET_VALID`, `EXPIRED`; `REPLAY_DETECTED`, `NONCE_STORE_UNAVAILABLE` |
| 13 | Acquire the provisioning ledger lock (PR #26 `exclusive`: in-process mutex, then the cross-process file lock). The wait is unbounded | — |
| 14 | **Execution deadline** (`profile.create`): while holding the lock, re-read the harness clock. If `now ≥ expiresAt + 30`, refuse with no effect (§10.4 P1) | `EXPIRED` |
| 15 | **Local admission** (§10.2), under the lock | §11 admission codes |
| 16 | Execute through `ProvisioningService` (§10.3), under the lock | §11 payload, merits, operation, conflict and indeterminate codes, or an operation response |

The reference implements steps 1 (size only) to 12 in `verifyCommand`, and
step 14 in `checkExecutionDeadline`. A negative fixture is single-fault: apart
from its one defect, it is canonical and correctly signed, so skipping any
check makes that vector fail.

### 10.2 Local admission (Lightagent PR #26, unchanged)

The harness operator maps each trusted `keyId` to **one local provisioning
credential key id**. This is configuration, never command content. For every
command the gateway builds a `Caller` from that credential through
`CredentialStore::caller_for_at`, and `ProvisioningService::admit` then
re-checks, under the ledger lock, that: the credential is unrevoked,
unexpired and not rotated away; its role is `operator`; its restriction is
**exactly** `{provision}`; the principal is active; and an unrevoked
provisioner registration exists. If the operator revokes that credential, the
next command is refused even with a valid signature. A `keyId` with no
mapping is `UNAUTHENTICATED`.

The signing key reaches no run, session, tool, settings, Jev or
administration route. PR #26 tests this route by route
(`provisioning_boundary.rs`). The gateway is a separate router.

### 10.3 Execution

| Operation | Service call | Extra gateway rule |
|---|---|---|
| `profile.create` | `provision(caller, idempotencyKey, {issuer, subject, profile_id: profileId, display_name: displayName, template})` | none |
| `profile.status` | `status(caller, operationId)` | `operation.profile == payload.profileId`, otherwise `UNKNOWN_OPERATION` |
| `profile.revoke` | `revoke(caller, operationId)` | same |

Lightagent's order inside `provision` is: (lock) → **execution deadline
(r2)** → admit → idempotency-key format → payload validation → credential
profile limit → **idempotency lookup** → `begin` (issuer allowed, template
allowed, quota, ledger capacity, profile id unknown, principal resolution) →
record `pending` → materialize → bind. A `begin` refusal records nothing.
§13.2 depends on this order, and any change to it on the Lightagent side is a
protocol change.

### 10.4 Execution properties a conforming harness MUST provide

| # | Property | PR #26 today |
|---|---|---|
| P1 | **Execution deadline.** For `profile.create`, the check at step 14 runs after the ledger lock is acquired and before the idempotency lookup and any ledger, profile or identity write. It uses a clock value read after acquisition, not the value `provision` reads before locking. A create past its deadline is answered `EXPIRED` **even if its key already has an operation**: the harness neither returns nor resumes that operation, because resuming can write. Web then learns the recorded outcome from a fresh transmission of the same logical command, which returns it (§13.2 R1) | **missing**: `provision` reads `now` before `exclusive()`. Required L3 change: a narrow additive entry point that takes the deadline and checks it inside `exclusive()`. The existing `provision` is unchanged |
| P2 | **Serialization to durability.** Steps 14–16 of every operation run under one lock, held until the call's outcome is durable: a terminal state, a recorded `pending`/`profile_created` followed by an indeterminate error, or a refusal that recorded nothing. Calls on one harness are totally ordered | yes: `exclusive()` holds the mutex and the file lock around the whole `work()` |
| P3 | **Record before effect.** No profile or identity write precedes the durable recording of the operation under `(provisioner, idempotencyKey)`. Every later call's idempotency lookup therefore sees every operation an earlier call started | yes: `begin` records `pending` before `materialize` and `bind` |
| P4 | **Terminal create answers.** A `profile.create` is answered with an operation in a terminal state (`completed`, `failed`, `revoked`) or with an error. An interrupted create is answered with an `indeterminate` code, never with `pending` or `profile_created` | yes: `resume` loops to a terminal state or returns the retryable error |
| P5 | **Status is read-only.** `profile.status` reports the recorded state and current ownership. It never advances, resumes or completes an operation. Recovery of an interrupted create is a resend (§13.3 R4) or an operator `reconcile` | yes: `status` calls only `status_of` |

`profile.status` and `profile.revoke` need no execution deadline. A late
status is a read. A late revoke only removes a binding that Web asked to
remove, and it is idempotent. A harness MAY apply step 14 to them as well.

Web MUST NOT register a harness for v1 provisioning unless it conforms to
P1–P5. Conformance is shown by `execution-deadline.json` and Lightagent's L3
tests, including the lock-wait race. Against a harness without P1, §13.2 R3's
horizon clause is unsound.

## 11. Errors

Codes are uppercase `[A-Z0-9_]{1,64}`, so they fit
`provisioning_jobs.error_code` unchanged. The registry, with HTTP status,
class and applicable operations, is `errors.json`. It is normative.

| Class | Meaning for Web | Codes (HTTP) |
|---|---|---|
| `protocol` | Refused before any side effect (`EXPIRED` at step 12 or step 14). Says nothing about *other* transmissions | `METHOD_NOT_ALLOWED` 405, `UNSUPPORTED_MEDIA_TYPE` 415, `PAYLOAD_TOO_LARGE` 413, `MALFORMED_JSON` `DUPLICATE_KEY` `INVALID_JSON_VALUE` `INVALID_ENVELOPE` `UNSUPPORTED_PROTOCOL` `UNKNOWN_FIELD` `MISSING_FIELD` `WRONG_PURPOSE` `UNSUPPORTED_OPERATION` `INVALID_FIELD` `INVALID_LIFETIME` `NON_CANONICAL` 400, `UNKNOWN_KEY` `KEY_REVOKED` `BAD_SIGNATURE` `NOT_YET_VALID` `EXPIRED` 401, `WRONG_AUDIENCE` 403, `NONCE_STORE_UNAVAILABLE` 503 |
| `payload` | Deterministic in the payload: the same payload can never succeed | `INVALID_PROFILE_ID` `RESERVED_PROFILE_ID` `INVALID_ISSUER` `INVALID_SUBJECT` `INVALID_DISPLAY_NAME` `INVALID_TEMPLATE` `INVALID_IDEMPOTENCY_KEY` `INVALID_OPERATION_ID` 400 |
| `admission` | Local authority refused **before** the idempotency lookup. State-dependent | `UNAUTHENTICATED` 401, `NOT_A_PROVISIONER` `CREDENTIAL_NOT_PROVISIONING_ONLY` `PROVISIONER_INACTIVE` `PROVISIONER_REVOKED` `PROFILE_OUTSIDE_CREDENTIAL` 403 |
| `merits` | create only. Refused **after** the idempotency lookup, so at that moment no operation existed for this key | `ISSUER_NOT_ALLOWED` `TEMPLATE_NOT_ALLOWED` `QUOTA_EXCEEDED` `LEDGER_FULL` 403, `PROFILE_UNAVAILABLE` `PRINCIPAL_INACTIVE` `EXTERNAL_IDENTITY_CONFLICT` 409 |
| `operation` | status/revoke on a known operation id | `UNKNOWN_OPERATION` 404, `OPERATION_IN_PROGRESS` `NOT_REVOCABLE` `OWNERSHIP_CHANGED` 409 |
| `conflict` | Web defect: the same key with a different payload. Never a failure | `IDEMPOTENCY_CONFLICT` 409 |
| `indeterminate` | The command **may have taken effect**. Treated exactly like a timeout | `STORAGE_UNAVAILABLE` `STORAGE_CORRUPT` `IDENTITY_UNAVAILABLE` 503, `INTERNAL_ERROR` 500, `REPLAY_DETECTED` 409 |

`REPLAY_DETECTED` is indeterminate because a network-duplicated copy of the
same transmission may have been the one that executed. `STORAGE_UNAVAILABLE`
can leave a `pending` operation in the ledger (PR #26 §6).

Operation failure codes appear only in `result.failure` of a `failed`
operation: `ISSUER_NOT_TRUSTED`, `PRINCIPAL_INACTIVE`,
`EXTERNAL_IDENTITY_CONFLICT`, `PROFILE_UNAVAILABLE`, `OWNERSHIP_CHANGED`,
`PROVISIONER_REVOKED`, `INVALID_TEMPLATE`. These are the codes PR #26 can
store: `resume` and `bind` record the first five, `reconcile` records
`provisioner_revoked` and `materialize` records `invalid_template`.

`INVALID_TEMPLATE` therefore has two distinct meanings:

- **As a refusal** (`400`, `payload` class), the request's template is not
  `assistant`. A Web signer never produces it.
- **As a failure code**, an operation recorded earlier names a template that
  the current harness build no longer defines, and `materialize` failed it.

The second meaning is an operation outcome. It is not a transport or
signature error: R1 resolves the job as `failed`, `error_code` is
`INVALID_TEMPLATE`, and the profile becomes `failed`. Web MUST NOT
automatically retry with a new key, because the same build would fail it
again. The job needs operator attention.

Lightagent's mapping is mechanical. Each lowercase PR #26 code becomes the
same name in uppercase (`invalid_request` → `MALFORMED_JSON`, `UNKNOWN_FIELD`,
`MISSING_FIELD` or `INVALID_FIELD`, depending on the gateway step that
catches it; `missing_idempotency_key` → `INVALID_IDEMPOTENCY_KEY`). The codes
the gateway adds are listed as `"gateway"` in `errors.json`. No error body
carries a path, subject, issuer, display name, token, key material or stack
trace.

## 12. Responses

### 12.1 Response authentication decision (v1)

**v1 responses are not application-signed.** Their integrity rests on:

1. HTTPS to the administrator-registered endpoint of the specific harness,
   with certificate validation by the Workers runtime, through an approved
   ingress (§12.5). No redirects.
2. **Binding:** every response echoes `protocol`, `commandId`, `audience` and
   `operation`. Results echo `profileId`, and for status and revoke the
   `operationId`. Web rejects any mismatch (§12.4). An answer meant for
   another command, another harness or another profile is never applied.
3. Strict parsing (duplicates, closed schemas, 8 KiB) and internal
   consistency (`failure` ⇔ `failed`; a create answer is terminal). There is
   deliberately **no** rule tying `ownerBound` to `state` (§12.2).
4. Monotonic observation: Web never moves an operation's observed `state`
   backwards (§13.1), so a stale or replayed answer cannot undo a revocation
   that Web has observed.
5. Polling: the observed state is re-read with `profile.status`. No
   unsolicited message is ever trusted.
6. Conservative conclusions: a single answer can make Web conclude `failed`
   only under §13.2 R1–R3. Every `failed` operation that Web knows the id of
   is re-confirmed by status before a suspension is considered complete
   (§13.5).

Threat model:

| Threat | Without response signatures | Residual risk |
|---|---|---|
| Network attacker without a valid certificate | Stopped by TLS | none |
| Answer from another harness, or a cached or misrouted answer | Per-harness endpoint, audience and commandId echo | none |
| Attacker who controls TLS termination in front of the harness (an ingress or tunnel that does not meet §12.5) | Could forge `completed`, `failed` or `revoked`. It could also drop commands, but signed commands cannot be forged | A forged `revoked` would make Web believe a binding was removed when it was not. This is **silent** where dropping is visible |
| **Injected false `failed`**: a forged operation response with `state: failed`, or a forged `merits` or `payload` refusal, for a create that actually completed | (a) **Authenticated HTTPS** (§12.5): without a position inside TLS, nothing can be injected into the Worker's connection. (b) **Strict correlation**: the answer must echo the transmission's fresh random `commandId`, the `audience`, `operation` and `profileId` (and the `operationId` for status), so blind injection, cross-command splicing and cached or misrouted answers are rejected (`RESPONSE_INVALID` → uncertain). (c) **Conservative transitions**: one forged refusal cannot fail a job that still has an uncertain transmission unless it answers a transmission issued after that one's horizon (R3). An uncertain or invalid answer never changes state. A forged `failed` operation is re-checked by `profile.status` when the profile's desired state becomes absent (§13.5) | An on-path attacker inside TLS can forge every answer consistently, including the confirming status. A forged **refusal** carries no `operationId`, so Web cannot re-check it until `profile.lookup` exists (§13.9). The real binding would then persist **silently**: R6 leaves `failed` jobs alone, and a later create for that id is refused `PROFILE_UNAVAILABLE`. As with a forged `revoked`, it grants nothing usable in v1 (rationale below), and the same gate applies |
| Forged `ownerBound` | Same as (a) and (b) | At worst a spurious or missed needs-attention flag. `ownerBound` never moves Web's state (§13.1) |
| Compromised harness | Signing would not help: the harness holds its own key and enforces the binding | Trust in the harness is inherent |

Residual risks of unsigned v1 responses, all accepted for v1 under the gate
below:

- An attacker inside TLS (Cloudflare's edge, a tunnel, or the harness host's
  network) can forge any outcome undetectably, including the confirming
  status.
- A forged `revoked`, or a forged `failed` (or refusal), leaves a real binding
  that Web believes absent.
- A forged `principalId` is stored. It is opaque to Web and never used for
  authorization.
- Forged indeterminate answers only delay resolution, because Web keeps
  reconciling.
- Cloudflare's edge sees the plaintext of every command and response, as it
  does for all of Web's traffic. Commands carry no secrets, and the signature
  protects their integrity.

Rationale: in v1 a provisioned user holds no Lightagent credential.
Provisioning issues none (PR #26 §13.3), and every future user path is
Worker-mediated (AGENT_ACCESS_CONTROL §4.1), so it checks Web state first. A
binding that silently survived a forged `revoked` therefore grants nothing a
user can exercise without separate operator action. Response signatures
would add a harness key, its distribution into `harnesses.public_key`, and
Rust signing code, and would protect only against an intermediary between
TLS termination and the harness.

**Gate:** response signing becomes **required** before any of the following
happens. It would be a new protocol revision, using the context
`"LA-WEB-PROVISIONING/1" 0x00 "provisioning-response" 0x00` (reserved now),
bound to `commandId`, and signed by a harness key held in
`harnesses.public_key`.

- (a) A user can reach a harness by any path that does not pass the Worker
  guard (for example AGENT_ACCESS_CONTROL §4.2 scoped tokens).
- (b) A harness is reached through an ingress that does not meet §12.5, in
  particular TLS termination that the harness operator does not control.
- (c) Provisioning is used across organizations, where the Web operator and
  the harness operator are different parties that do not trust each other's
  infrastructure.

### 12.2 Operation response (`200`, `201`)

Schema `LA-WEB-PROVISIONING/1#response/operation`. Exactly:

```json
{
  "protocol": "LA-WEB-PROVISIONING/1",
  "commandId": "<echo>",
  "audience": "<echo>",
  "operation": "<echo>",
  "replayed": false,
  "result": {
    "operationId": "<32 lowercase hex>",
    "state": "pending | profile_created | completed | failed | revoked",
    "failure": null,
    "principalId": "<Lightagent PrincipalId>",
    "profileId": "<echo of payload.profileId>",
    "template": "assistant",
    "ownerBound": true,
    "createdUnix": 1791000001,
    "updatedUnix": 1791000002
  }
}
```

- `replayed` is present **only** for `profile.create`: `201` with
  `replayed: false` when this transmission created the operation, and `200`
  with `replayed: true` when the key already had one. Status and revoke
  answer `200` without `replayed`.
- `failure` is `null` unless `state` is `failed`, in which case it is an
  operation failure code (§11). A failed operation is an **operation
  response** (`200`/`201`), not an error. This differs from PR #26's HTTP API,
  which answers `409` with the operation, and the gateway maps between them.
- **`profile.create` answers are terminal** (§10.4 P4). The `state` is
  `completed`, `failed` or `revoked`: the service outcome recorded for this
  idempotency key. A create answered with `pending` or `profile_created` is
  `RESPONSE_INVALID`. An interrupted create is answered with an
  `indeterminate` code, and Web resends it (§13.3 R4). **Status polling
  discovers an outcome that is already recorded. It never completes a paused
  create** (P5).
- **`ownerBound` is current ownership, independent of `state`.** It reports
  whether the operation's `principalId` effectively owns `profileId` on the
  harness at the moment of the answer, as PR #26 `status_of` computes it.
  - Every combination of `state` and `ownerBound` is valid on the wire.
    Examples: `completed`/`false` after an operator reassigned the profile;
    `profile_created`/`true` after a crash following the identity commit;
    `failed`/`true` when the same principal owns the id through a later
    operation; `revoked`/`true` after an operator re-assigned it to the same
    principal.
  - `ownerBound: true` does **not** mean that this request created a binding:
    a replayed create reports the recorded outcome with current ownership.
  - Web's handling of each combination is in §13.1. None of them is
    `RESPONSE_INVALID`.
- A revoke response's `state` is always `revoked`, whatever `ownerBound` says.
  Repeating a revoke returns the same answer.
- Integers follow §4.3. `updatedUnix ≥ createdUnix`.

### 12.3 Error response (all other statuses)

Schema `LA-WEB-PROVISIONING/1#response/error`. Exactly
`{ "protocol": "LA-WEB-PROVISIONING/1", "commandId": <echo or null>, "code": "<CODE>" }`.
`commandId` is echoed once the envelope passed §10 step 8, and is `null`
before that. The HTTP status MUST be the one in `errors.json` for the code.

### 12.4 Web's classification

Web classifies each transmission's outcome as exactly one of the following
(reference: `classifyResponse`; fixtures: `responses.json`):

| Outcome | When |
|---|---|
| `operation` | `200`/`201` and every §12.2 rule holds, including all echoes and, for `profile.create`, a terminal `state` |
| `refused` | An error status, a well-formed §12.3 body, `commandId` equal or `null`, a registered code whose HTTP status matches and which applies to this operation, and a class other than `indeterminate` |
| `uncertain` | Everything else: a timeout, a network error, any other status (for example `202` or `3xx`), an HTML error page, an oversized body, any schema or echo mismatch (`RESPONSE_INVALID`), or an indeterminate code |

An `uncertain` outcome never changes Web's view of what exists on the
harness.

### 12.5 Approved HTTPS ingress for unsigned v1 responses (Cloudflare Tunnel)

A harness endpoint qualifies for unsigned v1 responses only if one of these
holds:

- (i) the harness serves HTTPS itself with a publicly trusted certificate
  for the registered hostname; or
- (ii) it is reached through a **Cloudflare Tunnel** that meets **all** of
  T1–T7.

Otherwise response signing is required first (§12.1 gate b).

| # | Requirement |
|---|---|
| T1 | **Operator control.** The harness operator controls the Cloudflare account that owns the tunnel, the public hostname's zone and the Access application. This holds when the Web operator and the harness operator are the same organization in that account. An account controlled by anyone else is an intermediary the harness operator does not control, and does **not** qualify. This includes a hosting provider, or the Web operator fronting a harness someone else operates |
| T2 | **Edge TLS.** The registered `endpoint` is `https://<public hostname>` with a publicly trusted edge certificate and minimum TLS 1.2. The Worker connects with the runtime's default certificate validation. There is no `http://` endpoint outside development |
| T3 | **Origin leg.** `cloudflared` forwards to the gateway over loopback (`http://127.0.0.1:<port>` or a Unix socket) on the harness host. If `cloudflared` runs on another host, it forwards to `https://` with origin certificate verification on (`noTLSVerify: false`, `originServerName` set). `noTLSVerify: true` across hosts is prohibited |
| T4 | **Ingress rules.** One rule matches the hostname and exactly the gateway path (`…/la-web-provisioning/1/commands` under the operator's mount). The final rule is `service: http_status:404`. The Lightagent operator API, run and session routes, and any UI are never reachable through this hostname |
| T5 | **Access policy.** A self-hosted Access application covers the hostname with exactly one Service Auth policy, allowing one service token issued to that Web environment and stored as a Worker secret. There is no Allow or Bypass policy for users, emails, groups or "Everyone", and no identity-provider login. This is transport admission and defence in depth. It is **not** provisioning authority (§10.2), and the harness ignores Access headers |
| T6 | **No browser access.** The gateway sends no CORS headers. The hostname is never placed in the client bundle or any `VITE_*` or `LIGHTAGENT_PUBLIC_*` variable, and Web's CSP `connect-src` stays `'self'`. T5 refuses any browser that tries anyway. Direct browser-to-harness access is prohibited in every configuration, tunnelled or not |
| T7 | **No public listener.** The gateway listens only on loopback, or on a private interface reachable only by `cloudflared`. It is not exposed beside the tunnel |

A tunnel meeting T1–T7 counts as TLS termination controlled by the harness
operator. Cloudflare's edge is then trusted exactly as Web already trusts it
for its own traffic.

## 13. Lifecycle and reconciliation (Web state machine)

### 13.1 Desired and observed state

Web keeps two separate facts:

- **Desired state** (Web-authoritative): whether profile `agt_…` should be
  bound for its owner. It comes from `agent_profiles.status` and
  `user_profiles.status`. The Worker guard enforces it on every Web request
  immediately, whatever the harness says.
- **Observed state** (harness-reported), per create operation:
  - `state`: `unknown` (no operation id yet), or the last `result.state`
    seen. It changes only from an `operation` outcome, and only forward:
    `unknown → pending → profile_created → completed → revoked`, with
    `unknown | pending | profile_created → failed`. A response that would
    move it backwards is an anomaly (`needs attention`) and is never applied.
  - `ownerBound`: the last value seen, with its time. This is **current
    ownership**, not history, so it may change in either direction between
    observations and is not subject to the forward-only rule. It never moves
    `state`, desired state, or D1 status. It only raises or clears a
    needs-attention flag.
  - `operationId`, `principalId`, and the observation time.

Web's assessment of each observation (reference: `assessOwnership`;
fixtures: `responses.json` `ownership`):

| `state` | `ownerBound` | Assessment | Web's response |
|---|---|---|---|
| `completed` | `true` | `bound` | Normal |
| `completed` | `false` | `attention:OWNERSHIP_LOST` | The harness operator changed ownership after completion. Web does **not** re-create (the id cannot be reused, §13.6) and does not try to re-bind. It flags the profile for an operator. **Desired present:** the profile is shown as unavailable until the operator restores ownership on the harness (a later status shows `true` again) or the profile is revoked in Web and the user creates a new one. **Desired absent (suspension, deletion):** R6 still sends `profile.revoke`. `OWNERSHIP_CHANGED` means someone else now owns the profile, so this user holds nothing to remove: the revoke job ends `failed`/`OWNERSHIP_CHANGED` with needs attention, and the user's binding is considered absent. A `revoked` answer means no owner remained, and the job completes |
| `revoked` | `false` | `unbound` | Normal after revocation |
| `revoked` | `true` | `attention:UNEXPECTED_BINDING` | A binding Web did not create exists for a profile it revoked (operator action). Web never re-revokes in a loop, because revoke is idempotent and already terminal. It flags the operator, and desired state stays absent |
| `pending`, `profile_created`, `failed` | `false` | `unbound` | Normal for these states |
| `pending`, `profile_created`, `failed` | `true` | `bound-informational` | `profile_created`/`true` is a create interrupted after the identity commit. R4's resend completes it. `failed`/`true` means the principal owns the id through another operation, which Web tracks through that operation's own job. If desired is absent, R6 covers it |

A Web profile shown as `revoked` means access is withdrawn by Web. It means
"unbound on the harness" only once its revoke job is completed.

### 13.2 Resolving a create (rules R1–R3)

Inputs: every transmission of the job, with its `issuedAt`, `expiresAt` and
§12.4 outcome. Reference: `resolveCreateJob`. Fixtures:
`create-resolution.json`.

- **R1. An operation resolves the job.** If any transmission returned an
  operation, the job is resolved with that `operationId`, in its state,
  including `failed` and `revoked`. Two different operation ids for one job
  are an anomaly.
- **R2. Payload refusals are final.** If any transmission was refused with a
  `payload`-class code, the job is `failed` with that code, because the same
  payload can never succeed.
- **R3. Otherwise, refusals count only when they rule out every uncertain
  transmission.** The job is `failed` only if, for **every** `uncertain`
  transmission `u`, some transmission `t` was refused with a `merits`-class
  code and `t.issuedAt ≥ u.expiresAt + 60` (u's acceptance horizon). If there
  is no uncertain transmission, every transmission was refused before any side
  effect, so nothing exists and the job is `failed` with the latest code.
- Otherwise the job is **unresolved**. `IDEMPOTENCY_CONFLICT` and unknown
  codes are anomalies (`needs attention`), never failures.

Why R3 is stated this way:

- `admission` and `protocol` refusals happen before the idempotency lookup, so
  they say nothing about whether an earlier copy committed. That includes
  `EXPIRED` from step 14.
- A `merits` refusal of `t` happens under the ledger lock and after the
  lookup. It proves that, at the moment `t` held the lock, no operation was
  recorded for the key (P3), and that no other call was executing (P2).
- `u` can no longer *start* after `t`, because of the execution deadline
  (P1). `t` passed admission, so `t` acquired the lock at harness time
  ≥ `t.issuedAt − 30` ≥ `u.expiresAt + 30`, which is `u`'s execution
  deadline. Any later lock acquisition by `u` is refused `EXPIRED` at step
  14, with no effect. The inequality uses only the harness's own clock
  against the Web stamps it checked, so it holds for any Web–harness skew the
  harness accepted.
- If `u` started before `t`, P2 made `t` wait until `u`'s outcome was
  durable, and P3 would then have made `t`'s lookup find `u`'s operation and
  return it instead of refusing.

So R3's conclusion depends on P1–P3 together, not on elapsed time.
**Expiry alone never proves that a started create did not complete**
(`begun-before-deadline-completes-late` in `execution-deadline.json`). An
uncertain transmission stays under reconciliation until R1–R3 apply,
however much time passes (`elapsed-time-alone`, `timeouts-exhausted`).
Without P1, the lock-wait race in `execution-deadline.json` makes R3 unsound
(`unsafe: true`). With P1 it is safe. The workerd contract test checks this
on 20,000 random serialized schedules, with skew within ±30 s, lock waits,
slow commits, lost answers, and crashes after recording.

**Consequences:** exhausted retries never produce `failed`
(`timeouts-exhausted`). A timeout followed by a quick `QUOTA_EXCEEDED` stays
unresolved (`timeout-then-merits-too-early`).

### 13.3 Driving an unresolved create (rule R4)

- **R4.** While a create is unresolved, Web resends the **same logical
  command** (§9.1) with backoff, for example 10 s, 30 s, 2 min, then every
  15 min, until R1–R3 resolve it. If the user was suspended in the meantime,
  Web still resends, learns the operation id, and then revokes it (§13.5).
  Resending is safe: under the same key, Lightagent returns the existing
  operation and never creates a second one (S1, idempotency).
- After about 10 transmissions without resolution, Web marks the job
  `needs attention` for an operator, but **keeps** it unresolved and keeps
  reconciling at the slow cadence. It never marks it failed.
- **Create answers are final service outcomes** (§12.2, P4). There is
  nothing to poll after a create answer. Web uses `profile.status` only to
  confirm a known operation: to refresh `ownerBound` (§13.1), for R6
  confirmation (§13.5), and for revoke follow-up (§13.4).
- If `profile.status` reports `pending` or `profile_created` for a known
  operation, the create was interrupted, for example by a crash after Web
  received an indeterminate answer. Status does not advance it (P5). Web
  resends the **create** under R4, which resumes the recorded operation, or
  waits for the operator's `reconcile`. If Web had already observed a
  terminal state, the regression is an anomaly (§13.1).
- A new create job for the same `agt_` id, with a **new** idempotency key, is
  allowed only after that id's previous create resolved as `failed` (by R1
  with state `failed`, R2 or R3). It is never allowed after `revoked`, and
  never while a job is unresolved (S6).

### 13.4 Revoke (rule R5)

Revoke jobs need the create's `operationId`. If the create is unresolved, R4
runs first.

| Outcome | Web revoke job | Observed |
|---|---|---|
| operation `revoked` | `completed` | `revoked` |
| `NOT_REVOCABLE` | `completed`. Confirm with status that the operation is `failed` (nothing was bound) | `failed` |
| `OPERATION_IN_PROGRESS` | stays open. The create is interrupted. Resend the create (R4) to drive it to a terminal state, then revoke | unchanged |
| `OWNERSHIP_CHANGED` | `failed` with `OWNERSHIP_CHANGED`, plus needs attention (the operator reassigned the profile; Web cannot revoke it) | unchanged |
| `UNKNOWN_OPERATION` | needs attention. Never treated as revoked | unchanged |
| `uncertain` | resend the same logical command (revoke is idempotent) | unchanged |

### 13.5 Suspension, cancellation and revocation (rule R6)

- **R6.** When a profile's desired state becomes "absent" (the user deletes or
  revokes it, the account is suspended or disabled, or a create is cancelled),
  Web MUST durably record that intent in the same D1 transaction as the status
  change. A reconciler then drives it to completion: it revokes every
  `completed` operation, applies R4 to every unresolved create and then
  revokes the result, and leaves `failed` operations alone.
- The reconciler is **level-triggered**: it periodically selects every profile
  whose desired state is absent and whose create is not yet settled: either
  observed `completed` without a completed revoke, or still unresolved
  (§13.2). A lost event therefore cannot leave a binding behind.
- **Confirmation.** Before a suspension or deletion counts as complete, Web
  re-reads with `profile.status` every operation of that user that it
  observed as `failed`.
  - `ownerBound: true` on a `failed` operation, or on a `revoked` one, raises
    needs attention.
  - `failed` operations cannot be revoked (`NOT_REVOCABLE`), so only the
    harness operator can remove such a binding.
  - Creates that ended `failed` through a refusal (R2/R3) have no operation
    id and cannot be confirmed in v1 (§12.1 residual risk, §13.9).
- **Ownership already lost.** A `completed` operation with `ownerBound:
  false` is still revoked under R6. §13.1 describes the outcome.
- Because harness revocation is irreversible, suspending a user ends their
  existing harness bindings permanently. Reactivation creates **new** `agt_`
  profiles. The old data stays with the harness operator (Lightagent §8).

### 13.6 Profile identifiers

Web never assigns an `agt_` id to a second Web profile, never re-creates a
revoked one, and never re-creates one while a create for it is unresolved.
Lightagent refuses a revoked or known id with a new key
(`PROFILE_UNAVAILABLE`, S2), and with the same key returns the recorded
(revoked) operation (S1). Both sides therefore refuse reuse independently.

### 13.7 Mapping to D1 (existing schema)

| Observation | `provisioning_jobs.status` | `agent_profiles.status` |
|---|---|---|
| no transmission yet | `pending` | `provisioning` |
| transmission in flight, or last outcome uncertain or refused while unresolved | `sending`, or back to `pending` awaiting the next transmission (each new transmission enters `sending` again) | `provisioning` |
| status shows `pending` or `profile_created` (an interrupted create; create answers are terminal) | `accepted`, then R4 resend | `provisioning` |
| operation `completed` | `completed` | `active`. A later `ownerBound: false` does not change D1 status. It sets needs attention (§13.1) |
| operation `failed` (R1), including `INVALID_TEMPLATE`, or R2/R3 failure | `failed`, `error_code` = the failure or refusal code | `failed` |
| create resolves as `revoked` (only after lost Web records) | `completed` + needs attention | → `revoked` (needs the transition noted in §16.1) |
| revoke job outcomes | §13.4 | `revoked` (set when the intent was recorded, §13.5) |
| anomaly | unchanged + needs attention | unchanged |

An HTTP `200` or `201` alone never means `completed`. Only `result.state`
does (C10).

### 13.8 Stale, delayed and reordered commands

| # | Scenario | Outcome |
|---|---|---|
| S1 | A create redelivered with the same key after its operation was revoked | Returns `revoked`, does not bind again |
| S2 | A create for a revoked or known id with a new key | `PROFILE_UNAVAILABLE` |
| S3 | A revoke racing a create in progress | `OPERATION_IN_PROGRESS`. Calls are serialized by the ledger lock |
| S4 | A revoke before its create | Impossible: a revoke names an operation id, which only a create returns |
| S5 | A create's outcome is unknown and Web gives up | Not allowed: R3 and R4 |
| S6 | A new key for the same profile after an unknown outcome | Not allowed: §13.3 |
| S7 | The user is suspended while a create is in flight | R6 revokes the eventual operation |
| S8 | The operator reassigns or suspends locally | `OWNERSHIP_CHANGED` or `PRINCIPAL_INACTIVE`. Web does not override the operator |
| S9 | A command captured for another harness | `WRONG_AUDIENCE` (fixtures `cross-harness-*`) |
| S10 | A byte-identical replay within the window | `REPLAY_DETECTED`. Outside the window: `EXPIRED` |
| S11 | A delayed create arrives after its revoke | Same key, so S1 applies. A revoke is terminal, so no command can restore access |

A delayed or reordered command therefore cannot restore access after
revocation, and duplicate commands cannot create duplicate bindings
(idempotency, profile-id uniqueness and one in-flight job per profile and
operation in D1). This holds without a revocation-version counter. A
counter would only be needed for reversible operations such as
`disable`/`enable`, which v1 excludes. If they are added later, a counter
must be reconsidered.

### 13.9 Optional: read-only lookup by idempotency key (evaluated, deferred)

A `profile.lookup { idempotencyKey, profileId }` operation would return the
operation recorded for `(provisioner, idempotencyKey)`, or
`UNKNOWN_OPERATION`. It would pass the same §10 and §10.2 admission, would be
scoped to the caller's provisioner exactly like `status`, would have no side
effect and no ledger write, and would need one read-only method in
`ProvisioningService`, not a second ledger or authority. Its only benefit is
for R6 after a suspension: Web could learn that nothing was created without
resending a create that then has to be revoked. A "not found" answer would
still be final only under the R3 horizon rule.

Decision for r1 and r2: **not included.** R4 is sufficient for safety. In v1 a
binding created and then revoked within minutes grants nothing usable
(§12.1). In v1, `profile.lookup` is `UNSUPPORTED_OPERATION` (fixture
`unsupported-profile-lookup`). Either side may propose it for a later
revision with these semantics.

## 14. Lightagent audit items C1–C10

| # | Audit item | Resolution in this revision |
|---|---|---|
| C1 | Callbacks | None. Polling with `profile.status` only (§1, §13.3). No callback field exists. `callbackUrl` is `UNKNOWN_FIELD` |
| C2 | Disable / enable | Not v1. `UNSUPPORTED_OPERATION` (fixtures `forbidden-profile-disable`, `forbidden-profile-enable`). The D1 CHECK keeps the values, and Web never sends them |
| C3 | Revoke | By `operationId` with a `profileId` consistency check (§8.2). Terminal and idempotent (§12.2) |
| C4 | Display name | 1–64 Unicode scalar values, NFC, no Cc, no leading or trailing White_Space (§8.1). Web validates before signing. Fixtures cover 65, 81, 65 astral and 64 astral |
| C5 | Revocation version | Not in v1. Rules R1–R6 and §13.8. `revocationVersion` is `UNKNOWN_FIELD` |
| C6 | Subject | `payload.subject` = `user_profiles.id` (`usr_…`), immutable. The issuer is Web's configured https origin identifier. Lightagent derives its own principal |
| C7 | Authority | Signature (§6) then local admission (§10.2). Every `keyId` maps to one `{provision}`-only credential |
| C8 | Permissions | Closed payloads. Only `template: "assistant"`. Forbidden fields are listed in §8.4 and covered by fixtures |
| C9 | Encodings | One encoding per field (§4.4). Standard base64 or hex for signatures and nonces is `INVALID_FIELD` |
| C10 | State mapping | §12.4, §13.7. HTTP status alone never means completion. A failed operation is an operation response with `state: failed`. A create answer is terminal (P4). `ownerBound` is current ownership and independent of `state` (§12.2, §13.1) |

## 15. Fixtures, manifest and acceptance

| File | Content |
|---|---|
| `keys.json` | Four TEST-ONLY Ed25519 keys (`active`, `rotated`, `revoked`, `untrusted`) derived as `seed = SHA-256(label)`; three named verifier states (`overlap`, `afterRotation`, `harnessB`); constants |
| `commands-valid.json` | Valid commands, each with the command object, canonical JSON, `signingInputHex`, signature, `payloadHash` and the exact body |
| `commands-invalid.json` | Single-fault negative vectors with the expected code and HTTP status |
| `redelivery.json` | Create and revoke transmission series, including one across a key rotation, a replay, and a "not a redelivery" counter-example |
| `responses.json` | Response bodies and Web's expected classification |
| `create-resolution.json` | R1–R3 decision cases, including the horizon boundary (±1 s), `EXPIRED` at execution, and elapsed time alone |
| `execution-deadline.json` | §10 step 14: single deadline checks (including admitted-in-time, locked-too-late), and harness race scenarios (lock-wait race, late completion, crash after record, delayed admission, merits before horizon), each evaluated with and without step 14 |
| `errors.json` | The normative error registry |
| `MANIFEST.json` | Protocol, revision, schema ids, fixture ids, specification and file SHA-256 hashes, `fixtureDigest` |
| `MANIFEST.sha256` | The same hashes in `sha256sum -c` format (run it from the Web repository root) |

- `fixtureDigest` = SHA-256 of the lines `"<sha256>  <path>\n"` for every
  fixture file, sorted by path.
- **Compatibility digest** = SHA-256 of the exact bytes of `MANIFEST.json`.
  It covers this document, every fixture and every schema id. Both
  repositories pin this value.
- **Provenance without circularity.** The hashed contents are this document
  and the fixture files. `MANIFEST.json` hashes them, and the digest hashes
  `MANIFEST.json`. `ACCEPTANCE.md` (review metadata: digest, commit,
  reviewer) is outside the manifest. A candidate is published in two commits
  on a Web review branch:
  1. the **candidate commit** holds every hashed file, the manifest, the
     generator and the tests;
  2. a **metadata commit** names the candidate commit's SHA and the digest in
     `ACCEPTANCE.md`.

  The second commit changes no hashed byte, so the digest is identical at
  both commits. Reviewers verify the candidate commit's bytes.
- The generator is deterministic (`npm run protocol:fixtures -- write|check`).
  `tests/static/provisioning-fixtures.test.ts` fails if any committed byte
  differs from a regeneration or from the manifest.
  `tests/contracts/provisioning-protocol.test.ts` runs every vector inside
  workerd.
- `.gitattributes` marks these files `-text`, so checkouts on any platform
  keep the hashed bytes.
- A verifier passes the fixtures when every `commands-*` and `redelivery`
  vector gives exactly its `expect`, and every `execution-deadline.json`
  `deadlineCases` entry gives its `expect`. A Web implementation additionally
  passes `responses.json` and `create-resolution.json`. A harness's L3 tests
  reproduce the lock-wait race against the real service: one create blocked
  on the lock past its deadline while another call holds it MUST answer
  `EXPIRED` and record nothing.

## 16. Required follow-up work (not part of L0)

### 16.1 Web

1. Production codec under `src/worker/provisioning/`, ported from the
   reference and tested against these fixtures (L0 adds no production code).
2. Signing key: a per-environment Cloudflare secret (for example
   `PROVISIONING_SIGNING_KEY`, a 32-byte seed in base64url) read through
   `readSecret`, plus a non-secret `keyId` variable. Extend the bundle secret
   scan to the new names. Production stays empty until approved.
3. `PROVISIONING_ISSUER`, a non-secret https origin identifier, explicit per
   environment. Development needs an `https://` identifier even though
   `PUBLIC_ORIGIN` is `http://localhost:5173`.
4. A new migration (0003 or later). Never edit 0001 or 0002. It adds a
   transmissions record per job (`command_id`, nonce hash, `key_id`,
   `issued_at`, `expires_at`, outcome, code), which R3 needs, and job columns
   `operation_id`, `principal_id`, `observed_state`, `observed_at`,
   `needs_attention` and `next_attempt_at`. It decouples reconciliation from
   the `attempt_count ≤ 10` CHECK, which must stop counting reconciliation
   attempts or stop gating `failed`. It also adds a profile path for
   suspension, so that once a harness binding is revoked a profile can no
   longer return to `active`, either through `suspended → revoked` or by
   moving profiles to `revoked` on suspension.
5. Display-name check at profile creation and rename (or at least before
   signing): `agent_name` allows 1–80 UTF-16 units, but provisioning needs
   §8.1.
6. `PROVISIONING_OPERATIONS` and `HarnessCapabilitiesSchema` still list
   `profile.disable` and `profile.enable` and cannot express
   `profile.status`. The sender must be restricted to the v1 set.
7. A level-triggered reconciler (Cron Trigger plus `scheduled` handler) for
   R4–R6 and nonce purging.
8. Transport through `fetchWithTimeout` (10 s, `redirect: "manual"`, 8 KiB
   read limit), and response classification exactly as `classifyResponse`.
9. Where a harness sits behind a Cloudflare Tunnel (§12.5), a per-environment
   Access service token as Worker secrets (`CF-Access-Client-Id`/`-Secret`),
   sent only to that harness's endpoint. It is never a provisioning
   credential.
10. Observed `ownerBound` with its time, the needs-attention flags of §13.1,
    and the R6 confirmation step of §13.5.

### 16.2 Lightagent (adapter only, PR #26 service unchanged)

1. A gateway route `POST {mount}/la-web-provisioning/1/commands` in a separate
   `Router` behind a cargo feature, off by default, never merged into
   `router()` without opt-in.
2. A strict parser (§4.2: duplicates, lexemes, depth), the value profile,
   closed schemas, NFC checking with the ICU4X `icu_normalizer` already in the
   dependency graph (no new crate), JCS of the §4.3 subset, and the canonical
   byte comparison. PR #28's conformance crate already implements these
   offline.
3. Ed25519 through `ring`, with an explicit `S < L` check.
4. Fail-closed configuration: own `harnessId`, the trusted-key list,
   `keyId` → local credential key id (all mapping to one provisioner).
5. A nonce ledger (§9.2) checked and recorded before admission.
6. The §10.3 adapter: `caller_for_at` with the mapped credential, the
   `profileId` consistency check for status and revoke, uppercase code
   mapping, failed operations as `200`/`201` operation responses, and echoes.
7. Regression tests for S1 and S2 (added as `web_*` tests in PR #28).
8. A mirror of the specification and fixtures, with a CI job that runs every
   vector and checks `MANIFEST.sha256`.
9. **§10.4 P1 (L3, required):** a narrow, additive `ProvisioningService` entry
   point for the gateway's creates. It reads the clock **inside**
   `exclusive()`, refuses `EXPIRED` when `now ≥ deadline` before admission,
   the idempotency lookup and any write, and is otherwise `provision`. The
   existing `provision` and its HTTP API stay unchanged. Tests: a create
   blocked on the lock past its deadline records nothing; a create admitted
   in time completes even if its commit finishes after the deadline (P2).

## 17. Open points and residual risks

Resolved in r2 by Lightagent's review (PR #28):

- **NFC**: kept, with `icu_normalizer` (§4.6).
- **Retrying a failed create on the same id**: confirmed by the PR #28 test
  `web_a_failed_create_leaves_its_profile_id_available_to_a_new_key` (§13.3).

Still open:

1. **`profile.lookup`** (§13.9) is deferred, not rejected. It would also
   close the "forged refusal cannot be re-checked" residual risk (§12.1).
2. **Response signing** is gated, not dropped (§12.1 gates a–c).
3. **Clock discipline**: a backward clock step larger than 30 s on the
   harness, while creates wait for the lock, voids R3 for them (§9.3).
4. **Unsigned responses**: the residual risks listed in §12.1 are accepted
   for v1 only within the §12.5 ingress definition.
5. **Harness reachability** (direct HTTPS or a §12.5 tunnel) is a deployment
   choice per harness. It is recorded in that harness's registration review.

## 18. Revision history

### r2 (this revision)

Resolves Lightagent's review of r1 (PR #28,
`docs/integrations/web/l0-protocol-review.md`, reviewed digest
`030537b8…a1d2`). Wire format, signing, canonical form, keys and the command
schemas are unchanged, so every r1 command vector is unchanged in r2.

| Finding | Change |
|---|---|
| RC1 execution deadline | §9.3 separates admission-time from execution-time expiry. New §10 steps 13–14 and §10.4 P1–P5. §13.2 R3 now rests on P1–P3 and never on elapsed time. `EXPIRED` note in `errors.json`. New `execution-deadline.json`. New resolution cases `lock-wait-horizon-*`, `expired-at-execution-*` and `elapsed-time-alone`. Randomized schedule test |
| RC2 `ownerBound` | §12.2: current ownership, independent of `state`. The `ownerBound ⇔ completed` check is removed from the reference classifier. New §13.1 assessment table and §13.5 behaviour. Response vectors for `completed`/`false`, `profile_created`/`true`, `failed`/`true` and `revoked`/`true`. The r1 vector `invalid-owner-bound-pending` is replaced |
| RC3 `INVALID_TEMPLATE` | Added to the operation failure codes, matching PR #26 `materialize`. Its two meanings are set out in §11. New response vector `create-200-failed-invalid-template` |
| RC4 provenance | §15 two-commit procedure. The candidate is committed on a Web review branch, and `ACCEPTANCE.md` names the commit |
| CL1 | §12.2, §10.4 P4/P5, §13.3: create answers are terminal, status never completes a create, and a non-terminal create answer is `RESPONSE_INVALID` (vectors `invalid-create-nonterminal-*`). The r1 vector `create-200-replayed-pending` is replaced by `create-200-replayed-completed` |
| CL2 | §12.1 threat model: an injected false `failed`, its mitigations and residual risks |
| CL3 | §12.5 Cloudflare Tunnel requirements T1–T7. §3 allows only Access service-token headers. Gate (b) refers to §12.5 |
| CL4 | §4.6 Unicode data versions and `icu_normalizer` |

### r1

First candidate (digest `030537b8be8cc003cff31e503343d5082629eab3f3f10c82fb17d7776b24a1d2`).
Rejected by Lightagent in PR #28 pending RC1–RC4.
