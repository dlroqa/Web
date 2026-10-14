# LA-WEB-PROVISIONING/1: provisioning protocol

| | |
|---|---|
| Protocol identifier | `LA-WEB-PROVISIONING/1` |
| Revision | `la-web-provisioning-1/r4` (changes: §18) |
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

- **Recording.** At step 12 the harness records the command's nonce
  atomically (insert-if-absent) across every gateway process of the harness
  (§13.2 A1). The record MUST be durable before the command proceeds to step
  13 and before any answer for it is released. A nonce already present is
  `REPLAY_DETECTED`.
- **Durability (r3: MUST).** Nonce records MUST survive harness restarts and
  crashes. In r2 this was SHOULD, on the grounds that a replay can only repeat
  an idempotent outcome. That is false for a command that was *refused*: a
  duplicated copy arriving after a restart can succeed where the original was
  refused, after Web concluded the job `failed` (§13.2.2,
  `duplicate-of-refused-command-after-restart`).
- **Retention (r3).** A record is discarded only once the execution fence
  excludes its command: `fence ≥ expiresAt + 30` (§10.5). To discard records
  whose commands have expired (`now ≥ expiresAt + 30` on the harness clock),
  the harness first raises the fence to at least `expiresAt + 30`, durably and
  under the ledger lock, and only then discards them. A record is **never**
  discarded by wall clock alone. If the clock later steps back, a copy whose
  record was discarded would otherwise pass step 12
  (`duplicate-after-clock-purge-and-rollback`).
- Nonces are scoped to the harness: one ledger across all keys and all
  operations. The same rules apply to status and revoke nonces.
- If the nonce store cannot be read or written, the harness refuses with
  `NONCE_STORE_UNAVAILABLE`. It never skips the check.
- Commands refused before the nonce is recorded (§10 steps 1–11, and the
  audience and time checks of step 12) are not recorded. This keeps
  unauthenticated traffic out of the ledger. Such refusals are therefore
  *transmission-only* for Web (§11, §13.2): another copy of the same bytes may
  pass later.
- The nonce ledger blocks byte replay. Exactly-once effects come from the
  idempotency ledger (create) and terminal operation states (revoke).

### 9.3 Time

| Constant | Value |
|---|---|
| Maximum lifetime `expiresAt − issuedAt` | 120 s (Web uses 60 s) |
| Maximum clock skew `MAX_CLOCK_SKEW_SECONDS` | 30 s |
| Admission window (§10 step 12) | `issuedAt − 30 ≤ now < expiresAt + 30`, harness clock |
| `NOT_YET_VALID` | `issuedAt > now + 30` at step 12 |
| `EXPIRED` | `now ≥ expiresAt + 30` at step 12, or, for `profile.create`, at step 14 |
| **Execution deadline** (`profile.create`) | `expiresAt + 30`, compared after the ledger lock is acquired (§10 step 14) with **both** the harness clock read then **and** the durable execution fence (§10.5) |
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

The harness uses its wall clock for the admission window (step 12) and for
the wall-clock half of step 14. **Neither is needed for the safety of §13.2.**
A clock that is wrong, or that steps in either direction (NTP or chrony step
corrections, VM snapshot restore or migration, manual changes), can only do
two things:

- cause extra `EXPIRED` or `NOT_YET_VALID` answers, which fail closed;
- let a stale command reach step 14, where the durable execution fence
  (§10.5) refuses it.

r2's "backward step larger than 30 s" caveat is wrong: a 1 s step was enough
(Lightagent PR #28 RC5, `backward-step-while-waiting`). r3 removes the caveat
by adding the fence. The harness SHOULD still slew its clock rather than step
it, for liveness.

## 10. Verification and execution order

A harness MUST apply these steps in order and answer with the first failing
step's code.

- Steps 1–12 are the protocol layer, which every fixture in `commands-*.json`
  exercises.
- Steps 13–16 run inside Lightagent's provisioning service, reached only after
  the protocol layer passes. Step 14 was added in r2 and extended with the
  execution fence in r3 (§10.4, §10.5).

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
| 13 | Acquire the provisioning ledger lock (PR #26 `exclusive`: in-process mutex, then the cross-process file lock). The wait is unbounded. Then re-check the ledger's harness-id stamp and retirement (§10.6 C1, r4). While the start-up continuity check fails, the gateway answers every request with this code before step 1, with `commandId` null | `LEDGER_CONTINUITY_FAILED` |
| 14 | **Execution deadline** (`profile.create`): while holding the lock, read the durable fence `F` and re-read the harness clock. Refuse with no effect if `now ≥ expiresAt + 30` **or** `expiresAt + 30 ≤ F` (§10.4 P1, §10.5) | `EXPIRED` |
| 15 | **Local admission** (§10.2), under the lock. For `profile.create`, on success set `F := max(F, issuedAt − 30)`, durable before the lock is released (§10.5) | §11 admission codes |
| 16 | Execute through `ProvisioningService` (§10.3), under the lock | §11 payload, merits, operation, conflict and indeterminate codes, or an operation response |

The reference implements steps 1 (size only) to 12 in `verifyCommand`, step
14 in `checkExecutionDeadline`, and the step-15 fence advance in
`advanceFence`. `simulateOrdering` models steps 12–16 across processes,
clocks and restarts. A negative fixture is single-fault: apart
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

**Where each authentication decision is made (r4 clarification).** This
order fixes which refusals are `final` (§11):

| Step | Decision | Refusal | `createResolution` |
|---|---|---|---|
| 10 | `keyId` is in the harness's trusted-key list and is not revoked. A key revocation takes effect here, before any credential lookup | `UNKNOWN_KEY`, `KEY_REVOKED` | transmission-only |
| 11 | Ed25519 signature over the signing input, with `S < L` | `BAD_SIGNATURE` | transmission-only |
| 12 | Audience, time window, then the nonce recorded durably (§9.2) | `WRONG_AUDIENCE`, `NOT_YET_VALID`, `EXPIRED`, `REPLAY_DETECTED`, `NONCE_STORE_UNAVAILABLE` | transmission-only, or indeterminate for `REPLAY_DETECTED` |
| 13–14 | Lock, execution deadline and fence (§10.5), and the ledger continuity stamp (§10.6 C1) | `EXPIRED`, `LEDGER_CONTINUITY_FAILED` | transmission-only |
| 15 | **Only now** resolve the `keyId` → local provisioning credential mapping, build the `Caller` with `caller_for_at`, and run `admit` | `UNAUTHENTICATED`, `NOT_A_PROVISIONER`, `CREDENTIAL_NOT_PROVISIONING_ONLY`, `PROVISIONER_INACTIVE`, `PROVISIONER_REVOKED`, `PROFILE_OUTSIDE_CREDENTIAL` | final |
| 16 | Issuer and template authorization, quota and profile checks (`begin`), and operation scope for status and revoke | `ISSUER_NOT_ALLOWED`, … (merits), `UNKNOWN_OPERATION` | final / operation |

- The mapping MUST NOT be resolved, and `UNAUTHENTICATED` MUST NOT be
  answered, before the nonce is durably recorded. Resolving it at step 10
  would turn a missing or revoked mapping into a pre-nonce refusal labelled
  `final`, which a later copy could contradict.
- Resolving the mapping late bypasses nothing:
  - steps 10–12 still verify the trusted key, its revocation, the signature,
    the audience, freshness and the replay record first;
  - a signature without a mapping still grants nothing;
  - issuer authorization and operation scope remain PR #26's checks at
    steps 15–16.

The signing key reaches no run, session, tool, settings, Jev or
administration route. PR #26 tests this route by route
(`provisioning_boundary.rs`). The gateway is a separate router.

### 10.3 Execution

| Operation | Service call | Extra gateway rule |
|---|---|---|
| `profile.create` | `provision(caller, idempotencyKey, {issuer, subject, profile_id: profileId, display_name: displayName, template})` | none |
| `profile.status` | `status(caller, operationId)` | `operation.profile == payload.profileId`, otherwise `UNKNOWN_OPERATION` |
| `profile.revoke` | `revoke(caller, operationId)` | same |

Lightagent's order inside `provision` is: (lock) → **execution deadline and
fence check** → admit → **fence advance (r3)** → idempotency-key format → payload validation → credential
profile limit → **idempotency lookup** → `begin` (issuer allowed, template
allowed, quota, ledger capacity, profile id unknown, principal resolution) →
record `pending` → materialize → bind. In r3, the fence is checked with the
execution deadline, and advanced durably right after admit. A `begin` refusal
records nothing in the operation ledger. The fence is not an operation and is
not keyed.
§13.2 depends on this order, and any change to it on the Lightagent side is a
protocol change.

### 10.4 Execution properties a conforming harness MUST provide

| # | Property | PR #26 today |
|---|---|---|
| P1 | **Execution deadline.** For `profile.create`, the check at step 14 (wall clock **and** fence, §10.5) runs after the ledger lock is acquired and before the idempotency lookup and any ledger, profile or identity write. It uses a clock value read after acquisition, not the value `provision` reads before locking, and the fence value read from durable state after acquisition. A create past its deadline is answered `EXPIRED` **even if its key already has an operation**: the harness neither returns nor resumes that operation, because resuming can write. Web then learns the recorded outcome from a fresh transmission of the same logical command, which returns it (§13.2 R1) | **missing**: `provision` reads `now` before `exclusive()`. Required L3 change: a narrow additive entry point that takes the deadline and checks it inside `exclusive()`. The existing `provision` is unchanged |
| P2 | **Serialization to durability.** Steps 14–16 of every operation run under one lock, held until the call's outcome is durable: a terminal state, a recorded `pending`/`profile_created` followed by an indeterminate error, or a refusal that recorded nothing. Calls on one harness are totally ordered | yes: `exclusive()` holds the mutex and the file lock around the whole `work()` |
| P3 | **Record before effect.** No profile or identity write precedes the durable recording of the operation under `(provisioner, idempotencyKey)`. Every later call's idempotency lookup therefore sees every operation an earlier call started | yes: `begin` records `pending` before `materialize` and `bind` |
| P4 | **Terminal create answers.** A `profile.create` is answered with an operation in a terminal state (`completed`, `failed`, `revoked`) or with an error. An interrupted create is answered with an `indeterminate` code, never with `pending` or `profile_created` | yes: `resume` loops to a terminal state or returns the retryable error |
| P5 | **Status is read-only.** `profile.status` reports the recorded state and current ownership. It never advances, resumes or completes an operation. Recovery of an interrupted create is a resend (§13.3 R4) or an operator `reconcile` | yes: `status` calls only `status_of` |
| P6 | **Execution fence (r3).** One durable, non-decreasing fence per harness ledger, checked at step 14 and advanced after step 15 for every admitted create, with the advance durable before the ledger lock is released (§10.5) | **missing**: one integer in the ledger state, in the same L3 entry point as P1 |
| P7 | **Durable nonces (r3).** Nonce records are atomic across gateway processes, durable before the command proceeds or is answered, survive restarts, and are discarded only once the fence excludes them (§9.2) | not applicable: the nonce ledger is new in the L2 gateway |
| P8 | **Ledger continuity (r4).** The gateway serves only a ledger that an operator explicitly initialized for this harness id, and that passes the §10.6 C1–C3 check at start and activation. C1 is also checked under the lock for every command. Otherwise every command is answered `LEDGER_CONTINUITY_FAILED` | **missing**: PR #26 creates its ledger lazily and records no harness id. Required L1 change (§16.2) |

`profile.status` and `profile.revoke` need no execution deadline. A late
status is a read. A late revoke only removes a binding that Web asked to
remove, and it is idempotent. A harness MAY apply step 14 to them as well.

Web MUST NOT register a harness for v1 provisioning unless it conforms to
P1–P8. Conformance is shown by:

- `execution-deadline.json`, including the fence cases;
- `ordering-model.json`;
- Lightagent's L3 tests, including the lock-wait race with a clock step, and
  a duplicate of a refused command across a restart.

- `ledger-continuity.json`.

Against a harness without P1, P6, P7 or P8, §13.2 R3 is unsound
(§13.2.2).

### 10.5 Execution fence (RC5)

| Aspect | Rule |
|---|---|
| Identity and scope | **One fence per harness id**, which is one provisioning ledger (§13.2 A1): the integer `execution_fence`, in Unix seconds, starting at `0`, stored in the provisioning ledger's state. It is not keyed by profile, idempotency key, issuer, signing key, controller or provisioner (see "Why harness scope" below) |
| Durability | Written with the ledger's durable write (temporary file, `fsync`, rename, directory `fsync`, as PR #26 `write_durable`). It never decreases: no code path lowers it |
| Check (step 14) | Under the ledger lock, read `F` from durable state (never a cached value from an earlier call or another process). Refuse `EXPIRED` with no effect if `expiresAt + 30 ≤ F`. Also refuse if `now ≥ expiresAt + 30`. Equality refuses: fixture `fence-equals-deadline`, with `fence-one-below-deadline` proceeding |
| Advance (after step 15) | For every `profile.create` that passes local admission, set `F := max(F, issuedAt − 30)`. The new value MUST be durable **before the ledger lock is released**, and so before any answer. Implementations SHOULD write it before the idempotency lookup. The review's wording, "durable before the answer is released", is not enough: a second process can take the lock between unlock and the write and read the old fence (`fence-visible-only-after-unlock`) |
| Order under the lock | acquire lock → read `F` → step 14 (clock and fence) → step 15 admission → advance and persist `F` → idempotency lookup, `begin`, record, materialize, bind → release lock |
| Status, revoke | They do not advance the fence. They MAY apply the step-14 checks |
| Crash | If the process dies before the advance is durable, that create's answer was never released, so Web holds it as uncertain and relies on nothing. If it dies after, the durable value stands |
| Restore (r4, corrected) | A restore brings back the provisioning ledger (operations, idempotency keys, fence, harness-id stamp), the nonce store, the identity store and the profile store **together, from one mutually consistent recovery point** (A9, §10.6). It then sets `F := max(F_restored, T + 150)` before serving, where `T` is an operator-verified current time: this excludes every command issued before `T`, because `expiresAt + 30 ≤ T + 150`, and Web's commands in the next 60–120 s are refused `EXPIRED` and retried. A partial restore of only the nonce store or only the fence is not a sanctioned procedure (A9); if one happens anyway, the raise still excludes every earlier command (`nonces-restored-alone`, `fence-restored-alone`). **A harness id's ledger is never initialized anew, and never restored alone, while identity or profile state survives** (`fresh-ledger-retained-identity`). If the ledger cannot be restored consistently, the harness id is retired (§10.6). r3 permitted "initializing a new ledger for an existing harness id" with only the fence raise. That was unsafe (Lightagent PR #28, RC7) |
| Locks | `F` is read and written only under the provisioning ledger lock, the same lock as P2. Nonce discards that raise `F` (§9.2) also take that lock |
| Key rotation | Adding, rotating, revoking or removing trusted keys never changes `F` |
| Controller registration | Registering or withdrawing a provisioner, rotating its local credential, or changing the `keyId` → credential mapping never changes `F`. Only replacing the ledger triggers the restore rule |
| Concurrent creates | Serialized by the lock. `F` is the maximum of `issuedAt − 30` over admitted creates (and of discarded nonces' `expiresAt + 30`) |
| Replay and exact redelivery | A byte-identical copy is `REPLAY_DETECTED` while its nonce record exists. Once that record is discarded, `F ≥ expiresAt + 30` (§9.2), so step 14 refuses it. A redelivery (§9.1) has fresh stamps and is unaffected |
| Legitimate retries | The fence refuses a create only if `expiresAt + 30 ≤ issuedAt' − 30` for some admitted create `issuedAt'`, that is, only if it was issued at least 120 s before the newest admitted create. Web's fresh retries are never refused, unless Web's own clock steps back by more than about 120 s. In that case they fail closed with `EXPIRED` until the clock catches up |
| Liveness cost | None with a clock that does not step back. Step 12 admits only `issuedAt ≤ now + 30`, so every advance satisfies `F ≤ now` at that moment, and a fence refusal implies `expiresAt + 30 ≤ F ≤ now`, which the wall clock refuses anyway. In the fixtures and randomized schedules, removing the wall-clock check changes no outcome |
| Bad input | A command cannot push `F` into the future. Step 12 bounds `issuedAt − 30 ≤ now`. A harness clock running fast raises `F` only up to its own `now`, which fails closed until real time catches up |

**Why harness scope.** Lemma 2 of §13.2.1 needs the advance by `t` to be
visible to every later copy of `u`. `u` and `t` belong to one job, so they
share profile, idempotency key and provisioner. A per-key or per-provisioner
fence would therefore also satisfy Lemma 2. A per-profile fence would too, for
one job. Harness scope is still chosen, for four reasons:

- it is one durable value;
- it is what the review proposed;
- it covers the nonce-discard rule (§9.2) for every command, including
  status and revoke, without a lookup;
- the liveness argument above shows that it costs nothing.

A narrower fence is permitted only if it is at least as strict for every
command of the job (same profile and key), and if the §9.2 discard rule
raises the matching fence.

### 10.6 Ledger continuity and harness retirement (RC7)

**Relationships.** A9 (§13.2.1) binds these together:

| Element | Relationship |
|---|---|
| Harness identity (`hns_…`) | Exactly one provisioning ledger (A1). The ledger is **stamped** with the harness id when an operator explicitly initializes it, and is never created implicitly |
| Provisioning ledger | Holds the operations (operation ids, states, idempotency keys scoped to the provisioner), the execution fence, and the harness-id stamp. It is the only authority for "which operation does this key have" (P3) |
| Identity store | Holds ownership bindings and their provisioning transaction records (`provisioning:<operationId>`), written by the bind step of an operation the ledger recorded first |
| Profile store | Holds the profile directories and their `.provisioning-operation` markers, which name the operation that created each |
| Nonce store | Records commands by nonce. Its records must not be older than the fence that would exclude them (§9.2) |
| Execution fence | Never lower than the `issuedAt − 30` of any create that the ledger's operations reflect. Never lowered by a recovery (§10.5) |
| Operation ids and idempotency keys | Unique for the life of a harness id. A key resolves to the same operation forever (S1). A new ledger forgets keys, so it cannot keep S1 or P3 |
| Ownership bindings | Exist only as effects of ledger operations (or of operator actions, which `ownerBound` reports, §13.1). A binding without its operation is the RC7 hazard |

**Continuity check (P8).** The check below runs at gateway start, at
activation, and after any restore. C1 is also re-checked under the ledger
lock for every command. Reference: `checkLedgerContinuity`. Fixtures:
`ledger-continuity.json`.

| # | Condition | Failure |
|---|---|---|
| C1 | A ledger exists, stamped with the configured harness id, and not marked retired | `NO_LEDGER`, `UNSTAMPED_LEDGER`, `HARNESS_ID_MISMATCH`, `RETIRED` |
| C2 | Every operation id named by an identity provisioning record or a profile marker exists in the ledger | `LEDGER_BEHIND_STORES` (a fresh or older ledger beside surviving bindings) |
| C3 | Every ledger operation in state `completed` or `revoked` has its identity provisioning record | `STORES_BEHIND_LEDGER` (an identity store that is older, replaced or new) |

- **Absence is never a clean state.** A missing ledger, an unstamped one, or
  a new, empty identity store fails closed, even when no records exist at
  all. Only an explicit operator initialization establishes a new harness id,
  and it is permitted only for an id that Web has never had registered.
- **Fail-closed behaviour.** While the check fails, the gateway answers every
  command `503 LEDGER_CONTINUITY_FAILED` before parsing it (`commandId` is
  null), and changes nothing. In particular it never re-creates, re-binds,
  re-assigns or deletes a profile or binding.
- **Limitation.** PR #26's stores carry no generation marker. C2 and C3 rely
  on the operation ids that PR #26 already writes, as identity transaction
  keys and profile markers. Lightagent's L1 work MUST confirm that those
  records are retained for the life of the harness id, and are not pruned. If
  they could be pruned, L1 MUST add a durable generation marker, written to
  all three stores at initialization, before activation.
- **What no check can detect.** If every store is wiped together, nothing
  survives to be bound to, and invariant S holds. Web then sees
  `UNKNOWN_OPERATION` for operations it knew (needs attention, §13.4). Two
  live copies of one ledger (a cloned VM) remain excluded only by A1.

**Retirement.** If the provisioning history of a harness id is irretrievably
lost while profiles or bindings may survive:

1. The harness operator **retires** the id: the ledger is marked retired, or
   removed, and the gateway fails closed through C1. Nothing on the harness
   is re-created, re-assigned or deleted by provisioning.
2. **Web learns it in two ways**:
   - automatically, from the first `LEDGER_CONTINUITY_FAILED` answer: the
     harness is circuit-broken in Web, no new operation is sent to it, and
     operator attention is raised;
   - authoritatively, from the administrator's registry change: the
     `harnesses` row leaves `active` (it becomes `disabled`, and a later
     migration adds a retirement record).

   Web never depends on someone noticing a missing file.
3. Web sends nothing more to a retired harness id. Unresolved creates on it
   stay unresolved, flagged `LEDGER_CONTINUITY_FAILED` or
   `PROFILE_UNAVAILABLE_WHILE_OPEN`, never `failed` (§13.2 R3a). The
   reconciliation plan is `operator-attention` (`planReconciliation(…,
   "retired")`). Web never revokes, re-creates or migrates them on its own.
4. A replacement harness gets a **new** harness id, through explicit operator
   registration, with a documented migration or recovery decision for every
   profile of the retired id. Web never resends a retired id's create to the
   new id: the new ledger does not know the key, so it would create a second
   profile and binding.
5. Operation ids, ownership and idempotency semantics are unchanged.
   Retirement only stops new provisioning on the old id.

## 11. Errors

Codes are uppercase `[A-Z0-9_]{1,64}`, so they fit
`provisioning_jobs.error_code` unchanged. The registry, with HTTP status,
class and applicable operations, is `errors.json`. It is normative.

| Class | Meaning for Web | Codes (HTTP) |
|---|---|---|
| `protocol` | Refused before any side effect (`EXPIRED` at step 12 or step 14). Says nothing about *other* transmissions | `METHOD_NOT_ALLOWED` 405, `UNSUPPORTED_MEDIA_TYPE` 415, `PAYLOAD_TOO_LARGE` 413, `MALFORMED_JSON` `DUPLICATE_KEY` `INVALID_JSON_VALUE` `INVALID_ENVELOPE` `UNSUPPORTED_PROTOCOL` `UNKNOWN_FIELD` `MISSING_FIELD` `WRONG_PURPOSE` `UNSUPPORTED_OPERATION` `INVALID_FIELD` `INVALID_LIFETIME` `NON_CANONICAL` 400, `UNKNOWN_KEY` `KEY_REVOKED` `BAD_SIGNATURE` `NOT_YET_VALID` `EXPIRED` 401, `WRONG_AUDIENCE` 403, `NONCE_STORE_UNAVAILABLE` `LEDGER_CONTINUITY_FAILED` 503 |
| `payload` | Deterministic in the payload: the same payload can never succeed | `INVALID_PROFILE_ID` `RESERVED_PROFILE_ID` `INVALID_ISSUER` `INVALID_SUBJECT` `INVALID_DISPLAY_NAME` `INVALID_TEMPLATE` `INVALID_IDEMPOTENCY_KEY` `INVALID_OPERATION_ID` 400 |
| `admission` | Local authority refused **before** the idempotency lookup. State-dependent | `UNAUTHENTICATED` 401, `NOT_A_PROVISIONER` `CREDENTIAL_NOT_PROVISIONING_ONLY` `PROVISIONER_INACTIVE` `PROVISIONER_REVOKED` `PROFILE_OUTSIDE_CREDENTIAL` 403 |
| `merits` | create only. Refused **after** the idempotency lookup, so at that moment no operation existed for this key | `ISSUER_NOT_ALLOWED` `TEMPLATE_NOT_ALLOWED` `QUOTA_EXCEEDED` `LEDGER_FULL` 403, `PROFILE_UNAVAILABLE` `PRINCIPAL_INACTIVE` `EXTERNAL_IDENTITY_CONFLICT` 409 |
| `operation` | status/revoke on a known operation id | `UNKNOWN_OPERATION` 404, `OPERATION_IN_PROGRESS` `NOT_REVOCABLE` `OWNERSHIP_CHANGED` 409 |
| `conflict` | Web defect: the same key with a different payload. Never a failure | `IDEMPOTENCY_CONFLICT` 409 |
| `indeterminate` | The command **may have taken effect**. Treated exactly like a timeout | `STORAGE_UNAVAILABLE` `STORAGE_CORRUPT` `IDENTITY_UNAVAILABLE` 503, `INTERNAL_ERROR` 500, `REPLAY_DETECTED` 409 |

**Finality of a refusal for create resolution (r3).** Each code in
`errors.json` carries `createResolution`, which is derived from its class:

| `createResolution` | Classes | Meaning |
|---|---|---|
| `final` | `payload`, `admission`, `merits` | No copy of this transmission can ever take effect. Admission and merits refusals come after the nonce was durably recorded (§9.2). Payload refusals are deterministic in the payload |
| `transmission-only` | `protocol` | This copy had no effect. Another copy of the same bytes may still pass later: these refusals come before the nonce is recorded and depend on harness configuration (keys, harness id) or its clock. `EXPIRED` is in this group because it can come from step 12 as well as step 14 |
| `indeterminate` | `indeterminate` | This copy may have taken effect |
| `conflict`, `not-applicable` | `conflict`, `operation` | A Web defect, or a code that never answers create |

r2 treated `protocol` refusals as final. That was unsafe: the fixture
`pre-nonce-refusal-then-duplicate` shows a create refused `UNKNOWN_KEY`
whose duplicate binds after the operator adds the key.

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

**Inputs.** The inputs are every transmission in the job's **journal**
(§13.10), each with its `issuedAt`, `expiresAt` and §12.4 outcome.

- A journaled transmission without a recorded answer is `uncertain`, whatever
  the reason (it was never sent, the Worker crashed, it timed out).
- A transmission outside the journal cannot exist: nothing is sent before it
  is journaled (RC6).
- Refusal finality is the `createResolution` of §11.

Reference: `resolveCreateJob`. Fixtures: `create-resolution.json` and
`ordering-model.json`.

- **R1. An operation resolves the job.** If any transmission returned an
  operation, the job is resolved with that `operationId`, in its state,
  including `failed` and `revoked`. Two different operation ids for one job
  are an anomaly.
- **R2. Payload refusals are final.** If any transmission was refused with a
  `payload`-class code, the job is `failed` with that code, because the same
  payload can never succeed.
- **R3. Otherwise, a job fails only when every transmission is accounted
  for.** Call a transmission *open* if it is `uncertain`, or if it was refused
  `transmission-only`.
  - The job is `failed` only if, for **every** open transmission `u`, some
    transmission `t` was refused with a `merits`-class code and
    `t.issuedAt ≥ u.expiresAt + 60` (`u`'s acceptance horizon).
  - If no transmission is open (every one was refused `final`), nothing
    exists, and the job is `failed` with the latest code.
  - `PROFILE_UNAVAILABLE` never rules out an open transmission (R3a below).
- **R3a (r4). Signs of ledger discontinuity are never evidence.**
  - **`PROFILE_UNAVAILABLE` while open.** If a job has any open transmission
    and any transmission was refused `PROFILE_UNAVAILABLE`, the job needs
    attention (`PROFILE_UNAVAILABLE_WHILE_OPEN`). It is never `failed`. Under
    A9, a resend of the same key cannot get `PROFILE_UNAVAILABLE` for an `agt_`
    id that only this job uses. Getting one means the ledger may have
    forgotten an operation whose binding survives (RC7).
  - **`LEDGER_CONTINUITY_FAILED`.** Any transmission refused with this code
    makes an otherwise unresolved job need attention
    (`LEDGER_CONTINUITY_FAILED`, §10.6).
  - **Defence in depth.** R3a is a backstop for the harness check. A fresh
    ledger that answers on quota (`QUOTA_EXCEEDED`) is caught only by P8
    (`fresh-ledger-quota-refusal`).
- Otherwise the job is **unresolved**. `IDEMPOTENCY_CONFLICT` and unknown
  codes are anomalies (`needs attention`), never failures.

**Consequences:**

- Exhausted retries never produce `failed` (`timeouts-exhausted`), and
  neither does elapsed time alone (`elapsed-time-alone`).
- A timeout followed by a quick `QUOTA_EXCEEDED` stays unresolved
  (`timeout-then-merits-too-early`).
- A lone `UNKNOWN_KEY` or `EXPIRED` stays unresolved, and Web keeps
  reconciling (`single-protocol-refusal`, `single-expired-refusal`). This also
  covers the review's recommendation to retry transient refusals.

#### 13.2.1 Safety invariant and proof

**Invariant S.** If Web concludes `failed` for a `profile.create` job, then no
operation is recorded, now or at any later time, under the job's
`(provisioner, idempotencyKey)`. No owner binding therefore results from that
job.

Assumptions. Each one is a normative requirement elsewhere in this document:

| # | Assumption | Where |
|---|---|---|
| A1 | One harness id is exactly one provisioning ledger: one lock, one fence, one nonce store, shared by every gateway process. Two ledgers behind one endpoint, for example behind a load balancer, break idempotency itself and are forbidden | §10.4, §10.5 |
| A2 | Every trusted `keyId` of the Web environment maps to the same provisioner principal, so every transmission of a job has one idempotency scope | §6.4 |
| A3 | P2 (serialization to durability) and P3 (record before effect) | §10.4 |
| A4 | The fence: durable, never decreasing (including the restore rule), checked at step 14 under the lock, and advanced after step 15 under the lock, durably before the lock is released | §10.5 |
| A5 | Nonces: recorded atomically at step 12, durable before the command proceeds or is answered, and discarded only when `F ≥ expiresAt + 30` | §9.2 |
| A6 | Journal: every transmission that can reach the harness is journaled before it is sent; rows are never deleted; recorded answers are final | §13.10 |
| A7 | Truthful classification: an answer that Web classifies as an operation or a refusal was produced by the harness for that transmission (authenticated HTTPS plus correlation). Forged answers are outside S | §12.1, §12.5 |
| A8 | Only this job uses its idempotency key (unique in D1), and the §8 validation rules do not change within a revision | §9.1, D1 |
| A9 | **Provisioning ledger continuity.** For an existing harness identity, the provisioning operation history (operations, idempotency keys, fence, nonce records) remains consistent with the identity bindings and profile state it governs. The harness never begins with an empty or replacement ledger while bindings made through the old one remain valid. Ledger, nonce store, fence, identity store and profile store are restored only together, from one mutually consistent recovery point. A ledger whose continuity cannot be established fails closed (P8), and its harness id is retired. A new ledger is never evidence that past operations did not happen | §10.5, §10.6, P8 |

**Not assumed:**

- anything about the harness clock: it may be wrong and may step in either
  direction;
- any bound on how long a call waits for the lock, or how long a started
  execution takes;
- anything about network delay, loss, duplication or reordering;
- any bound on Web–harness skew.

**Lemma 1 (final refusals).** If Web received a `final` refusal for
transmission `x`, no copy of `x` ever records an operation.

*Proof.*

1. `admission` and `merits` refusals are produced at steps 15–16, after `x`'s
   nonce was durably recorded at step 12 (A5).
2. The insert is atomic, so the copy `c` that Web received the answer from is
   the copy that recorded the nonce. Any other copy that arrived while the
   record existed answered `REPLAY_DETECTED`, which is indeterminate.
3. `c` recorded no operation. A refusal at step 15 writes nothing, and a
   `begin` refusal records nothing (P3).
4. A later copy finds the record and is refused. The record is discarded only
   once `F ≥ x.expiresAt + 30` (A5). After that, `F` never decreases (A4), so
   step 14 refuses every copy with no effect.
5. `payload` refusals are deterministic in the payload, which every copy and
   every transmission of the job share (§9.1, A8). □

A9 is what makes P3 hold *across time* for a harness id: "every later
lookup sees every operation an earlier call started" assumes that the ledger
which recorded `u`'s operation is the one that `t` reads. RC7 is exactly a
violation of this. A fresh ledger answered `t` on the merits while `u`'s
binding survived in the identity store.

**Lemma 2 (exclusion by a later merits refusal).** If transmission `t` was
refused on the merits and `t.issuedAt ≥ u.expiresAt + 60`, no copy of `u`
ever records an operation.

*Proof.*

1. `t` passed step 15. Before `t` released the lock, `F` became durably
   `≥ t.issuedAt − 30 ≥ u.expiresAt + 30` (A4).
2. Take any copy `c` of `u` that reaches step 14. Calls are serialized (A3),
   so there are two cases.
3. **`c` takes the lock after `t` releases it.** `F` is already
   `≥ u.expiresAt + 30` and has not decreased, so step 14 refuses `c` with no
   effect. This holds whatever the clock reads.
4. **`c` held the lock before `t`.** `c`'s call completed durably before
   `t`'s began (P2). If `c` recorded an operation, it did so under the
   job's key (A2, A8). `t`'s idempotency lookup would then have found it
   (P3), and `t` would have answered with that operation, not a merits
   refusal (A7). □

**Theorem.** Suppose Web concludes `failed`.

- By R2, Lemma 1 (payload case) applies to every transmission.
- By R3, every open transmission is excluded by Lemma 2, and every other
  transmission is a `final` refusal, excluded by Lemma 1.

By A6, these are all the transmissions that can reach the harness. So no copy
of any transmission records an operation, and by A8 nothing else uses the
key. ∎

The harness clock appears nowhere in the proof. The wall-clock half of step
14 bounds execution in normal operation; safety rests on the fence. The
randomized schedules agree: removing the wall-clock check produces no unsafe
schedule.

#### 13.2.2 Counterexamples: why each r3 rule is needed

Each scenario in `ordering-model.json` is evaluated under r2, under the
review's literal RC5/RC6 proposal, under r3, and under r3 with one rule
removed. `unsafe` means Web concluded `failed` while an operation exists.

| Scenario | Unsafe under | Rule that defeats it |
|---|---|---|
| `backward-step-while-waiting` (the review's RC5 case) | r2, r3 without fence | fence check (A4) |
| `fence-visible-only-after-unlock` | r2, review proposal, r3 without fence, r3 with fence durable only after unlock | fence durable before unlock (A4). **New in r3**, not in the review |
| `duplicate-of-refused-command-after-restart` | r2, review proposal, r3 without durable nonces | durable nonces (A5). **New in r3** |
| `duplicate-after-clock-purge-and-rollback` | r2, review proposal, r3 discarding nonces by clock | discard only when fenced (A5). **New in r3** |
| `pre-nonce-refusal-then-duplicate` | r2, review proposal, r3 treating protocol refusals as final | `transmission-only` refusals (§11). **New in r3** |
| `unjournaled-transmission` (the review's RC6 case) | r2, r3 without journal | write-before-send journal (A6) |
| `fresh-ledger-retained-identity` (the review's RC7 case) | r2, review proposal, r3 and every r3 ablation | ledger continuity (A9, P8) **and** R3a, each sufficient alone here |
| `fresh-ledger-quota-refusal` | r2, review proposal, r3, r4 without the continuity check | P8 only. R3a cannot see a `QUOTA_EXCEEDED` from a fresh ledger |
| `ledger-restored-older-than-identity` | as `fresh-ledger-retained-identity` | as above |
| `nonces-restored-alone`, `fence-restored-alone` | r2, review proposal, r3 without fence, r4 without the restore's fence raise | `F := max(F_restored, T + 150)` (§10.5) |
| `identity-restored-older-than-ledger`, `consistent-restore-of-all-stores` | none (r4 fails closed on the former until an operator reconciles) | — |
| `crash-after-record-restart-resend`, `maximum-skew-no-step`, `completion-after-expiry`, `overlapping-windows-out-of-order` | none | (liveness and positive cases) |

#### 13.2.3 Test evidence

The tests check that the model and the fixtures agree with the proof. They do
not replace it.

`tests/contracts/provisioning-protocol.test.ts` runs in workerd:

- **Broad schedules.** Seed `0x7a3c2026`, 30,000 schedules:
  - 1–4 transmissions, with gaps of 0–250 s or at the horizon;
  - 0–2 copies of each, delays up to 400 s, lock waits up to 300 s, holds up
    to 200 s;
  - a clock offset of ±30 s plus up to two steps of ±90 s;
  - restarts, housekeeping, a key trusted late, quota windows, crashes after
    record, lost answers, and unjournaled sends.
- **Focused hazards.** Seed `0x5afe0003`, 25,000 per family:
  - lock-wait with a backward step around a refusal at the horizon;
  - a duplicate of a refused command across a restart, and across a clock
    jump with a purge.
- **Recovery schedules (r4).** Seed `0x0a900004`, 25,000 schedules:
  - u completes, crashes after record, or is refused, sometimes with a
    duplicate copy;
  - one recovery restores a random non-empty subset of {ledger, identity,
    nonces, fence}, the fence to 0 or an older value;
  - a clock offset of ±30 s with up to one step of ±60 s;
  - 1–3 resends at or after the horizon, and quota windows.
- **Results.**
  - r4 is unsafe in 0 schedules in every family.
  - In the recovery family, r3 is unsafe in 2,475 schedules, and r4 without
    the continuity check in 786.
  - Outside recoveries, r3 and r4 behave identically (0 unsafe).
  - Every other rule set and ablation has counterexamples, in its family or
    in the deterministic fixtures.
  - The exact counts are in §18.

`tests/contracts/provisioning-journal.test.ts` checks the §13.10 journal on
real D1.

**Not modelled:** forged answers (§12.1), a compromised harness, two ledgers
behind one harness id (A1), operator reassignment during recovery, and Web
clock errors. Web clock errors do not
affect S, because the proof uses only Web's signed stamps; they can only cost
liveness (§10.5).

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

### 13.10 Transmission journal: write before send (RC6)

**Invariant J.** Every transmission that could reach a harness is
represented in Web's durable D1 journal before any byte of it leaves the
Worker. Create resolution (§13.2) reads only the journal. An in-memory value,
the request's lifetime, a log line or `waitUntil` is never evidence that a
transmission was or was not sent.

Required sequence for each transmission:

| # | Step | Durable effect |
|---|---|---|
| 1 | Authenticate and authorize the user (existing guard) | — |
| 2 | Persist the job and the desired state | `provisioning_jobs` row, with the desired state on the profile and job |
| 3 | Fix the logical command: canonical payload, `payloadHash`, operation, harness, idempotency key | Persisted with the job, never recomputed from mutable rows (a rename must not change a retry's payload) |
| 4 | Claim the job's delivery lease and insert the transmission row. Identity: `command_id`, `seq`, nonce hash, `key_id`, `harness_id`, operation, `payload_hash`, `issued_at`, `expires_at` (the deadline), state `journaled` | **One D1 batch** (a transaction). Losing the claim inserts nothing |
| 5 | Commit | The batch returns. Only now may the command be signed and sent |
| 6 | Sign and send over HTTPS (§3) | — |
| 7 | Persist the answer (`answered`, final), or mark the row `uncertain` (timeout, network error, `RESPONSE_INVALID`, indeterminate code), and release the lease | Atomic batch |
| 8 | Reconcile: §13.2 over the journal, then §13.3–§13.5 (status, R4 resends with the same logical command, revoke) | — |

Rules:

- **A journal row is not delivery.** A `journaled` row says only that the
  transmission *may* have been sent. With no recorded answer, it is uncertain
  for resolution. It is never `refused`, `failed` or "not sent".
- **No resend of a journaled transmission's bytes.** The plaintext nonce
  lives only in the sending Worker's memory. The journal stores its SHA-256.
  A retry is a new transmission with a new row and the same logical command
  (§9.1).
- **Crash after send, before step 7:** the row stays `journaled`. Recovery
  makes it `uncertain`. Its identity (`issued_at`, `expires_at`, payload
  hash, key) is enough for R3 and for R4 resends.
- **A late answer** after recovery marked the row uncertain may still be
  recorded, because more information is allowed. A recorded answer is
  final.

Protocol-level D1 constraints. They are to be implemented by an **additive
migration 0003 or later**. 0001 and 0002 are never edited.

| Constraint | Purpose |
|---|---|
| `command_id` primary key; `nonce_hash` UNIQUE; `(job_id, seq)` UNIQUE | One row per transmission, no nonce reuse, ordered history |
| Insert trigger: `payload_hash` equals the job's fixed payload hash | Retries cannot change the logical command |
| `expires_at > issued_at` and `expires_at − issued_at ≤ 120` | Matches §9.3 |
| Update trigger: an `answered` row is immutable; identity columns never change; `uncertain` never returns to `journaled` | The history Web reasons over is stable |
| Delete trigger: refuse | Append-only. Retention may archive rows only after the job is terminal and every row's horizon has passed |
| Job delivery lease (`lease_token`, `lease_until`, both or neither) | Concurrency-safe claiming |

**Claiming and leases.**

- A Worker claims with a conditional
  `UPDATE … SET lease_token = ?, lease_until = ?, next_seq = next_seq + 1
  WHERE job_id = ? AND (lease_until IS NULL OR lease_until <= now)`.
- In the same batch it runs
  `INSERT … SELECT … WHERE lease_token = ?` for its own token, so only the
  winner inserts.
- Concurrent claims produce exactly one row. A Worker that loses inserts
  nothing and sends nothing.
- **Lease recovery:** the reconciler turns `journaled` rows of expired leases
  into `uncertain` and clears the lease.
- A stalled Worker whose lease expired may still send its journaled row,
  while a new Worker journals and sends another. Both rows exist, both are
  reasoned over, and the harness's idempotency makes them one operation. The
  lease is an efficiency measure. **Safety rests on J, not on the lease.**

**Primary-consistent reconciliation (r4 clarification).** When D1 read
replication is enabled, a replica may lag the primary. Any read that can lead
to a `failed` conclusion, or that decides whether every potentially delivered
transmission is accounted for, MUST be primary-consistent:

- run it in a D1 session started with `first-primary`;
- or run it in a session that continues from the bookmark of the journal
  write it must observe;
- or run it in the same batch as that write.

It MUST NOT use an unconstrained replica read. A stale journal could omit a
row and break A6. Reads that only drive retries or display are not
restricted.

The later Web implementation (migration 0003 or later, not part of L0)
therefore provides:

1. durable journal insertion before network delivery (invariant J);
2. transactionally safe delivery claiming (one batch: lease and insert);
3. conservative treatment of uncertain transmissions (journaled without an
   answer is uncertain);
4. primary-consistent reconciliation reads;
5. an immutable logical command identity (the payload-hash trigger);
6. no definitive failure while provisioning history may be unresolved
   (§13.2 R3 and R3a, and the retired-harness plan of §10.6).

Reference: `tests/contracts/provisioning/journal.ts`, test-only and not a
migration. It runs on real D1 in workerd
(`provisioning-journal.test.ts`), covering each of these:

- a crash before journaling;
- a crash after commit, before send;
- a crash during send;
- a crash after send, before persistence;
- a lost refusal;
- 8 concurrent claims;
- a stalled Worker overlapping a new one;
- retry identity and the payload-mismatch trigger;
- append-only and final rows;
- suspension while uncertain (resend, then revoke);
- late completion after a restart;
- safe failure classification.

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
| `create-resolution.json` | R1–R3 decision cases, including the horizon boundary (±1 s), `EXPIRED` at execution, elapsed time alone, `transmission-only` refusals (r3), and the reconciliation plan (`send-create`, `revoke`, `confirm-status`, `operator-attention`, `none`) for desired present and absent |
| `execution-deadline.json` | §10 step 14: single checks, each with `fence` (0 for the r2 cases; r3 adds fence = deadline → refuse, fence = deadline − 1 → proceed, and a clock rolled back below a raised fence), and the r2 race scenarios with and without step 14 (clock never steps) |
| `ordering-model.json` | The rule sets (r2, review proposal, r3, r4, and ablations) and the deterministic scenarios of §13.2.2, including the r4 recovery scenarios, each evaluated under every rule set (`simulateOrdering`). Results include the surviving `binding` and whether the gateway `failedClosed` |
| `ledger-continuity.json` | r4: the §10.6 C1–C3 activation check, 13 cases with the expected verdict and reason |
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
- **Portable delivery.** While the Web repository has no remote, the review
  branch is delivered as a `git bundle` with full ancestry. Its path and
  SHA-256 are recorded in `ACCEPTANCE.md`. A reviewer verifies it in four
  steps:
  1. `git bundle verify`;
  2. clone it;
  3. check the candidate SHA;
  4. run `git archive <candidate> docs/PROVISIONING_PROTOCOL.md protocol | tar -x`
     and `sha256sum -c protocol/la-web-provisioning-1/MANIFEST.sha256`.

  The reviewer imports the exact committed bytes, never a regeneration.
- The generator is deterministic (`npm run protocol:fixtures -- write|check`).
  `tests/static/provisioning-fixtures.test.ts` fails if any committed byte
  differs from a regeneration or from the manifest.
  `tests/contracts/provisioning-protocol.test.ts` runs every vector inside
  workerd.
- `.gitattributes` marks these files `-text`, so checkouts on any platform
  keep the hashed bytes.
- A verifier passes the fixtures when every `commands-*` and `redelivery`
  vector gives exactly its `expect`, and every `execution-deadline.json`
  `deadlineCases` entry (with its `fence`) gives its `expect`.
- A Web implementation additionally passes `responses.json` and
  `create-resolution.json`.
- An ordering model passes when it reproduces `ordering-model.json`.
- A harness's continuity check passes when it reproduces
  `ledger-continuity.json`.
- `create-resolution.json` `plan` lists the plan for an active harness
  (`present`, `absent`) and for a retired one (`retiredPresent`,
  `retiredAbsent`).
- A harness's L3 tests reproduce the following against the real service:
  - a create blocked on the lock past its deadline, while another call
    holds it, answers `EXPIRED` and records nothing;
  - the same with the clock stepped back but the fence raised;
  - a duplicate of a refused create across a restart answers
    `REPLAY_DETECTED`.

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
4. A new migration (0003 or later). Never edit 0001 or 0002. It adds the
   §13.10 transmission journal (RC6, required before any delivery), its
   triggers, the job's fixed canonical payload and delivery lease, and job
   columns
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
4. Fail-closed configuration and **ledger continuity (P8, L1):**
   - explicit operator initialization stamps the ledger with the harness id,
     and the ledger is never created lazily;
   - the §10.6 C1–C3 check runs at start, at activation and after restores,
     and C1 runs per command under the lock;
   - while the check fails, the gateway answers `LEDGER_CONTINUITY_FAILED`;
   - L1 confirms that `provisioning:<op>` identity records and
     `.provisioning-operation` markers are never pruned, or adds a
     generation marker;
   - an operator `retire` marks the ledger retired.

   Also part of this item: the harness's own `harnessId`, the trusted-key list,
   `keyId` → local credential key id (all mapping to one provisioner).
5. A nonce ledger (§9.2, P7): atomic across gateway processes, durable
   before proceeding or answering, surviving restarts, and discarded only
   once the fence excludes the command (raise the fence first).
6. The §10.3 adapter, with the `keyId` → credential mapping resolved at
   step 15, after the nonce (§10.2 table): `caller_for_at` with the mapped
   credential, the
   `profileId` consistency check for status and revoke, uppercase code
   mapping, failed operations as `200`/`201` operation responses, and echoes.
7. Regression tests for S1 and S2 (added as `web_*` tests in PR #28).
8. A mirror of the specification and fixtures, with a CI job that runs every
   vector and checks `MANIFEST.sha256`.
9. **§10.4 P1 and P6 (L3, required):** a narrow, additive
   `ProvisioningService` entry point for the gateway's creates. Inside
   `exclusive()`:
   - it reads the clock and the durable `execution_fence`;
   - it refuses `EXPIRED` when `now ≥ deadline` or `deadline ≤ fence`;
   - after admit, it sets `fence := max(fence, issuedAt − 30)` and saves it
     durably before the lock is released;
   - it is otherwise `provision`.

   The existing `provision` and its HTTP API stay unchanged. Tests:
   - a create blocked on the lock past its deadline records nothing;
   - the same with a backward clock step and a raised fence;
   - a create admitted in time completes even if its commit finishes after
     the deadline (P2);
   - a restore never lowers the fence (§10.5).

## 17. Open points and residual risks

Resolved in r2 by Lightagent's review (PR #28):

- **NFC**: kept, with `icu_normalizer` (§4.6).
- **Retrying a failed create on the same id**: confirmed by the PR #28 test
  `web_a_failed_create_leaves_its_profile_id_available_to_a_new_key` (§13.3).

Resolved in r3: harness clock steps (RC5, the fence) and write-before-send
(RC6, the journal). r3 also resolves three further gaps found while proving
RC5: fence durability before unlock, durable nonces discarded only under the
fence, and `transmission-only` refusals.

Resolved in r4: ledger continuity (RC7): A9, the corrected §10.5 restore
rule, §10.6 continuity check and retirement, and R3a. It also clarifies where
the credential mapping is resolved (§10.2) and requires primary-consistent D1
reconciliation (§13.10).

Still open:

1. **`profile.lookup`** (§13.9) is deferred, not rejected. It would also
   close the "forged refusal cannot be re-checked" residual risk (§12.1).
2. **Response signing** is gated, not dropped (§12.1 gates a–c).
3. **Restores and ledger replacement (corrected in r4).** r3 claimed this
   was covered by Lightagent's existing restore procedure (PR #26 §12). **It
   was not.** PR #26 §12 restores the ledger and the identity store together
   from one point. It never covered a fresh, empty or replacement ledger
   beside a retained identity store, and r3 §10.5 permitted exactly that
   (RC7). This case is now governed by A9, the corrected §10.5 restore row,
   §10.6 (continuity check C1–C3, fail-closed gateway, retirement), and Web's
   R3a.
   - **Residual:** the continuity check relies on PR #26's operation-id
     records being retained (§10.6 limitation).
   - **Residual:** a restore still needs an operator-verified time for the
     fence raise.
   - **Residual:** cloned live ledgers are excluded only by A1.
4. **Unsigned responses**: the residual risks listed in §12.1 are accepted
   for v1 only within the §12.5 ingress definition.
5. **Harness reachability** (direct HTTPS or a §12.5 tunnel) is a deployment
   choice per harness. It is recorded in that harness's registration review.
6. **Forged answers** stay outside invariant S (A7). See §12.1.
7. **Web's own clock** stepping back by more than about 120 s causes
   fail-closed `EXPIRED` answers until it catches up. Safety is unaffected.

## 18. Revision history

### r4 (this revision)

Resolves Lightagent's review of r3 (PR #28 `bcbdcf0`, `l0-protocol-review.md`,
reviewed digest `bd410d38…4a8d`, candidate `15f196c`). There is no wire
change: the envelope, signatures, JCS, payloads, response schema, fence,
nonces, journal, `ownerBound`, `INVALID_TEMPLATE`, NFC and T1–T7 are
unchanged. Every r3 command, redelivery, response and key vector is
byte-identical apart from the revision label.

| Item | Change |
|---|---|
| RC7 ledger continuity | A9 (§13.2.1). The §10.5 restore row is corrected: one consistent recovery point, never a new or lone ledger for an existing harness id. New §10.6 covers the relationships, the C1–C3 fail-closed check (P8), retirement, and how Web learns it. New registry code `LEDGER_CONTINUITY_FAILED` (`503`, `protocol`, transmission-only) |
| Web backstop | §13.2 R3a: `PROFILE_UNAVAILABLE` never rules out an open transmission (`PROFILE_UNAVAILABLE_WHILE_OPEN`). `LEDGER_CONTINUITY_FAILED` needs attention. The plan for a retired harness is `operator-attention` |
| §17 item 3 | Corrected: PR #26 §12 never covered a fresh ledger beside retained identity state |
| Clarifications | §10.2: authentication-decision order; the credential mapping is resolved at step 15, after the nonce. §13.10: primary-consistent D1 reads, and the six implementation requirements |
| Fixtures | `ordering-model.json`: rule sets r4 and ablations, `binding` and `failedClosed` results, and 7 recovery scenarios including `fresh-ledger-retained-identity`. `ledger-continuity.json` (new, 13 cases). `create-resolution.json`: 3 cases and retired-harness plans. `errors.json`: the new code |

Randomized results (unsafe schedules per rule set; r3-era counts are
unchanged):

| Rule set | Broad (`0x7a3c2026`, 30,000) | Lock-wait (`0x5afe0003`, 25,000) | Duplicate (`0x5afe0003`, 25,000) | Recovery (`0x0a900004`, 25,000) |
|---|---|---|---|---|
| r4 | 0 | 0 | 0 | 0 |
| r4 without the continuity check | 0 | 0 | 0 | 786 |
| r4 with `PROFILE_UNAVAILABLE` ruling out | 0 | 0 | 0 | 0 |
| r4 without the restore's fence raise | 0 | 0 | 0 | 0 (covered by `nonces-restored-alone` and `fence-restored-alone`) |
| r3 | 0 | 0 | 0 | 2,475 |
| r2 | 422 | 1,268 | 25,000 | 2,747 |
| Review proposal | 133 | 319 | 25,000 | 2,747 |

### r3

Resolves Lightagent's review of r2 (PR #28 `l0-protocol-review.md`, reviewed
digest `8649b453…b9a`, candidate `d31e544`). Wire format, signatures, JCS,
envelope, payloads, response schema, `ownerBound`, `INVALID_TEMPLATE`, NFC and
T1–T7 are unchanged. Every r2 command, redelivery, response and key vector is
unchanged.

| Item | Change |
|---|---|
| RC5 execution fence | §10.5 (new). Step 14 checks `deadline ≤ F`, and step 15 advances `F`. P6. §9.3 replaces r2's clock caveat. Fence cases in `execution-deadline.json` |
| RC5, refined: fence durable before unlock | §10.5. The review's "durable before the answer" is not enough (`fence-visible-only-after-unlock`) |
| New: durable nonces, discarded only under the fence | §9.2, P7. A duplicate of a *refused* command could bind after a restart, or after a clock purge and rollback |
| New: `transmission-only` refusals | §11, §13.2 R3, the `createResolution` field in `errors.json`. A pre-nonce refusal could be followed by a binding duplicate |
| RC6 write-before-send journal | §13.10 (new): sequence, invariant J, D1 constraints, claiming, lease recovery, and the test-only D1 reference |
| Proof | §13.2.1: invariant S, assumptions A1–A8, two lemmas, theorem. §13.2.2: counterexamples. §13.2.3: test evidence |
| Fixtures | `ordering-model.json` (new). `create-resolution.json` gains cases and `plan`. `execution-deadline.json` gains `fence`. `errors.json` gains `createResolution` |
| Delivery | §15 two-commit procedure, plus a `git bundle` |

Randomized results, as the test prints them. Each count is the number of
schedules in which a rule set is unsafe.

| Rule set | Broad (seed `0x7a3c2026`, 30,000 schedules) | Lock-wait hazards (seed `0x5afe0003`, 25,000) | Duplicate hazards (seed `0x5afe0003`, 25,000) |
|---|---|---|---|
| r3 | 0 | 0 | 0 |
| r3 without the wall-clock check | 0 | 0 | 0 |
| r2 | 422 | 1,268 | 25,000 |
| Review proposal | 133 | 319 | 25,000 |
| r3 without the fence | 0 | 1,268 | 0 |
| r3, fence durable only after unlock | 0 | 319 | 0 |
| r3 without durable nonces | 0 | 0 | 13,014 |
| r3, nonces discarded by clock | 0 | 0 | 12,550 |
| r3, protocol refusals treated as final | 132 | 0 | 0 |
| r3 without the journal | 7 | 0 | 0 |

### r2

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
