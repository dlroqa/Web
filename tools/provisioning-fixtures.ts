/**
 * Deterministic generator for the LA-WEB-PROVISIONING/1 shared fixtures
 * (Node only, test tooling; nothing in the Worker imports it).
 *
 * Every byte is derived from fixed labels: keys are SHA-256 of public
 * strings, nonces and command ids are hashes of the vector id, and Ed25519
 * signatures are deterministic. Running it twice gives identical files, which
 * tests/static/provisioning-fixtures.test.ts checks against the committed set.
 *
 * Each negative vector declares its expected code by hand; the generator
 * refuses to emit a vector the reference verifier does not agree with.
 */
import {
  ACCEPTANCE_HORIZON_SECONDS,
  assessOwnership,
  checkExecutionDeadline,
  executionDeadline,
  type RaceScenario,
  simulateCreateRace,
  canonicalize,
  type CanonicalValue,
  classifyResponse,
  type Command,
  COMMAND_PURPOSE,
  concatBytes,
  ED25519_L,
  ERRORS,
  FAILURE_CODES,
  fromBase64Url,
  isValidRedelivery,
  MAX_CLOCK_SKEW_SECONDS,
  MAX_COMMAND_LIFETIME_SECONDS,
  MAX_MESSAGE_BYTES,
  MAX_NESTING_DEPTH,
  OPERATION_STATES,
  type Operation,
  type OperationState,
  payloadHash,
  PROTOCOL,
  publicKeyFromSeed,
  resolveCreateJob,
  sha256Hex,
  signBytes,
  signCommand,
  signingInput,
  toBase64Url,
  toHex,
  type Transmission,
  type TrustedKey,
  utf8,
  verifyCommand,
  type VerifierState,
} from "../tests/contracts/provisioning/reference";

export const FIXTURE_DIR = "protocol/la-web-provisioning-1";
export const SPEC_PATH = "docs/PROVISIONING_PROTOCOL.md";
export const FIXTURE_SET = "la-web-provisioning-1/r2";

export const SCHEMA_IDS = [
  "LA-WEB-PROVISIONING/1#command/profile.create",
  "LA-WEB-PROVISIONING/1#command/profile.status",
  "LA-WEB-PROVISIONING/1#command/profile.revoke",
  "LA-WEB-PROVISIONING/1#response/operation",
  "LA-WEB-PROVISIONING/1#response/error",
] as const;

// ---------------------------------------------------------------------------
// Fixed inputs
// ---------------------------------------------------------------------------

const T0 = 1_791_000_000;
const HARNESS_A = "hns_fixtureharnessalpha0000001";
const HARNESS_B = "hns_fixtureharnessbravo0000002";
const ISSUER = "https://lightagent-control.example";
const SUBJECT = "usr_fixtureuser00000000000001";
const PROFILE = "agt_fixtureprofile000000000001";
const OPERATION_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
const PRINCIPAL = "ext-3b0c44298fc1c149afbf4c8996fb92427ae41e46";

const KEY_SPECS = [
  { name: "active", keyId: "web-test-active", description: "Current Worker signing key. Trusted (active) by every verifier state except afterRotation." },
  { name: "rotated", keyId: "web-test-rotated", description: "Successor key introduced by rotation. Trusted (active) during the overlap and after rotation." },
  { name: "revoked", keyId: "web-test-revoked", description: "A key the harness operator marked revoked. Must be refused even though its signatures verify." },
  { name: "untrusted", keyId: "web-test-untrusted", description: "Never configured on any harness. Used to forge signatures." },
] as const;
type KeyName = (typeof KEY_SPECS)[number]["name"];

interface Key {
  name: KeyName;
  keyId: string;
  seed: Uint8Array;
  publicKey: Uint8Array;
}

async function loadKeys(): Promise<Record<KeyName, Key>> {
  const out = {} as Record<KeyName, Key>;
  for (const spec of KEY_SPECS) {
    const seed = await sha256Bytes(`${PROTOCOL} TEST-ONLY signing key: ${spec.name}`);
    out[spec.name] = { name: spec.name, keyId: spec.keyId, seed, publicKey: await publicKeyFromSeed(seed) };
  }
  return out;
}

async function sha256Bytes(label: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(label)));
}

/** Verifier states, named so vectors can refer to them. */
function verifierStates(keys: Record<KeyName, Key>): Record<string, Omit<VerifierState, "now" | "seenNonces">> {
  const trust = (name: KeyName, status: TrustedKey["status"]): TrustedKey => ({
    keyId: keys[name].keyId,
    publicKey: toBase64Url(keys[name].publicKey),
    status,
  });
  const overlap = [trust("active", "active"), trust("rotated", "active"), trust("revoked", "revoked")];
  return {
    overlap: { harnessId: HARNESS_A, trustedKeys: overlap },
    afterRotation: { harnessId: HARNESS_A, trustedKeys: [trust("rotated", "active"), trust("revoked", "revoked")] },
    harnessB: { harnessId: HARNESS_B, trustedKeys: overlap },
  };
}

const hexOf = async (label: string) => toHex(await sha256Bytes(label));
const commandIdFor = async (id: string) => `cmd_${(await hexOf(`commandId:${id}`)).slice(0, 26)}`;
const nonceFor = async (id: string) => toBase64Url(await sha256Bytes(`nonce:${id}`));

type Envelope = Record<string, CanonicalValue>;

function createPayload(overrides: Record<string, CanonicalValue> = {}): Record<string, CanonicalValue> {
  return {
    profileId: PROFILE,
    issuer: ISSUER,
    subject: SUBJECT,
    displayName: "Research assistant",
    template: "assistant",
    idempotencyKey: "idk_fixturecreate00000000001",
    ...overrides,
  };
}

const operationPayload = (overrides: Record<string, CanonicalValue> = {}) => ({ operationId: OPERATION_ID, profileId: PROFILE, ...overrides });

async function envelope(id: string, operation: string, payload: CanonicalValue, overrides: Envelope = {}): Promise<Envelope> {
  return {
    protocol: PROTOCOL,
    purpose: COMMAND_PURPOSE,
    operation,
    commandId: await commandIdFor(id),
    // A status poll serves the create job it reconciles.
    jobId: operation === "profile.revoke" ? "prv_fixturejobrevoke000000001" : "prv_fixturejobcreate000000001",
    requestId: "req_fixturerequest00000000001",
    audience: HARNESS_A,
    keyId: "web-test-active",
    issuedAt: T0,
    expiresAt: T0 + 60,
    nonce: await nonceFor(id),
    payload,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------

interface CommandVector {
  id: string;
  description: string;
  verifier: string;
  now: number;
  seenNonces: string[];
  bodyHex: string;
  bodyText?: string;
  expect: { ok: true } | { ok: false; code: string; http: number };
  /** Valid vectors only. */
  detail?: {
    command: Envelope;
    canonicalJson: string;
    signingInputHex: string;
    signature: string;
    signedBy: KeyName;
    payloadHash: string;
  };
}

function textOf(bytes: Uint8Array): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

class Builder {
  readonly vectors: CommandVector[] = [];
  constructor(
    private readonly keys: Record<KeyName, Key>,
    private readonly states: ReturnType<typeof verifierStates>,
  ) {}

  key(name: KeyName): Key {
    return this.keys[name];
  }

  async sign(env: Envelope, by: KeyName = "active") {
    return signCommand(env, this.keys[by].seed);
  }

  async add(
    v: Omit<CommandVector, "bodyHex" | "bodyText" | "seenNonces" | "now" | "verifier" | "expect"> & {
      body: Uint8Array;
      verifier?: string;
      now?: number;
      seenNonces?: string[];
      expect: string | "ok";
    },
  ): Promise<void> {
    const verifier = v.verifier ?? "overlap";
    const now = v.now ?? T0 + 10;
    const seenNonces = v.seenNonces ?? [];
    const state = this.states[verifier];
    if (!state) throw new Error(`unknown verifier ${verifier}`);
    const result = await verifyCommand(v.body, { ...state, now, seenNonces });
    const expected = v.expect;
    const actual = result.ok ? "ok" : result.code;
    if (actual !== expected) throw new Error(`vector ${v.id}: reference says ${actual}, declared ${expected}`);
    const text = textOf(v.body);
    this.vectors.push({
      id: v.id,
      description: v.description,
      verifier,
      now,
      seenNonces,
      bodyHex: toHex(v.body),
      ...(text === undefined ? {} : { bodyText: text }),
      expect: expected === "ok" ? { ok: true } : { ok: false, code: expected, http: httpOf(expected) },
      ...(v.detail ? { detail: v.detail } : {}),
    });
  }

  /** A correctly signed, canonical command that must verify. */
  async valid(id: string, description: string, env: Envelope, options: { by?: KeyName; verifier?: string; now?: number } = {}) {
    const by = options.by ?? "active";
    const signed = await this.sign(env, by);
    await this.add({
      id,
      description,
      body: signed.body,
      verifier: options.verifier,
      now: options.now,
      expect: "ok",
      detail: {
        command: env,
        canonicalJson: canonicalize(env),
        signingInputHex: toHex(signed.signingInput),
        signature: signed.signature,
        signedBy: by,
        payloadHash: await payloadHash(env.operation as Operation, env.payload as CanonicalValue),
      },
    });
    return signed;
  }

  /** A correctly signed, canonical command whose content violates one rule. */
  async signedInvalid(id: string, description: string, env: Envelope, expect: string, options: { by?: KeyName; verifier?: string; now?: number; seenNonces?: string[] } = {}) {
    const signed = await this.sign(env, options.by);
    await this.add({ id, description, body: signed.body, expect, verifier: options.verifier, now: options.now, seenNonces: options.seenNonces });
  }

  /** Text-level mutation of a correctly signed base command. */
  async mutated(id: string, description: string, env: Envelope, mutate: (canonical: string) => string, expect: string) {
    const signed = await this.sign(env);
    const text = new TextDecoder().decode(signed.body);
    const changed = mutate(text);
    if (changed === text) throw new Error(`vector ${id}: mutation changed nothing`);
    await this.add({ id, description, body: utf8(changed), expect });
  }

  async raw(id: string, description: string, body: Uint8Array, expect: string) {
    await this.add({ id, description, body, expect });
  }
}

function httpOf(code: string): number {
  const found = ERRORS.find((e) => e.code === code);
  if (!found) throw new Error(`unregistered code ${code}`);
  return found.http;
}

const replaceOnce = (from: string, to: string) => (text: string) => {
  const index = text.indexOf(from);
  if (index < 0) throw new Error(`mutation target not found: ${from}`);
  return text.slice(0, index) + to + text.slice(index + from.length);
};

async function buildCommandVectors(b: Builder): Promise<{ valid: CommandVector[]; invalid: CommandVector[] }> {
  const create = (id: string, payload = createPayload(), overrides: Envelope = {}) => envelope(id, "profile.create", payload, overrides);
  const status = (id: string, overrides: Envelope = {}) => envelope(id, "profile.status", operationPayload(), overrides);
  const revoke = (id: string, overrides: Envelope = {}) => envelope(id, "profile.revoke", operationPayload(), overrides);

  // ---- valid ---------------------------------------------------------------
  await b.valid("valid-create-basic", "profile.create with an ASCII display name, signed by the active key.", await create("valid-create-basic"));
  await b.valid("valid-status-basic", "profile.status for a known operation.", await status("valid-status-basic"));
  await b.valid("valid-revoke-basic", "profile.revoke of a completed operation.", await revoke("valid-revoke-basic"));
  await b.valid(
    "valid-create-rotated-key",
    "profile.create signed by the rotated (successor) key while both keys are trusted.",
    await create("valid-create-rotated-key", createPayload(), { keyId: "web-test-rotated" }),
    { by: "rotated" },
  );
  await b.valid(
    "valid-status-after-rotation",
    "profile.status signed by the rotated key, accepted after the old key was removed.",
    await status("valid-status-after-rotation", { keyId: "web-test-rotated" }),
    { by: "rotated", verifier: "afterRotation" },
  );
  await b.valid(
    "valid-create-unicode",
    "Display name with Latin-1, CJK and an astral emoji: raw UTF-8 in the canonical form, 12 scalar values.",
    await create("valid-create-unicode", createPayload({ displayName: "Café 研究 🤖 agent", idempotencyKey: "idk_fixtureunicode0000000001" })),
  );
  await b.valid(
    "valid-create-escapes",
    "Display name with a quotation mark and a backslash: the only escapes canonical JSON uses here.",
    await create("valid-create-escapes", createPayload({ displayName: 'Ana\'s "lab" \\ notes', idempotencyKey: "idk_fixtureescapes0000000001" })),
  );
  await b.valid(
    "valid-create-64-astral",
    "64 Unicode scalar values that are 128 UTF-16 code units: the limit counts scalars, not UTF-16 units.",
    await create("valid-create-64-astral", createPayload({ displayName: "🤖".repeat(64), idempotencyKey: "idk_fixtureastral00000000001" })),
  );
  await b.valid(
    "valid-create-64-ascii",
    "Exactly 64 ASCII characters (the upper bound).",
    await create("valid-create-64-ascii", createPayload({ displayName: "a".repeat(64), idempotencyKey: "idk_fixtureascii64000000001" })),
  );
  await b.valid(
    "valid-create-zwj-sequence",
    "Emoji ZWJ sequence (U+200D is format, not white space or control): 3 scalars.",
    await create("valid-create-zwj-sequence", createPayload({ displayName: "👩\u200D💻", idempotencyKey: "idk_fixturezwj00000000000001" })),
  );
  await b.valid(
    "valid-create-inner-line-separator",
    "U+2028 is White_Space but allowed inside the name; JCS writes it raw.",
    await create("valid-create-inner-line-separator", createPayload({ displayName: "a\u2028b", idempotencyKey: "idk_fixturels000000000000001" })),
  );
  await b.valid(
    "valid-create-leading-bom-char",
    "Leading U+FEFF is not Unicode White_Space, so it is allowed (JavaScript String.prototype.trim would wrongly strip it).",
    await create("valid-create-leading-bom-char", createPayload({ displayName: "\uFEFFagent", idempotencyKey: "idk_fixturefeff0000000000001" })),
  );
  await b.valid(
    "valid-create-max-lengths",
    "Longest allowed profileId (64), idempotencyKey (128), and a 120-second lifetime.",
    await create(
      "valid-create-max-lengths",
      createPayload({ profileId: `agt_${"z".repeat(60)}`, idempotencyKey: `K${"-_09azAZ".repeat(15)}${"x".repeat(7)}` }),
      { expiresAt: T0 + MAX_COMMAND_LIFETIME_SECONDS },
    ),
  );
  await b.valid(
    "valid-skew-future-boundary",
    "issuedAt exactly MAX_CLOCK_SKEW_SECONDS ahead of the verifier clock is accepted.",
    await status("valid-skew-future-boundary"),
    { now: T0 - MAX_CLOCK_SKEW_SECONDS },
  );
  await b.valid(
    "valid-skew-expiry-boundary",
    "One second before expiresAt + MAX_CLOCK_SKEW_SECONDS is still accepted.",
    await status("valid-skew-expiry-boundary"),
    { now: T0 + 60 + MAX_CLOCK_SKEW_SECONDS - 1 },
  );
  const valid = [...b.vectors];
  b.vectors.length = 0;

  // ---- size and syntax -----------------------------------------------------
  const base = await create("invalid-base");
  const baseText = new TextDecoder().decode((await b.sign(base)).body);
  const padTo = async (id: string, size: number) => {
    const env = await create(id);
    const without = new TextDecoder().decode((await b.sign(env)).body);
    const filler = "x".repeat(size - utf8(without).length + "Research assistant".length);
    return utf8(replaceOnce('"Research assistant"', `"${filler}"`)(without));
  };
  await b.raw("oversized-8193", "Body of 8193 bytes: refused before parsing.", await padTo("oversized-8193", MAX_MESSAGE_BYTES + 1), "PAYLOAD_TOO_LARGE");
  await b.raw("size-boundary-8192", "Body of exactly 8192 bytes passes the size check (and then fails on the name).", await padTo("size-boundary-8192", MAX_MESSAGE_BYTES), "INVALID_DISPLAY_NAME");
  await b.raw("malformed-empty", "Empty body.", new Uint8Array(), "MALFORMED_JSON");
  await b.raw("malformed-truncated", "Truncated JSON text.", utf8(baseText.slice(0, -1)), "MALFORMED_JSON");
  await b.raw("malformed-trailing-comma", "Trailing comma inside the payload object.", utf8(replaceOnce('"template":"assistant"}', '"template":"assistant",}')(baseText)), "MALFORMED_JSON");
  await b.raw("malformed-trailing-garbage", "A second value after the object.", utf8(`${baseText}{}`), "MALFORMED_JSON");
  await b.raw("malformed-single-quotes", "Single-quoted string.", utf8(replaceOnce('"template":"assistant"', "'template':'assistant'")(baseText)), "MALFORMED_JSON");
  await b.raw("malformed-raw-tab-in-string", "Unescaped U+0009 inside a string.", utf8(replaceOnce("Research assistant", "Research\tassistant")(baseText)), "MALFORMED_JSON");
  await b.raw("malformed-leading-zero", "Number with a leading zero.", utf8(replaceOnce(`"issuedAt":${T0}`, `"issuedAt":0${T0}`)(baseText)), "MALFORMED_JSON");
  await b.raw("malformed-plus-sign", "Number with a plus sign.", utf8(replaceOnce(`"issuedAt":${T0}`, `"issuedAt":+${T0}`)(baseText)), "MALFORMED_JSON");
  await b.raw("malformed-lone-surrogate", "Escaped lone high surrogate \\ud800 (not a Unicode scalar value).", utf8(replaceOnce("Research assistant", "Research \\ud800 assistant")(baseText)), "MALFORMED_JSON");
  await b.raw("malformed-lone-low-surrogate", "Escaped lone low surrogate \\udc00.", utf8(replaceOnce("Research assistant", "\\udc00")(baseText)), "MALFORMED_JSON");
  {
    const bytes = utf8(baseText);
    const at = baseText.indexOf("Research") + 1;
    const broken = concatBytes(bytes.subarray(0, at), new Uint8Array([0xc3, 0x28]), bytes.subarray(at + 2));
    await b.raw("malformed-invalid-utf8", "Invalid UTF-8 sequence C3 28 inside the display name.", broken, "MALFORMED_JSON");
    const overlong = concatBytes(bytes.subarray(0, at), new Uint8Array([0xc0, 0xaf]), bytes.subarray(at + 2));
    await b.raw("malformed-overlong-utf8", "Overlong UTF-8 encoding C0 AF.", overlong, "MALFORMED_JSON");
    await b.raw("malformed-utf8-bom", "Body starts with a UTF-8 byte order mark.", concatBytes(new Uint8Array([0xef, 0xbb, 0xbf]), bytes), "MALFORMED_JSON");
  }
  const nest = (levels: number) => `${'{"a":'.repeat(levels)}1${"}".repeat(levels)}`;
  await b.raw(
    "malformed-nesting-17",
    `Nesting depth 17 (> ${MAX_NESTING_DEPTH}) inside an unknown payload member.`,
    utf8(replaceOnce('"template":"assistant"}', `"template":"assistant","zz":${nest(MAX_NESTING_DEPTH - 1)}}`)(baseText)),
    "MALFORMED_JSON",
  );
  await b.raw(
    "nesting-16-unknown-field",
    `Nesting depth exactly ${MAX_NESTING_DEPTH} parses; the extra member is then an unknown field.`,
    utf8(replaceOnce('"template":"assistant"}', `"template":"assistant","zz":${nest(MAX_NESTING_DEPTH - 2)}}`)(baseText)),
    "UNKNOWN_FIELD",
  );

  // ---- duplicate keys ------------------------------------------------------
  await b.raw("duplicate-top-level", "Top-level member \"nonce\" appears twice.", utf8(replaceOnce('"nonce":', `"nonce":"${await nonceFor("other")}","nonce":`)(baseText)), "DUPLICATE_KEY");
  await b.raw("duplicate-top-level-same-value", "Top-level \"operation\" repeated with the same value.", utf8(replaceOnce('"operation":"profile.create"', '"operation":"profile.create","operation":"profile.create"')(baseText)), "DUPLICATE_KEY");
  await b.raw("duplicate-nested", "Payload member \"profileId\" appears twice with different values.", utf8(replaceOnce(`"profileId":"${PROFILE}"`, `"profileId":"agt_fixtureprofile000000000002","profileId":"${PROFILE}"`)(baseText)), "DUPLICATE_KEY");
  await b.raw("duplicate-escaped-name", "\"nonce\" and \"\\u006eonce\" are the same member name after unescaping.", utf8(replaceOnce('"nonce":', `"\\u006eonce":"${await nonceFor("other")}","nonce":`)(baseText)), "DUPLICATE_KEY");

  // ---- JSON value profile --------------------------------------------------
  const issued = (to: string) => replaceOnce(`"issuedAt":${T0}`, `"issuedAt":${to}`);
  await b.mutated("number-fraction", "issuedAt written as 1791000000.0.", base, issued(`${T0}.0`), "INVALID_JSON_VALUE");
  await b.mutated("number-exponent", "issuedAt written as 1.791e9.", base, issued("1.791e9"), "INVALID_JSON_VALUE");
  await b.mutated("number-negative", "Negative issuedAt.", base, issued(`-${T0}`), "INVALID_JSON_VALUE");
  await b.mutated("number-negative-zero", "issuedAt written as -0.", base, issued("-0"), "INVALID_JSON_VALUE");
  await b.mutated("number-above-safe-integer", "issuedAt of 2^53 (above 2^53-1).", base, issued("9007199254740992"), "INVALID_JSON_VALUE");
  await b.mutated("number-huge-exponent", "1e400 (not representable).", base, issued("1e400"), "INVALID_JSON_VALUE");
  await b.mutated("value-null", "displayName is null.", base, replaceOnce('"Research assistant"', "null"), "INVALID_JSON_VALUE");
  await b.mutated("value-boolean", "displayName is true.", base, replaceOnce('"Research assistant"', "true"), "INVALID_JSON_VALUE");
  await b.mutated("value-array", "profileId is an array.", base, replaceOnce(`"profileId":"${PROFILE}"`, `"profileId":["${PROFILE}"]`), "INVALID_JSON_VALUE");
  await b.raw("value-top-level-array", "Top-level array wrapping the command.", utf8(`[${baseText}]`), "INVALID_JSON_VALUE");

  // ---- envelope ------------------------------------------------------------
  await b.raw("envelope-top-level-string", "Top-level JSON string.", utf8('"profile.create"'), "INVALID_ENVELOPE");
  {
    const { protocol: _p, ...noProtocol } = base;
    await b.signedInvalid("envelope-missing-protocol", "No protocol member.", noProtocol, "INVALID_ENVELOPE");
  }
  await b.signedInvalid("protocol-v2", "Unknown protocol version LA-WEB-PROVISIONING/2.", { ...base, protocol: "LA-WEB-PROVISIONING/2" }, "UNSUPPORTED_PROTOCOL");
  await b.signedInvalid("protocol-case", "Protocol identifier compared byte for byte (lowercase is unknown).", { ...base, protocol: "la-web-provisioning/1" }, "UNSUPPORTED_PROTOCOL");
  await b.signedInvalid("unknown-top-level-callback", "Top-level callbackUrl (no callbacks in v1).", { ...base, callbackUrl: "https://lightagent-control.example/callback" }, "UNKNOWN_FIELD");
  await b.signedInvalid("unknown-top-level-permissions", "Top-level permissions object.", { ...base, permissions: { shell: "true" } }, "UNKNOWN_FIELD");
  await b.signedInvalid("unknown-top-level-revocation-version", "Top-level revocationVersion (not part of v1).", { ...base, revocationVersion: 2 }, "UNKNOWN_FIELD");
  {
    const { nonce: _n, ...noNonce } = base;
    await b.raw("missing-signature", "No signature member.", utf8(canonicalize(base)), "MISSING_FIELD");
    await b.signedInvalid("missing-nonce", "No nonce member.", noNonce, "MISSING_FIELD");
  }
  await b.signedInvalid("wrong-purpose-invocation", "purpose agent-invocation (another message type).", { ...base, purpose: "agent-invocation" }, "WRONG_PURPOSE");
  await b.signedInvalid("wrong-purpose-response", "purpose provisioning-response (reserved for signed responses).", { ...base, purpose: "provisioning-response" }, "WRONG_PURPOSE");
  for (const [id, operation] of [
    ["forbidden-profile-disable", "profile.disable"],
    ["forbidden-profile-enable", "profile.enable"],
    ["forbidden-agent-invoke", "agent.invoke"],
    ["unsupported-profile-lookup", "profile.lookup"],
    ["unsupported-operation-case", "PROFILE.CREATE"],
  ] as const) {
    await b.signedInvalid(id, `operation ${operation} is not a v1 operation.`, await envelope(id, operation, operationPayload()), "UNSUPPORTED_OPERATION");
  }
  await b.signedInvalid("type-issued-at-string", "issuedAt as a string.", { ...base, issuedAt: String(T0) }, "INVALID_FIELD");
  await b.signedInvalid("issued-at-milliseconds", "issuedAt in milliseconds (13 digits).", { ...base, issuedAt: T0 * 1000, expiresAt: T0 * 1000 + 60 }, "INVALID_FIELD");
  await b.signedInvalid("audience-url", "audience is a URL, not a harness id.", { ...base, audience: "https://harness.example" }, "INVALID_FIELD");
  await b.signedInvalid("command-id-uppercase", "commandId with uppercase letters.", { ...base, commandId: "cmd_FIXTURE0000000000000000001" }, "INVALID_FIELD");
  await b.signedInvalid("key-id-space", "keyId containing a space.", { ...base, keyId: "web test active" }, "INVALID_FIELD");
  await b.signedInvalid("nonce-short", "Nonce of 16 bytes (22 characters).", { ...base, nonce: toBase64Url(new Uint8Array(16).fill(7)) }, "INVALID_FIELD");
  {
    const nonce = await nonceFor("noncanonical");
    const last = nonce.slice(-1);
    const bumped = String.fromCharCode(last.charCodeAt(0) + 1);
    await b.signedInvalid("nonce-noncanonical-bits", "Nonce whose last character has non-zero padding bits.", { ...base, nonce: nonce.slice(0, -1) + bumped }, "INVALID_FIELD");
    const std = btoa(String.fromCharCode(...(fromBase64Url(nonce) as Uint8Array)));
    await b.signedInvalid("nonce-standard-base64", "Nonce in standard base64 with padding (C9: one encoding per field).", { ...base, nonce: std }, "INVALID_FIELD");
  }
  {
    const good = await b.sign(base);
    const sigBytes = fromBase64Url(good.signature) as Uint8Array;
    const withSig = (signature: string) => utf8(canonicalize({ ...base, signature }));
    await b.raw("signature-standard-base64", "Signature in standard base64 with padding.", withSig(btoa(String.fromCharCode(...sigBytes))), "INVALID_FIELD");
    await b.raw("signature-hex", "Signature in hex.", withSig(toHex(sigBytes)), "INVALID_FIELD");
    const flipped = Uint8Array.from(sigBytes);
    flipped[10] = (flipped[10] as number) ^ 0x01;
    await b.raw("signature-bit-flip", "One bit of R flipped.", withSig(toBase64Url(flipped)), "BAD_SIGNATURE");
    await b.raw("signature-zero", "All-zero signature.", withSig(toBase64Url(new Uint8Array(64))), "BAD_SIGNATURE");
    // S + L encodes the same scalar mod L: valid under a lax verifier, refused by RFC 8032 §5.1.7.
    let s = 0n;
    for (let i = 63; i >= 32; i -= 1) s = (s << 8n) | BigInt(sigBytes[i] as number);
    const sPlusL = s + ED25519_L;
    if (sPlusL >= 1n << 256n) throw new Error("S + L overflows; pick another base vector");
    const malleable = Uint8Array.from(sigBytes);
    let t = sPlusL;
    for (let i = 32; i < 64; i += 1) {
      malleable[i] = Number(t & 0xffn);
      t >>= 8n;
    }
    await b.raw("signature-noncanonical-s", "Malleated signature with S + L (non-canonical scalar).", withSig(toBase64Url(malleable)), "BAD_SIGNATURE");
    const forged = toBase64Url(await signBytes(b.key("untrusted").seed, signingInput(base)));
    await b.raw("signature-forged-untrusted-key", "Signed by an untrusted key but labelled with the active keyId.", withSig(forged), "BAD_SIGNATURE");
    const otherKey = toBase64Url(await signBytes(b.key("rotated").seed, signingInput(base)));
    await b.raw("signature-key-id-mismatch", "Signed by the rotated key but labelled with the active keyId.", withSig(otherKey), "BAD_SIGNATURE");
    const noContext = toBase64Url(await signBytes(b.key("active").seed, utf8(canonicalize(base))));
    await b.raw("signature-missing-context", "Signature over the canonical JSON without the domain-separation prefix.", withSig(noContext), "BAD_SIGNATURE");
    const wrongContext = toBase64Url(await signBytes(b.key("active").seed, signingInput(base, utf8(`${PROTOCOL}\u0000provisioning-response\u0000`))));
    await b.raw("signature-wrong-context", "Signature under the provisioning-response context.", withSig(wrongContext), "BAD_SIGNATURE");
    const insertionOrder = toBase64Url(
      await signBytes(b.key("active").seed, concatBytes(utf8(`${PROTOCOL}\u0000${COMMAND_PURPOSE}\u0000`), utf8(JSON.stringify(base)))),
    );
    await b.raw("signature-over-json-stringify", "Signature over JSON.stringify insertion order instead of JCS bytes.", withSig(insertionOrder), "BAD_SIGNATURE");
    const tampered = utf8(canonicalize({ ...base, payload: createPayload({ displayName: "Research assistant 2" }), signature: good.signature }));
    await b.raw("signature-stale-after-payload-change", "displayName changed after signing.", tampered, "BAD_SIGNATURE");
  }
  {
    const signedForA = await b.sign(base);
    const retargeted = utf8(canonicalize({ ...base, audience: HARNESS_B, signature: signedForA.signature }));
    await b.add({ id: "signature-stale-after-audience-change", description: "audience rewritten from harness A to B after signing, delivered to B.", body: retargeted, verifier: "harnessB", expect: "BAD_SIGNATURE" });
    await b.add({ id: "cross-harness-a-to-b", description: "Command signed for harness A replayed to harness B.", body: signedForA.body, verifier: "harnessB", expect: "WRONG_AUDIENCE" });
    await b.signedInvalid("cross-harness-b-to-a", "Command signed for harness B delivered to harness A.", { ...base, audience: HARNESS_B }, "WRONG_AUDIENCE");
  }
  await b.signedInvalid("key-unknown", "keyId not configured on the harness.", { ...base, keyId: "web-test-untrusted" }, "UNKNOWN_KEY", { by: "untrusted" });
  await b.signedInvalid("key-revoked", "Correct signature by a key the harness marked revoked.", { ...base, keyId: "web-test-revoked" }, "KEY_REVOKED", { by: "revoked" });
  await b.signedInvalid("key-rotated-away", "Signed by the old active key after the harness removed it.", base, "UNKNOWN_KEY", { verifier: "afterRotation" });
  await b.signedInvalid("lifetime-121", "expiresAt - issuedAt = 121 seconds.", { ...base, expiresAt: T0 + MAX_COMMAND_LIFETIME_SECONDS + 1 }, "INVALID_LIFETIME");
  await b.signedInvalid("lifetime-zero", "expiresAt equals issuedAt.", { ...base, expiresAt: T0 }, "INVALID_LIFETIME");
  await b.signedInvalid("lifetime-negative", "expiresAt before issuedAt.", { ...base, expiresAt: T0 - 1 }, "INVALID_LIFETIME");
  await b.signedInvalid("expired", "Verifier clock at expiresAt + MAX_CLOCK_SKEW_SECONDS.", base, "EXPIRED", { now: T0 + 60 + MAX_CLOCK_SKEW_SECONDS });
  await b.signedInvalid("expired-long-ago", "Command delivered an hour after issue.", base, "EXPIRED", { now: T0 + 3600 });
  await b.signedInvalid("future-issued-at", "issuedAt more than MAX_CLOCK_SKEW_SECONDS ahead of the verifier.", base, "NOT_YET_VALID", { now: T0 - MAX_CLOCK_SKEW_SECONDS - 1 });
  await b.signedInvalid("replay-exact-bytes", "Byte-identical copy of a command whose nonce is recorded.", base, "REPLAY_DETECTED", { seenNonces: [base.nonce as string] });
  await b.signedInvalid(
    "replay-reused-nonce",
    "New commandId, same nonce: the nonce alone is the replay key.",
    { ...base, commandId: await commandIdFor("replay-reused-nonce") },
    "REPLAY_DETECTED",
    { seenNonces: [base.nonce as string] },
  );

  // ---- payload -------------------------------------------------------------
  const payloadCase = (id: string, description: string, payload: Record<string, CanonicalValue>, expect: string, operation = "profile.create") =>
    envelope(id, operation, payload).then((env) => b.signedInvalid(id, description, env, expect));
  const forbidden: Array<[string, string, CanonicalValue]> = [
    ["forbidden-payload-permissions", "permissions", { shell: "allow", mcp: "allow" }],
    ["forbidden-payload-tools", "tools", "terminal.run"],
    ["forbidden-payload-workspace-path", "workspacePath", "/srv/lightagent/profiles/other"],
    ["forbidden-payload-cwd", "cwd", "../../etc"],
    ["forbidden-payload-model-url", "modelBaseUrl", "https://attacker.example/v1"],
    ["forbidden-payload-endpoint", "endpoint", "https://harness.example/api"],
    ["forbidden-payload-principal-id", "principalId", PRINCIPAL],
    ["forbidden-payload-owner", "owner", SUBJECT],
    ["forbidden-payload-config", "config", { approval_policy: "never" }],
    ["forbidden-payload-revocation-version", "revocationVersion", 7],
  ];
  for (const [id, field, value] of forbidden) {
    await payloadCase(id, `Payload member ${field} is not allowed.`, createPayload({ [field]: value }), "UNKNOWN_FIELD");
  }
  await payloadCase("forbidden-status-extra-field", "profile.status payload carrying create fields.", { ...operationPayload(), displayName: "x" }, "UNKNOWN_FIELD", "profile.status");
  {
    const { idempotencyKey: _k, ...noKey } = createPayload();
    await payloadCase("create-missing-idempotency-key", "profile.create without idempotencyKey.", noKey, "MISSING_FIELD");
    const { operationId: _o, ...noOperation } = operationPayload();
    await payloadCase("revoke-missing-operation-id", "profile.revoke without operationId (revocation is by operation id).", noOperation, "MISSING_FIELD", "profile.revoke");
  }
  const names: Array<[string, string, string]> = [
    ["display-name-65", "65 ASCII characters.", "a".repeat(65)],
    ["display-name-81", "81 ASCII characters (beyond Web's 80-character agent_name too).", "a".repeat(81)],
    ["display-name-65-astral", "65 astral scalars (130 UTF-16 units).", "🤖".repeat(65)],
    ["display-name-empty", "Empty string.", ""],
    ["display-name-leading-space", "Leading U+0020.", " Research"],
    ["display-name-trailing-ideographic-space", "Trailing U+3000.", "Research\u3000"],
    ["display-name-leading-nbsp", "Leading U+00A0 (White_Space).", "\u00A0Research"],
    ["display-name-trailing-line-separator", "Trailing U+2028.", "Research\u2028"],
    ["display-name-control-bel", "Contains U+0007 (written \\u0007 in canonical JSON).", "Research\u0007"],
    ["display-name-control-del", "Contains U+007F.", "Research\u007F"],
    ["display-name-control-c1", "Contains U+0085 (C1 control).", "Research\u0085x"],
    ["display-name-not-nfc", "e followed by U+0301 COMBINING ACUTE ACCENT (NFD form).", "Cafe\u0301"],
    ["display-name-only-space", "A single U+0020.", " "],
  ];
  for (const [id, description, displayName] of names) {
    await payloadCase(id, `Display name: ${description}`, createPayload({ displayName }), "INVALID_DISPLAY_NAME");
  }
  const profileIds: Array<[string, string, string]> = [
    ["profile-id-default", "The reserved Lightagent name default.", "default"],
    ["profile-id-uppercase", "Uppercase letters.", "agt_FIXTUREPROFILE00000000001"],
    ["profile-id-too-long", "agt_ plus 61 characters (65).", `agt_${"z".repeat(61)}`],
    ["profile-id-path-traversal", "Path traversal.", "../agt_fixtureprofile0000001"],
    ["profile-id-wrong-prefix", "Not an agt_ id.", "usr_fixtureprofile000000000001"],
  ];
  for (const [id, description, profileId] of profileIds) {
    await payloadCase(id, `profileId: ${description}`, createPayload({ profileId }), "INVALID_PROFILE_ID");
  }
  const issuers: Array<[string, string, string]> = [
    ["issuer-http", "http scheme.", "http://lightagent-control.example"],
    ["issuer-trailing-slash", "Trailing slash.", "https://lightagent-control.example/"],
    ["issuer-path", "With a path.", "https://lightagent-control.example/auth"],
    ["issuer-userinfo", "With userinfo.", "https://admin@lightagent-control.example"],
    ["issuer-query", "With a query.", "https://lightagent-control.example?x=1"],
    ["issuer-uppercase-host", "Uppercase host (no case folding).", "https://Lightagent-Control.example"],
    ["issuer-port-out-of-range", "Port 70000.", "https://lightagent-control.example:70000"],
  ];
  for (const [id, description, issuer] of issuers) {
    await payloadCase(id, `issuer: ${description}`, createPayload({ issuer }), "INVALID_ISSUER");
  }
  await payloadCase("subject-free-text", "subject is not a Web usr_ id.", createPayload({ subject: "user-123" }), "INVALID_SUBJECT");
  await payloadCase("subject-email", "subject is an email address (never sent).", createPayload({ subject: "alice@example.com" }), "INVALID_SUBJECT");
  await payloadCase("template-admin", "Template other than assistant.", createPayload({ template: "admin" }), "INVALID_TEMPLATE");
  await payloadCase("idempotency-key-short", "15-character idempotency key.", createPayload({ idempotencyKey: "a".repeat(15) }), "INVALID_IDEMPOTENCY_KEY");
  await payloadCase("idempotency-key-dot", "Contains '.', which Lightagent accepts but the protocol does not.", createPayload({ idempotencyKey: "idk.fixture.000000001" }), "INVALID_IDEMPOTENCY_KEY");
  await payloadCase("operation-id-uppercase", "Uppercase hex operationId.", operationPayload({ operationId: OPERATION_ID.toUpperCase() }), "INVALID_OPERATION_ID", "profile.revoke");
  await payloadCase("operation-id-short", "31 hex digits.", operationPayload({ operationId: OPERATION_ID.slice(1) }), "INVALID_OPERATION_ID", "profile.status");

  // ---- canonical form ------------------------------------------------------
  {
    const env = await create("noncanonical-base", createPayload({ displayName: "Café", idempotencyKey: "idk_fixturenoncanon000000001" }));
    const signed = await b.sign(env);
    const text = new TextDecoder().decode(signed.body);
    const parsed = JSON.parse(text) as Record<string, unknown>;
    await b.raw("noncanonical-pretty", "Indented with whitespace.", utf8(JSON.stringify(parsed, null, 2)), "NON_CANONICAL");
    const reordered = { signature: parsed.signature, ...parsed };
    await b.raw("noncanonical-member-order", "Members not in JCS order.", utf8(JSON.stringify(reordered)), "NON_CANONICAL");
    await b.raw("noncanonical-escaped-unicode", "é written as \\u00e9.", utf8(replaceOnce("Café", "Caf\\u00e9")(text)), "NON_CANONICAL");
    await b.raw("noncanonical-escaped-ascii", "C written as \\u0043.", utf8(replaceOnce("Café", "\\u0043afé")(text)), "NON_CANONICAL");
    await b.raw("noncanonical-escaped-solidus", "Issuer slashes written as \\/.", utf8(replaceOnce("https://", "https:\\/\\/")(text)), "NON_CANONICAL");
    await b.raw("noncanonical-trailing-newline", "Trailing LF after the object.", utf8(`${text}\n`), "NON_CANONICAL");
    await b.raw("noncanonical-leading-space", "Leading U+0020 before the object.", utf8(` ${text}`), "NON_CANONICAL");
  }

  const invalid = [...b.vectors];
  return { valid, invalid };
}

// ---------------------------------------------------------------------------
// Redelivery
// ---------------------------------------------------------------------------

async function buildRedelivery(b: Builder) {
  b.vectors.length = 0;
  const payload = createPayload({ idempotencyKey: "idk_fixtureredelivery00000001" });
  const attempt = async (n: number, issuedAt: number, keyId: string) =>
    envelope(`redelivery-create-${n}`, "profile.create", payload, { issuedAt, expiresAt: issuedAt + 60, keyId });
  const attempts = [
    await attempt(1, T0, "web-test-active"),
    await attempt(2, T0 + 90, "web-test-active"),
    await attempt(3, T0 + 400, "web-test-rotated"),
  ];
  const signers: KeyName[] = ["active", "active", "rotated"];
  for (const [i, env] of attempts.entries()) {
    await b.valid(`redelivery-create-${i + 1}`, `Create transmission ${i + 1} of one logical command.`, env, {
      by: signers[i],
      now: (env.issuedAt as number) + 5,
    });
  }
  const first = await b.sign(attempts[0] as Envelope);
  await b.add({
    id: "redelivery-create-1-replayed",
    description: "Transmission 1's exact bytes received again after it was recorded.",
    body: first.body,
    now: T0 + 20,
    seenNonces: [attempts[0]?.nonce as string],
    expect: "REPLAY_DETECTED",
  });
  const revokes = [
    await envelope("redelivery-revoke-1", "profile.revoke", operationPayload(), { issuedAt: T0 + 1000, expiresAt: T0 + 1060 }),
    await envelope("redelivery-revoke-2", "profile.revoke", operationPayload(), { issuedAt: T0 + 1030, expiresAt: T0 + 1090 }),
  ];
  for (const [i, env] of revokes.entries()) {
    await b.valid(`redelivery-revoke-${i + 1}`, `Revoke transmission ${i + 1} of one logical command.`, env, { now: (env.issuedAt as number) + 5 });
  }
  const vectors = [...b.vectors];

  const asCommand = (v: CommandVector) => ({ ...(v.detail?.command as Envelope), signature: v.detail?.signature }) as unknown as Command;
  const createVectors = vectors.filter((v) => v.id.startsWith("redelivery-create-") && v.detail);
  const hashes = new Set(createVectors.map((v) => v.detail?.payloadHash));
  if (hashes.size !== 1) throw new Error("redelivery payload hashes differ");
  for (const later of createVectors.slice(1)) {
    if (!isValidRedelivery(asCommand(createVectors[0] as CommandVector), asCommand(later))) throw new Error(`${later.id} is not a valid redelivery`);
  }
  const changed = await envelope("redelivery-create-changed", "profile.create", { ...payload, displayName: "Renamed" }, { issuedAt: T0 + 120, expiresAt: T0 + 180 });
  const changedHash = await payloadHash("profile.create", changed.payload as CanonicalValue);
  if (isValidRedelivery(asCommand(createVectors[0] as CommandVector), { ...(changed as unknown as Command), signature: "x" })) {
    throw new Error("a changed payload must not count as a redelivery");
  }

  return {
    description:
      "Redelivery series. Every transmission of one logical command repeats protocol, purpose, operation, jobId, requestId, audience and payload (so idempotencyKey and payloadHash), and renews commandId, nonce, issuedAt, expiresAt and signature. keyId may change across a key rotation.",
    logicalCommands: [
      {
        jobId: "prv_fixturejobcreate000000001",
        operation: "profile.create",
        payloadHash: [...hashes][0],
        transmissions: ["redelivery-create-1", "redelivery-create-2", "redelivery-create-3"],
      },
      {
        jobId: "prv_fixturejobrevoke000000001",
        operation: "profile.revoke",
        payloadHash: vectors.find((v) => v.id === "redelivery-revoke-1")?.detail?.payloadHash,
        transmissions: ["redelivery-revoke-1", "redelivery-revoke-2"],
      },
    ],
    notARedelivery: {
      description:
        "Same jobId and idempotencyKey with a changed displayName. Web must never send this; Lightagent answers IDEMPOTENCY_CONFLICT if it arrives.",
      command: changed,
      payloadHash: changedHash,
      expectedHarnessCode: "IDEMPOTENCY_CONFLICT",
    },
    vectors,
  };
}

// ---------------------------------------------------------------------------
// Responses (§12) and create resolution (§13.2)
// ---------------------------------------------------------------------------

function sentCommand(v: CommandVector | undefined): Command {
  if (!v?.detail) throw new Error("response vectors need a valid request vector");
  return { ...v.detail.command, signature: v.detail.signature } as unknown as Command;
}

async function buildResponses(valid: CommandVector[]) {
  const byId = (id: string) => sentCommand(valid.find((v) => v.id === id));
  const create = byId("valid-create-basic");
  const status = byId("valid-status-basic");
  const revoke = byId("valid-revoke-basic");
  const result = (overrides: Record<string, unknown> = {}) => ({
    operationId: OPERATION_ID,
    state: "completed",
    failure: null,
    principalId: PRINCIPAL,
    profileId: PROFILE,
    template: "assistant",
    ownerBound: true,
    createdUnix: T0 + 1,
    updatedUnix: T0 + 2,
    ...overrides,
  });
  const ok = (sent: Command, r: Record<string, unknown>, replayed?: boolean) => ({
    protocol: PROTOCOL,
    commandId: sent.commandId,
    audience: sent.audience,
    operation: sent.operation,
    ...(replayed === undefined ? {} : { replayed }),
    result: r,
  });
  const err = (sent: Command, code: string, commandId: string | null = sent.commandId) => ({ protocol: PROTOCOL, commandId, code });

  type Case = { id: string; description: string; request: string; sent: Command; http: number; body: string };
  const cases: Case[] = [];
  const add = (id: string, description: string, request: string, sent: Command, http: number, body: unknown) =>
    cases.push({ id, description, request, sent, http, body: typeof body === "string" ? body : JSON.stringify(body) });

  add("create-201-completed", "New operation, completed.", "valid-create-basic", create, 201, ok(create, result(), false));
  add("create-200-replayed-completed", "Same key again after completion: the recorded outcome, not a new binding.", "valid-create-basic", create, 200, ok(create, result(), true));
  add("create-200-replayed-completed-not-owner", "Completed earlier, but the operator has since changed ownership (RC2): valid, needs attention.", "valid-create-basic", create, 200, ok(create, result({ ownerBound: false }), true));
  add("create-200-replayed-revoked", "Same key after revocation (S1): revoked, not re-bound.", "valid-create-basic", create, 200, ok(create, result({ state: "revoked", ownerBound: false }), true));
  add("create-201-failed", "Operation failed on the merits during binding.", "valid-create-basic", create, 201, ok(create, result({ state: "failed", failure: "PRINCIPAL_INACTIVE", ownerBound: false }), false));
  add("create-200-failed-invalid-template", "Recorded operation whose template the harness no longer knows (RC3).", "valid-create-basic", create, 200, ok(create, result({ state: "failed", failure: "INVALID_TEMPLATE", ownerBound: false }), true));
  add("create-401-expired-at-execution", "Admitted in time but reached the ledger lock after its execution deadline (§10 step 14): no effect.", "valid-create-basic", create, 401, err(create, "EXPIRED"));
  add("status-200-completed", "Status of a completed operation.", "valid-status-basic", status, 200, ok(status, result()));
  add("status-200-profile-created", "Interrupted create (profile staged, not bound); status does not advance it.", "valid-status-basic", status, 200, ok(status, result({ state: "profile_created", ownerBound: false })));
  add("status-200-pending", "Interrupted create recorded as pending.", "valid-status-basic", status, 200, ok(status, result({ state: "pending", ownerBound: false })));
  add("status-200-profile-created-owner-bound", "Crash after the identity commit: bound, ledger not yet completed (RC2, informational).", "valid-status-basic", status, 200, ok(status, result({ state: "profile_created", ownerBound: true })));
  add("status-200-completed-not-owner", "Completed, ownership since changed by the operator (RC2).", "valid-status-basic", status, 200, ok(status, result({ ownerBound: false })));
  add("status-200-failed-owner-bound", "Failed operation whose principal owns the profile through a later operation (RC2, informational).", "valid-status-basic", status, 200, ok(status, result({ state: "failed", failure: "PROFILE_UNAVAILABLE", ownerBound: true })));
  add("status-200-revoked-owner-bound", "Revoked, but the principal owns the profile again (operator action): unexpected binding.", "valid-status-basic", status, 200, ok(status, result({ state: "revoked", ownerBound: true })));
  add("revoke-200-revoked", "Revocation recorded.", "valid-revoke-basic", revoke, 200, ok(revoke, result({ state: "revoked", ownerBound: false, updatedUnix: T0 + 900 })));
  add("create-409-profile-unavailable", "Refused on the merits; no operation exists for this key.", "valid-create-basic", create, 409, err(create, "PROFILE_UNAVAILABLE"));
  add("create-401-unauthenticated", "Local admission refused.", "valid-create-basic", create, 401, err(create, "UNAUTHENTICATED"));
  add("create-400-malformed-null-command-id", "Refused before the envelope was understood; commandId null.", "valid-create-basic", create, 400, err(create, "MALFORMED_JSON", null));
  add("create-503-storage-unavailable", "Storage failure: the operation may exist.", "valid-create-basic", create, 503, err(create, "STORAGE_UNAVAILABLE"));
  add("create-409-replay-detected", "A duplicated copy of this transmission may have executed.", "valid-create-basic", create, 409, err(create, "REPLAY_DETECTED"));
  add("status-404-unknown-operation", "Operation unknown to this provisioner.", "valid-status-basic", status, 404, err(status, "UNKNOWN_OPERATION"));
  add("revoke-409-in-progress", "Create still running; retry later.", "valid-revoke-basic", revoke, 409, err(revoke, "OPERATION_IN_PROGRESS"));
  add("revoke-409-ownership-changed", "Operator reassigned the profile.", "valid-revoke-basic", revoke, 409, err(revoke, "OWNERSHIP_CHANGED"));
  // invalid → uncertain
  add("invalid-command-id-mismatch", "commandId of another command.", "valid-create-basic", create, 201, { ...ok(create, result(), false), commandId: status.commandId });
  add("invalid-audience-mismatch", "Answer claims to come from harness B.", "valid-create-basic", create, 201, { ...ok(create, result(), false), audience: HARNESS_B });
  add("invalid-profile-mismatch", "result.profileId differs from the request.", "valid-create-basic", create, 201, ok(create, result({ profileId: "agt_fixtureprofile000000000002" }), false));
  add("invalid-create-nonterminal-pending", "A create answered with a non-terminal state (create responses are terminal, CL1).", "valid-create-basic", create, 200, ok(create, result({ state: "pending", ownerBound: false }), true));
  add("invalid-create-nonterminal-profile-created", "A create answered with profile_created.", "valid-create-basic", create, 201, ok(create, result({ state: "profile_created", ownerBound: true }), false));
  add("invalid-failure-unregistered", "Failure code outside the registry.", "valid-create-basic", create, 201, ok(create, result({ state: "failed", failure: "TEMPLATE_GONE", ownerBound: false }), false));
  add("invalid-failure-lowercase", "Failure code not uppercased.", "valid-create-basic", create, 201, ok(create, result({ state: "failed", failure: "principal_inactive", ownerBound: false }), false));
  add("invalid-failed-without-code", "state failed with failure null.", "valid-create-basic", create, 201, ok(create, result({ state: "failed", ownerBound: false }), false));
  add("invalid-201-replayed", "HTTP 201 with replayed true.", "valid-create-basic", create, 201, ok(create, result(), true));
  add("invalid-http-202", "HTTP 202 is never a protocol answer.", "valid-create-basic", create, 202, ok(create, result(), false));
  add("invalid-duplicate-key", "Duplicate state member.", "valid-status-basic", status, 200, JSON.stringify(ok(status, result())).replace('"state":"completed"', '"state":"revoked","state":"completed"'));
  add("invalid-unknown-result-field", "Extra member in result.", "valid-status-basic", status, 200, ok(status, { ...result(), callbackUrl: "https://x.example" }));
  add("invalid-unregistered-code", "Error code not in the registry.", "valid-create-basic", create, 400, err(create, "SOMETHING_ELSE"));
  add("invalid-code-http-mismatch", "QUOTA_EXCEEDED with HTTP 409 (registry says 403).", "valid-create-basic", create, 409, err(create, "QUOTA_EXCEEDED"));
  add("invalid-code-wrong-operation", "A create-only code answering profile.status.", "valid-status-basic", status, 403, err(status, "QUOTA_EXCEEDED"));
  add("invalid-revoke-completed", "Revoke answered with a completed operation.", "valid-revoke-basic", revoke, 200, ok(revoke, result()));
  add("invalid-status-other-operation", "Status of a different operation id.", "valid-status-basic", status, 200, ok(status, result({ operationId: "ffffffffffffffffffffffffffffffff" })));
  add("invalid-html-502", "Proxy error page.", "valid-create-basic", create, 502, "<html>Bad gateway</html>");
  add("invalid-oversized", "Body above 8 KiB.", "valid-status-basic", status, 200, JSON.stringify(ok(status, result())) + " ".repeat(MAX_MESSAGE_BYTES));
  add("invalid-updated-before-created", "updatedUnix < createdUnix.", "valid-status-basic", status, 200, ok(status, result({ updatedUnix: T0 })));
  add("invalid-float-timestamp", "createdUnix written as a float.", "valid-status-basic", status, 200, JSON.stringify(ok(status, result())).replace(`"createdUnix":${T0 + 1}`, `"createdUnix":${T0 + 1}.0`));
  add("invalid-protocol", "Different protocol identifier.", "valid-status-basic", status, 200, { ...ok(status, result()), protocol: "LA-WEB-PROVISIONING/2" });

  return cases.map((c) => {
    const outcome = classifyResponse(c.http, utf8(c.body), c.sent);
    const ownership = outcome.kind === "operation" ? { ownership: assessOwnership(outcome.result) } : {};
    return { id: c.id, description: c.description, request: c.request, httpStatus: c.http, body: c.body, expect: { ...outcome, ...ownership } };
  });
}

function buildResolution() {
  const tx = (issuedAt: number, outcome: Transmission["outcome"]): Transmission => ({ issuedAt, expiresAt: issuedAt + 60, outcome });
  const op = (state: OperationState = "completed", operationId = OPERATION_ID) =>
    ({ kind: "operation", operationId, state }) as const;
  const refused = (code: string) => ({ kind: "refused", code }) as const;
  const uncertain = { kind: "uncertain" } as const;
  const H = 60 + ACCEPTANCE_HORIZON_SECONDS;
  const cases: Array<{ id: string; description: string; transmissions: Transmission[] }> = [
    { id: "no-transmission", description: "Nothing sent yet.", transmissions: [] },
    { id: "single-completed", description: "First transmission returns a completed operation.", transmissions: [tx(T0, op())] },
    { id: "timeout-then-operation", description: "Timeout, then the same key returns the operation.", transmissions: [tx(T0, uncertain), tx(T0 + 30, op())] },
    { id: "timeouts-exhausted", description: "Ten timeouts: still unresolved, never failed.", transmissions: Array.from({ length: 10 }, (_, i) => tx(T0 + i * 30, uncertain)) },
    { id: "replay-detected-only", description: "Only a REPLAY_DETECTED answer (indeterminate).", transmissions: [tx(T0, uncertain)] },
    { id: "single-merits-refusal", description: "Only transmission refused with PROFILE_UNAVAILABLE.", transmissions: [tx(T0, refused("PROFILE_UNAVAILABLE"))] },
    { id: "single-admission-refusal", description: "Only transmission refused with UNAUTHENTICATED.", transmissions: [tx(T0, refused("UNAUTHENTICATED"))] },
    { id: "timeout-then-merits-too-early", description: "Timeout, then QUOTA_EXCEEDED sent before the first copy's horizon.", transmissions: [tx(T0, uncertain), tx(T0 + 30, refused("QUOTA_EXCEEDED"))] },
    { id: "timeout-then-merits-after-horizon", description: "Timeout, then QUOTA_EXCEEDED sent after the first copy's horizon.", transmissions: [tx(T0, uncertain), tx(T0 + H, refused("QUOTA_EXCEEDED"))] },
    { id: "lock-wait-horizon-minus-one", description: "Timeout, then QUOTA_EXCEEDED issued one second before the horizon: the first copy may still start under the lock.", transmissions: [tx(T0, uncertain), tx(T0 + H - 1, refused("QUOTA_EXCEEDED"))] },
    { id: "lock-wait-horizon-exact", description: "Timeout, then QUOTA_EXCEEDED issued exactly at the horizon: safe only because §10 step 14 refuses the first copy if it reaches the lock later.", transmissions: [tx(T0, uncertain), tx(T0 + H, refused("QUOTA_EXCEEDED"))] },
    { id: "expired-at-execution-then-operation", description: "Timeout, EXPIRED at execution, then a fresh transmission returns the committed operation.", transmissions: [tx(T0, uncertain), tx(T0 + 30, refused("EXPIRED")), tx(T0 + 60, op())] },
    { id: "expired-at-execution-after-uncertain", description: "Timeout, then EXPIRED (protocol class): proves nothing about the first copy.", transmissions: [tx(T0, uncertain), tx(T0 + H, refused("EXPIRED"))] },
    { id: "timeout-then-admission-after-horizon", description: "Timeout, then UNAUTHENTICATED: admission happens before the idempotency lookup, so it proves nothing.", transmissions: [tx(T0, uncertain), tx(T0 + H, refused("UNAUTHENTICATED"))] },
    { id: "timeout-then-protocol-after-horizon", description: "Timeout, then BAD_SIGNATURE: a per-transmission refusal proves nothing.", transmissions: [tx(T0, uncertain), tx(T0 + H, refused("BAD_SIGNATURE"))] },
    { id: "timeout-then-payload-refusal", description: "Timeout, then INVALID_DISPLAY_NAME: the same payload can never succeed.", transmissions: [tx(T0, uncertain), tx(T0 + 30, refused("INVALID_DISPLAY_NAME"))] },
    { id: "operation-failed", description: "Timeout, then an operation in state failed (definitive).", transmissions: [tx(T0, uncertain), tx(T0 + 30, op("failed"))] },
    { id: "elapsed-time-alone", description: "One uncertain transmission and a day of silence: elapsed time alone never resolves a create.", transmissions: [tx(T0, uncertain)] },
    { id: "operation-revoked-replay", description: "Redelivery after revocation returns the revoked operation (S1).", transmissions: [tx(T0, uncertain), tx(T0 + 30, op("revoked"))] },
    { id: "idempotency-conflict", description: "IDEMPOTENCY_CONFLICT is a Web defect, never a failure.", transmissions: [tx(T0, uncertain), tx(T0 + 30, refused("IDEMPOTENCY_CONFLICT"))] },
    { id: "operation-mismatch", description: "Two different operation ids for one key.", transmissions: [tx(T0, op()), tx(T0 + 30, op("completed", "ffffffffffffffffffffffffffffffff"))] },
  ];
  return cases.map((c) => ({ ...c, expect: resolveCreateJob(c.transmissions) }));
}

// ---------------------------------------------------------------------------
// Execution deadline (§10 step 14) and lock-wait races
// ---------------------------------------------------------------------------

function buildExecutionDeadline(valid: CommandVector[]) {
  const command = sentCommand(valid.find((v) => v.id === "valid-create-basic"));
  const deadline = executionDeadline(command);
  const deadlineCases = [
    { id: "lock-at-issue", description: "Lock acquired immediately.", admittedAt: T0 + 1, lockAcquiredAt: T0 + 1 },
    { id: "lock-one-second-before-deadline", description: "Admitted in time; lock acquired at expiresAt + 29.", admittedAt: T0 + 10, lockAcquiredAt: deadline - 1 },
    { id: "lock-at-deadline", description: "Admitted in time; lock acquired exactly at expiresAt + 30.", admittedAt: T0 + 10, lockAcquiredAt: deadline },
    { id: "admitted-at-last-second-lock-after", description: "Admission passes at expiresAt + 29; the lock is acquired two seconds later.", admittedAt: deadline - 1, lockAcquiredAt: deadline + 1 },
    { id: "lock-after-long-wait", description: "Admitted at once, then waited ten minutes for the lock.", admittedAt: T0 + 1, lockAcquiredAt: T0 + 600 },
  ].map((c) => ({ ...c, command: "valid-create-basic", executionDeadline: deadline, expect: checkExecutionDeadline(command, c.lockAcquiredAt) }));

  const ALWAYS: Array<[number, number]> = [[0, Number.MAX_SAFE_INTEGER]];
  const races: Array<{ id: string; description: string; scenario: Omit<RaceScenario, "executionDeadlineCheck"> }> = [
    {
      id: "lock-wait-race",
      description:
        "Transmission 1 passes admission at T0+5, its response is lost, and it waits for the ledger lock until T0+200. Transmission 2, issued at the horizon, is refused QUOTA_EXCEEDED. Quota frees at T0+150. Without step 14 the first copy binds the user after Web concluded failed.",
      scenario: {
        attempts: [
          { issuedAt: T0, expiresAt: T0 + 60, admittedAt: T0 + 5, lockAcquiredAt: T0 + 200, responseLost: true },
          { issuedAt: T0 + 120, expiresAt: T0 + 180, admittedAt: T0 + 121, lockAcquiredAt: T0 + 121, releasedAt: T0 + 122 },
        ],
        quotaAvailable: [[T0 + 150, Number.MAX_SAFE_INTEGER]],
      },
    },
    {
      id: "begun-before-deadline-completes-late",
      description:
        "Transmission 1 acquires the lock before its deadline and holds it until T0+400 (slow commit). Expiry bounds only the start of execution, not completion; serialization makes the later transmission run after it and return the operation.",
      scenario: {
        attempts: [
          { issuedAt: T0, expiresAt: T0 + 60, admittedAt: T0 + 5, lockAcquiredAt: T0 + 80, releasedAt: T0 + 400, responseLost: true },
          { issuedAt: T0 + 380, expiresAt: T0 + 440, admittedAt: T0 + 381, lockAcquiredAt: T0 + 400 },
        ],
        quotaAvailable: ALWAYS,
      },
    },
    {
      id: "crash-after-record-then-resend",
      description: "Transmission 1 records the operation and fails with STORAGE_UNAVAILABLE; the quota is then exhausted. The resend hits the idempotency ledger and completes the recorded operation.",
      scenario: {
        attempts: [
          { issuedAt: T0, expiresAt: T0 + 60, admittedAt: T0 + 1, crashAfterRecord: true },
          { issuedAt: T0 + 120, expiresAt: T0 + 180, admittedAt: T0 + 121 },
        ],
        quotaAvailable: [[T0, T0 + 2]],
      },
    },
    {
      id: "delayed-past-admission",
      description: "Transmission 1 is delayed in the network and arrives after expiresAt + 30: EXPIRED at admission in both modes.",
      scenario: {
        attempts: [
          { issuedAt: T0, expiresAt: T0 + 60, admittedAt: T0 + 95, responseLost: true },
          { issuedAt: T0 + 120, expiresAt: T0 + 180, admittedAt: T0 + 121 },
        ],
        quotaAvailable: [[T0 + 150, Number.MAX_SAFE_INTEGER]],
      },
    },
    {
      id: "merits-before-horizon",
      description: "A merits refusal issued before the first copy's horizon never resolves the job, with or without step 14.",
      scenario: {
        attempts: [
          { issuedAt: T0, expiresAt: T0 + 60, admittedAt: T0 + 5, lockAcquiredAt: T0 + 100, responseLost: true },
          { issuedAt: T0 + 30, expiresAt: T0 + 90, admittedAt: T0 + 31 },
        ],
        quotaAvailable: [[T0 + 90, Number.MAX_SAFE_INTEGER]],
      },
    },
  ];
  return {
    executionDeadlineSeconds: "expiresAt + MAX_CLOCK_SKEW_SECONDS, harness clock read after acquiring the ledger lock",
    deadlineCases,
    races: races.map((r) => ({
      ...r,
      withExecutionDeadline: simulateCreateRace({ ...r.scenario, executionDeadlineCheck: true }),
      withoutExecutionDeadline: simulateCreateRace({ ...r.scenario, executionDeadlineCheck: false }),
    })),
  };
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

/** Every fixture file (path → content) except the manifest files. */
export async function buildFixtureFiles(): Promise<Map<string, string>> {
  const keys = await loadKeys();
  const states = verifierStates(keys);
  const b = new Builder(keys, states);
  const { valid, invalid } = await buildCommandVectors(b);
  const redelivery = await buildRedelivery(b);
  const files = new Map<string, string>();
  const header = (kind: string) => ({ protocol: PROTOCOL, fixtureSet: FIXTURE_SET, kind });

  files.set(
    `${FIXTURE_DIR}/keys.json`,
    json({
      ...header("keys"),
      warning: "TEST-ONLY. Every seed is SHA-256 of a public label. Never trust these keys on any real harness.",
      derivation: "seed = SHA-256(UTF-8 label); publicKey = Ed25519 public key of seed (RFC 8032).",
      encodings: { seedHex: "lowercase hex, 32 bytes", publicKey: "base64url without padding, 32 bytes (wire/config form)", publicKeyHex: "lowercase hex, 32 bytes" },
      keys: await Promise.all(
        KEY_SPECS.map(async (spec) => ({
          name: spec.name,
          keyId: spec.keyId,
          description: spec.description,
          label: `${PROTOCOL} TEST-ONLY signing key: ${spec.name}`,
          seedHex: toHex(keys[spec.name].seed),
          publicKey: toBase64Url(keys[spec.name].publicKey),
          publicKeyHex: toHex(keys[spec.name].publicKey),
        })),
      ),
      verifierStates: states,
      constants: {
        maxMessageBytes: MAX_MESSAGE_BYTES,
        maxNestingDepth: MAX_NESTING_DEPTH,
        maxCommandLifetimeSeconds: MAX_COMMAND_LIFETIME_SECONDS,
        maxClockSkewSeconds: MAX_CLOCK_SKEW_SECONDS,
        acceptanceHorizonSeconds: ACCEPTANCE_HORIZON_SECONDS,
        signingContextHex: toHex(utf8(`${PROTOCOL}\u0000${COMMAND_PURPOSE}\u0000`)),
      },
    }),
  );
  const vectorFile = (kind: string, description: string, vectors: CommandVector[]) =>
    json({
      ...header(kind),
      description,
      howToRun:
        "For each vector: build the verifier state named by `verifier` from keys.json, set its clock to `now` and its recorded nonces to `seenNonces`, then verify the bytes of `bodyHex`. The result must be `expect` exactly (ok, or the first failing error code in §10 order).",
      vectors,
    });
  files.set(`${FIXTURE_DIR}/commands-valid.json`, vectorFile("commands-valid", "Correctly signed canonical commands that every verifier must accept.", valid));
  files.set(`${FIXTURE_DIR}/commands-invalid.json`, vectorFile("commands-invalid", "Commands every verifier must refuse with exactly the listed code.", invalid));
  files.set(`${FIXTURE_DIR}/redelivery.json`, json({ ...header("redelivery"), ...redelivery }));
  files.set(
    `${FIXTURE_DIR}/responses.json`,
    json({
      ...header("responses"),
      description:
        "How Web classifies a harness answer to the command named by `request` (from commands-valid.json). `body` is the exact UTF-8 response body. Lightagent's gateway must only produce bodies that classify as `operation` or `refused`.",
      vectors: await buildResponses(valid),
    }),
  );
  files.set(
    `${FIXTURE_DIR}/create-resolution.json`,
    json({
      ...header("create-resolution"),
      description: "What Web may conclude about one profile.create job from all its transmissions (§13.2). Times are Web-clock Unix seconds.",
      acceptanceHorizonSeconds: ACCEPTANCE_HORIZON_SECONDS,
      cases: buildResolution(),
    }),
  );
  files.set(
    `${FIXTURE_DIR}/execution-deadline.json`,
    json({
      ...header("execution-deadline"),
      description:
        "§10 step 14 for profile.create: after acquiring the ledger lock and before the idempotency lookup, the harness refuses EXPIRED when now ≥ expiresAt + 30. `deadlineCases` are single checks; `races` model one harness serving one job (calls serialized by the ledger lock) with and without step 14. `unsafe` means Web concluded failed while an operation exists.",
      ...buildExecutionDeadline(valid),
    }),
  );
  files.set(
    `${FIXTURE_DIR}/errors.json`,
    json({
      ...header("errors"),
      description: "Normative error registry (§11). `lightagent` lists the existing Lightagent codes each maps from; `gateway` marks codes the signed-command gateway introduces.",
      errors: ERRORS,
      operationFailureCodes: FAILURE_CODES,
      operationStates: OPERATION_STATES,
    }),
  );
  return files;
}

/** MANIFEST.json and MANIFEST.sha256 for the fixture files plus the specification. */
export async function buildManifest(files: Map<string, string>, spec: Uint8Array): Promise<Map<string, string>> {
  const entries = await Promise.all(
    [...files.entries()]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(async ([path, content]) => ({ path, bytes: utf8(content).length, sha256: await sha256Hex(utf8(content)) })),
  );
  const fixtureDigest = await sha256Hex(utf8(entries.map((e) => `${e.sha256}  ${e.path}\n`).join("")));
  const specEntry = { path: SPEC_PATH, bytes: spec.length, sha256: await sha256Hex(spec) };
  const manifest = {
    protocol: PROTOCOL,
    fixtureSet: FIXTURE_SET,
    specification: specEntry,
    schemas: SCHEMA_IDS,
    fixtureIds: Object.fromEntries(
      [...files.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([path, content]) => {
        const parsed = JSON.parse(content) as Record<string, unknown>;
        const lists = ["vectors", "cases", "deadlineCases", "races"].flatMap((key) => (Array.isArray(parsed[key]) ? (parsed[key] as Array<{ id: string }>) : []));
        return [path, lists.map((v) => v.id)];
      }),
    ),
    files: entries,
    fixtureDigest,
    compatibilityDigest: "SHA-256 of this file's exact bytes (MANIFEST.json); recorded in ACCEPTANCE.md, not here.",
  };
  const manifestText = json(manifest);
  const sums = [specEntry, ...entries, { path: `${FIXTURE_DIR}/MANIFEST.json`, sha256: await sha256Hex(utf8(manifestText)) }]
    .map((e) => `${e.sha256}  ${e.path}\n`)
    .join("");
  return new Map([
    [`${FIXTURE_DIR}/MANIFEST.json`, manifestText],
    [`${FIXTURE_DIR}/MANIFEST.sha256`, sums],
  ]);
}

export async function compatibilityDigest(manifestText: string): Promise<string> {
  return sha256Hex(utf8(manifestText));
}
