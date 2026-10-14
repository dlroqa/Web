/**
 * LA-WEB-PROVISIONING/1 reference codec. TEST-ONLY: nothing in src/ imports
 * this, and no Worker route, binding, or secret uses it.
 *
 * The normative text is docs/PROVISIONING_PROTOCOL.md. This module exists so
 * the shared fixtures in protocol/la-web-provisioning-1/ are generated and
 * checked by code that follows the specification step by step. It uses only
 * Web-standard APIs (TextEncoder/TextDecoder, crypto.subtle), so it runs
 * unchanged in workerd (tests) and Node (fixture generator).
 *
 * Section numbers in comments (§n) refer to the specification.
 */

export const PROTOCOL = "LA-WEB-PROVISIONING/1";
export const COMMAND_PURPOSE = "provisioning-command";
export const OPERATIONS = ["profile.create", "profile.status", "profile.revoke"] as const;
export type Operation = (typeof OPERATIONS)[number];

export const MAX_MESSAGE_BYTES = 8192;
export const MAX_NESTING_DEPTH = 16;
export const MAX_COMMAND_LIFETIME_SECONDS = 120;
export const MAX_CLOCK_SKEW_SECONDS = 30;
/** A delayed copy of a command can be accepted until expiresAt + this (Web clock), §9.3. */
export const ACCEPTANCE_HORIZON_SECONDS = 2 * MAX_CLOCK_SKEW_SECONDS;
export const TEMPLATE = "assistant";

const encoder = new TextEncoder();

// ---------------------------------------------------------------------------
// §4.2 Strict JSON parsing
// ---------------------------------------------------------------------------

export type JsonValue =
  | { kind: "object"; members: Array<[string, JsonValue]> }
  | { kind: "array"; items: JsonValue[] }
  | { kind: "string"; value: string }
  | { kind: "number"; lexeme: string }
  | { kind: "true" }
  | { kind: "false" }
  | { kind: "null" };

export type ParseResult = { ok: true; value: JsonValue } | { ok: false; code: "MALFORMED_JSON" | "DUPLICATE_KEY" };

class Malformed extends Error {}

/**
 * RFC 8259 parser that keeps number lexemes, rejects invalid UTF-8, a BOM,
 * lone surrogate escapes, and nesting deeper than MAX_NESTING_DEPTH, and
 * reports duplicate member names (compared after unescaping) only once the
 * whole text is known to be well-formed, so MALFORMED_JSON always wins.
 */
export function parseStrictJson(bytes: Uint8Array): ParseResult {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { ok: false, code: "MALFORMED_JSON" };
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { ok: false, code: "MALFORMED_JSON" };
  }
  let pos = 0;
  let duplicate = false;

  const ws = () => {
    while (pos < text.length) {
      const c = text.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos += 1;
      else break;
    }
  };
  const expect = (literal: string) => {
    if (text.slice(pos, pos + literal.length) !== literal) throw new Malformed();
    pos += literal.length;
  };
  const hex4 = (): number => {
    const digits = text.slice(pos, pos + 4);
    if (!/^[0-9A-Fa-f]{4}$/.test(digits)) throw new Malformed();
    pos += 4;
    return Number.parseInt(digits, 16);
  };
  const string = (): string => {
    expect('"');
    let out = "";
    for (;;) {
      if (pos >= text.length) throw new Malformed();
      const c = text.charCodeAt(pos);
      if (c === 0x22) {
        pos += 1;
        return out;
      }
      if (c < 0x20) throw new Malformed();
      if (c !== 0x5c) {
        out += text[pos];
        pos += 1;
        continue;
      }
      pos += 1;
      const e = text[pos];
      pos += 1;
      switch (e) {
        case '"': out += '"'; break;
        case "\\": out += "\\"; break;
        case "/": out += "/"; break;
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        case "u": {
          const unit = hex4();
          if (unit >= 0xdc00 && unit <= 0xdfff) throw new Malformed();
          if (unit >= 0xd800 && unit <= 0xdbff) {
            expect("\\u");
            const low = hex4();
            if (low < 0xdc00 || low > 0xdfff) throw new Malformed();
            out += String.fromCharCode(unit, low);
          } else {
            out += String.fromCharCode(unit);
          }
          break;
        }
        default:
          throw new Malformed();
      }
    }
  };
  const number = (): string => {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(pos));
    if (!match) throw new Malformed();
    pos += match[0].length;
    return match[0];
  };
  const value = (depth: number): JsonValue => {
    ws();
    const c = text[pos];
    if (c === "{") {
      if (depth + 1 > MAX_NESTING_DEPTH) throw new Malformed();
      pos += 1;
      const members: Array<[string, JsonValue]> = [];
      const seen = new Set<string>();
      ws();
      if (text[pos] === "}") {
        pos += 1;
        return { kind: "object", members };
      }
      for (;;) {
        ws();
        const key = string();
        if (seen.has(key)) duplicate = true;
        seen.add(key);
        ws();
        expect(":");
        members.push([key, value(depth + 1)]);
        ws();
        if (text[pos] === ",") {
          pos += 1;
          continue;
        }
        expect("}");
        return { kind: "object", members };
      }
    }
    if (c === "[") {
      if (depth + 1 > MAX_NESTING_DEPTH) throw new Malformed();
      pos += 1;
      const items: JsonValue[] = [];
      ws();
      if (text[pos] === "]") {
        pos += 1;
        return { kind: "array", items };
      }
      for (;;) {
        items.push(value(depth + 1));
        ws();
        if (text[pos] === ",") {
          pos += 1;
          continue;
        }
        expect("]");
        return { kind: "array", items };
      }
    }
    if (c === '"') return { kind: "string", value: string() };
    for (const literal of ["true", "false", "null"] as const) {
      if (text.startsWith(literal, pos)) {
        pos += literal.length;
        return { kind: literal };
      }
    }
    return { kind: "number", lexeme: number() };
  };

  try {
    const root = value(0);
    ws();
    if (pos !== text.length) throw new Malformed();
    return duplicate ? { ok: false, code: "DUPLICATE_KEY" } : { ok: true, value: root };
  } catch (error) {
    if (error instanceof Malformed) return { ok: false, code: "MALFORMED_JSON" };
    throw error;
  }
}

const CANONICAL_INTEGER = /^(?:0|[1-9][0-9]*)$/;

/** §4.3: only objects, strings, and non-negative safe integers. */
export function isCommandValueProfile(value: JsonValue): boolean {
  switch (value.kind) {
    case "object":
      return value.members.every(([, member]) => isCommandValueProfile(member));
    case "string":
      return true;
    case "number":
      return CANONICAL_INTEGER.test(value.lexeme) && BigInt(value.lexeme) <= BigInt(Number.MAX_SAFE_INTEGER);
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// §5 Canonical bytes: RFC 8785 (JCS)
// ---------------------------------------------------------------------------

/** JCS string escaping (RFC 8785 §3.2.2.2). */
function jcsString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const cp = ch.codePointAt(0) as number;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (cp === 0x08) out += "\\b";
    else if (cp === 0x09) out += "\\t";
    else if (cp === 0x0a) out += "\\n";
    else if (cp === 0x0c) out += "\\f";
    else if (cp === 0x0d) out += "\\r";
    else if (cp < 0x20) out += `\\u${cp.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return `${out}"`;
}

/** UTF-16 code-unit order, as RFC 8785 §3.2.3 requires. */
function compareUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** JCS serialization of a parsed value (numbers via ECMAScript Number → string, RFC 8785 §3.2.2.3). */
export function canonicalizeParsed(value: JsonValue): string {
  switch (value.kind) {
    case "object":
      return `{${[...value.members]
        .sort(([a], [b]) => compareUtf16(a, b))
        .map(([key, member]) => `${jcsString(key)}:${canonicalizeParsed(member)}`)
        .join(",")}}`;
    case "array":
      return `[${value.items.map(canonicalizeParsed).join(",")}]`;
    case "string":
      return jcsString(value.value);
    case "number":
      return String(Number(value.lexeme));
    default:
      return value.kind;
  }
}

/** Values a command may contain (§4.3). */
export type CanonicalValue = string | number | { readonly [key: string]: CanonicalValue };

/** JCS serialization of a command value built in code. Throws outside the §4.3 subset. */
export function canonicalize(value: CanonicalValue): string {
  if (typeof value === "string") return jcsString(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("only non-negative safe integers");
    return String(value);
  }
  return `{${Object.keys(value)
    .sort(compareUtf16)
    .map((key) => `${jcsString(key)}:${canonicalize(value[key] as CanonicalValue)}`)
    .join(",")}}`;
}

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** §6.1 domain-separation prefix: "LA-WEB-PROVISIONING/1" NUL "provisioning-command" NUL. */
export const SIGNING_CONTEXT = utf8(`${PROTOCOL}\u0000${COMMAND_PURPOSE}\u0000`);

/** §6.1 The exact bytes Ed25519 signs: context ‖ JCS(envelope without `signature`). */
export function signingInput(unsigned: Readonly<Record<string, CanonicalValue>>, context: Uint8Array = SIGNING_CONTEXT): Uint8Array {
  if ("signature" in unsigned) throw new TypeError("signing input excludes the signature member");
  return concatBytes(context, utf8(canonicalize(unsigned)));
}

// ---------------------------------------------------------------------------
// Encodings (§4.5)
// ---------------------------------------------------------------------------

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) throw new TypeError("lowercase hex expected");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** RFC 4648 §5 base64url without padding. */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict base64url (no padding, canonical trailing bits); null when invalid. */
export function fromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return null;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return toBase64Url(bytes) === value ? bytes : null;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

// ---------------------------------------------------------------------------
// Field rules (§7, §8)
// ---------------------------------------------------------------------------

const idPattern = (prefix: string) => new RegExp(`^${prefix}_[a-z0-9]{8,60}$`);

export const PATTERNS = {
  commandId: idPattern("cmd"),
  jobId: idPattern("prv"),
  requestId: idPattern("req"),
  harnessId: idPattern("hns"),
  profileId: idPattern("agt"),
  subject: idPattern("usr"),
  keyId: /^[a-z0-9][a-z0-9._-]{2,63}$/,
  nonce: /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/,
  signature: /^[A-Za-z0-9_-]{85}[AQgw]$/,
  operationId: /^[0-9a-f]{32}$/,
  idempotencyKey: /^[A-Za-z0-9_-]{16,128}$/,
  issuer: /^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::([1-9][0-9]{0,4}))?$/,
  principalId: /^[a-z0-9][a-z0-9_-]{0,63}$/,
} as const;

/** 10-digit Unix seconds (rejects milliseconds and implausible values). */
export const MIN_TIMESTAMP = 1_000_000_000;
export const MAX_TIMESTAMP = 9_999_999_999;

export function isValidIssuer(value: string): boolean {
  if (value.length > 256) return false;
  const match = PATTERNS.issuer.exec(value);
  return match !== null && (match[1] === undefined || Number(match[1]) <= 65535);
}

/** Unicode White_Space (PropList.txt), which Rust's str::trim uses. Not JS String.prototype.trim. */
const WHITE_SPACE = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
  0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);
/** General category Cc, which Rust's char::is_control tests. */
const isControl = (cp: number) => cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f);

/** §8.1 displayName: NFC, 1–64 Unicode scalar values, no Cc, no leading/trailing White_Space. */
export function isValidDisplayName(value: string): boolean {
  const scalars = Array.from(value, (ch) => ch.codePointAt(0) as number);
  if (scalars.length < 1 || scalars.length > 64) return false;
  if (scalars.some((cp) => isControl(cp) || (cp >= 0xd800 && cp <= 0xdfff))) return false;
  if (WHITE_SPACE.has(scalars[0] as number) || WHITE_SPACE.has(scalars[scalars.length - 1] as number)) return false;
  return value.normalize("NFC") === value;
}

// ---------------------------------------------------------------------------
// §7 Command schema
// ---------------------------------------------------------------------------

export interface CreatePayload {
  displayName: string;
  idempotencyKey: string;
  issuer: string;
  profileId: string;
  subject: string;
  template: string;
}

export interface OperationPayload {
  operationId: string;
  profileId: string;
}

export interface Command {
  audience: string;
  commandId: string;
  expiresAt: number;
  issuedAt: number;
  jobId: string;
  keyId: string;
  nonce: string;
  operation: Operation;
  payload: CreatePayload | OperationPayload;
  protocol: string;
  purpose: string;
  requestId: string;
  signature: string;
}

export const ENVELOPE_FIELDS = [
  "audience", "commandId", "expiresAt", "issuedAt", "jobId", "keyId", "nonce", "operation", "payload", "protocol",
  "purpose", "requestId", "signature",
] as const;

export const PAYLOAD_FIELDS: Readonly<Record<Operation, readonly string[]>> = {
  "profile.create": ["displayName", "idempotencyKey", "issuer", "profileId", "subject", "template"],
  "profile.status": ["operationId", "profileId"],
  "profile.revoke": ["operationId", "profileId"],
};

type Rule = { code: string; ok: (value: JsonValue) => boolean };

const str = (test: (s: string) => boolean) => (value: JsonValue) => value.kind === "string" && test(value.value);
const re = (pattern: RegExp) => str((s) => pattern.test(s));
const timestamp = (value: JsonValue) => {
  if (value.kind !== "number") return false;
  const n = Number(value.lexeme);
  return n >= MIN_TIMESTAMP && n <= MAX_TIMESTAMP;
};

/** Envelope member checks after purpose and operation, in JCS key order (§10 step 7). */
const ENVELOPE_RULES: ReadonlyArray<[string, Rule]> = [
  ["audience", { code: "INVALID_FIELD", ok: re(PATTERNS.harnessId) }],
  ["commandId", { code: "INVALID_FIELD", ok: re(PATTERNS.commandId) }],
  ["expiresAt", { code: "INVALID_FIELD", ok: timestamp }],
  ["issuedAt", { code: "INVALID_FIELD", ok: timestamp }],
  ["jobId", { code: "INVALID_FIELD", ok: re(PATTERNS.jobId) }],
  ["keyId", { code: "INVALID_FIELD", ok: re(PATTERNS.keyId) }],
  ["nonce", { code: "INVALID_FIELD", ok: re(PATTERNS.nonce) }],
  ["payload", { code: "INVALID_FIELD", ok: (v) => v.kind === "object" }],
  ["requestId", { code: "INVALID_FIELD", ok: re(PATTERNS.requestId) }],
  ["signature", { code: "INVALID_FIELD", ok: re(PATTERNS.signature) }],
];

const PAYLOAD_RULES: Readonly<Record<string, Rule>> = {
  displayName: { code: "INVALID_DISPLAY_NAME", ok: str(isValidDisplayName) },
  idempotencyKey: { code: "INVALID_IDEMPOTENCY_KEY", ok: re(PATTERNS.idempotencyKey) },
  issuer: { code: "INVALID_ISSUER", ok: str(isValidIssuer) },
  operationId: { code: "INVALID_OPERATION_ID", ok: re(PATTERNS.operationId) },
  profileId: { code: "INVALID_PROFILE_ID", ok: re(PATTERNS.profileId) },
  subject: { code: "INVALID_SUBJECT", ok: re(PATTERNS.subject) },
  template: { code: "INVALID_TEMPLATE", ok: str((s) => s === TEMPLATE) },
};

function closedShape(value: JsonValue & { kind: "object" }, fields: readonly string[]): string | null {
  const names = value.members.map(([key]) => key);
  if (names.some((name) => !fields.includes(name))) return "UNKNOWN_FIELD";
  if (fields.some((field) => !names.includes(field))) return "MISSING_FIELD";
  return null;
}

function member(value: JsonValue & { kind: "object" }, name: string): JsonValue {
  const found = value.members.find(([key]) => key === name);
  if (!found) throw new Error(`missing ${name}`);
  return found[1];
}

function plain(value: JsonValue): CanonicalValue {
  switch (value.kind) {
    case "object":
      return Object.fromEntries(value.members.map(([key, m]) => [key, plain(m)]));
    case "string":
      return value.value;
    case "number":
      return Number(value.lexeme);
    default:
      throw new TypeError("outside the command value profile");
  }
}

/** §10 steps 4–8 on a parsed, profile-checked document. */
export function checkCommandSchema(root: JsonValue): { ok: true; command: Command } | { ok: false; code: string } {
  if (root.kind !== "object") return { ok: false, code: "INVALID_ENVELOPE" };
  const protocol = root.members.find(([key]) => key === "protocol")?.[1];
  if (protocol?.kind !== "string") return { ok: false, code: "INVALID_ENVELOPE" };
  if (protocol.value !== PROTOCOL) return { ok: false, code: "UNSUPPORTED_PROTOCOL" };

  const shape = closedShape(root, ENVELOPE_FIELDS);
  if (shape) return { ok: false, code: shape };

  const purpose = member(root, "purpose");
  if (purpose.kind !== "string") return { ok: false, code: "INVALID_FIELD" };
  if (purpose.value !== COMMAND_PURPOSE) return { ok: false, code: "WRONG_PURPOSE" };

  const operation = member(root, "operation");
  if (operation.kind !== "string") return { ok: false, code: "INVALID_FIELD" };
  if (!(OPERATIONS as readonly string[]).includes(operation.value)) return { ok: false, code: "UNSUPPORTED_OPERATION" };

  for (const [name, rule] of ENVELOPE_RULES) {
    if (!rule.ok(member(root, name))) return { ok: false, code: rule.code };
  }

  const payload = member(root, "payload") as JsonValue & { kind: "object" };
  const fields = PAYLOAD_FIELDS[operation.value as Operation];
  const payloadShape = closedShape(payload, fields);
  if (payloadShape) return { ok: false, code: payloadShape };
  for (const name of fields) {
    const rule = PAYLOAD_RULES[name] as Rule;
    if (!rule.ok(member(payload, name))) return { ok: false, code: rule.code };
  }

  const command = plain(root) as unknown as Command;
  const lifetime = command.expiresAt - command.issuedAt;
  if (lifetime < 1 || lifetime > MAX_COMMAND_LIFETIME_SECONDS) return { ok: false, code: "INVALID_LIFETIME" };
  return { ok: true, command };
}

// ---------------------------------------------------------------------------
// §6 Ed25519
// ---------------------------------------------------------------------------

const PKCS8_ED25519_PREFIX = fromHex("302e020100300506032b657004220420");

export async function importSigningKey(seed: Uint8Array, extractable = false) {
  if (seed.length !== 32) throw new TypeError("Ed25519 seed must be 32 bytes");
  return crypto.subtle.importKey("pkcs8", concatBytes(PKCS8_ED25519_PREFIX, seed), { name: "Ed25519" }, extractable, ["sign"]);
}

export async function publicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  const jwk = (await crypto.subtle.exportKey("jwk", await importSigningKey(seed, true))) as { x?: string };
  const x = fromBase64Url(jwk.x ?? "");
  if (!x || x.length !== 32) throw new Error("could not derive public key");
  return x;
}

export async function signBytes(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, await importSigningKey(seed), message));
}

export async function verifyBytes(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
}

/** The group order L (RFC 8032 §5.1); a signature's S must be < L. */
export const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

function littleEndianToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) n = (n << 8n) | BigInt(bytes[i] as number);
  return n;
}

/** RFC 8032 §5.1.7 step 1, checked explicitly so no runtime default is relied on. */
export function hasCanonicalS(signature: Uint8Array): boolean {
  return signature.length === 64 && littleEndianToBigInt(signature.subarray(32)) < ED25519_L;
}

export type UnsignedCommand = Omit<Command, "signature">;

/** Build the wire body of a correctly signed command (§6.2). */
export async function signCommand(
  unsigned: Readonly<Record<string, CanonicalValue>>,
  seed: Uint8Array,
): Promise<{ body: Uint8Array; signingInput: Uint8Array; signature: string }> {
  const input = signingInput(unsigned);
  const signature = toBase64Url(await signBytes(seed, input));
  return { body: utf8(canonicalize({ ...unsigned, signature })), signingInput: input, signature };
}

// ---------------------------------------------------------------------------
// §10 Verification (protocol layer, before local admission)
// ---------------------------------------------------------------------------

export interface TrustedKey {
  keyId: string;
  /** base64url, 32 raw bytes */
  publicKey: string;
  status: "active" | "revoked";
}

export interface VerifierState {
  harnessId: string;
  now: number;
  trustedKeys: readonly TrustedKey[];
  /** Nonces already recorded and still retained. */
  seenNonces: readonly string[];
}

export type VerifyResult = { ok: true; command: Command } | { ok: false; code: string };

export async function verifyCommand(body: Uint8Array, state: VerifierState): Promise<VerifyResult> {
  if (body.length > MAX_MESSAGE_BYTES) return { ok: false, code: "PAYLOAD_TOO_LARGE" };
  const parsed = parseStrictJson(body);
  if (!parsed.ok) return parsed;
  if (!isCommandValueProfile(parsed.value)) return { ok: false, code: "INVALID_JSON_VALUE" };
  const schema = checkCommandSchema(parsed.value);
  if (!schema.ok) return schema;
  const { command } = schema;

  if (toHex(utf8(canonicalizeParsed(parsed.value))) !== toHex(body)) return { ok: false, code: "NON_CANONICAL" };

  const key = state.trustedKeys.find((k) => k.keyId === command.keyId);
  if (!key) return { ok: false, code: "UNKNOWN_KEY" };
  if (key.status !== "active") return { ok: false, code: "KEY_REVOKED" };

  const publicKey = fromBase64Url(key.publicKey);
  const signature = fromBase64Url(command.signature);
  if (!publicKey || publicKey.length !== 32) throw new Error(`misconfigured trusted key ${key.keyId}`);
  const { signature: _omit, ...unsigned } = command;
  if (
    !signature ||
    !hasCanonicalS(signature) ||
    !(await verifyBytes(publicKey, signature, signingInput(unsigned as unknown as Record<string, CanonicalValue>)))
  ) {
    return { ok: false, code: "BAD_SIGNATURE" };
  }

  if (command.audience !== state.harnessId) return { ok: false, code: "WRONG_AUDIENCE" };
  if (command.issuedAt > state.now + MAX_CLOCK_SKEW_SECONDS) return { ok: false, code: "NOT_YET_VALID" };
  if (state.now >= command.expiresAt + MAX_CLOCK_SKEW_SECONDS) return { ok: false, code: "EXPIRED" };
  if (state.seenNonces.includes(command.nonce)) return { ok: false, code: "REPLAY_DETECTED" };
  return { ok: true, command };
}

// ---------------------------------------------------------------------------
// §9.1 Retry identity
// ---------------------------------------------------------------------------

/** §9.1 payloadHash: what D1 stores as provisioning_jobs.request_hash. */
export function payloadHash(operation: Operation, payload: CanonicalValue): Promise<string> {
  return sha256Hex(concatBytes(utf8(`${PROTOCOL}\u0000payload\u0000${operation}\u0000`), utf8(canonicalize(payload))));
}

/** §9.1: a redelivery repeats the logical command and renews every per-transmission field. */
export function isValidRedelivery(first: Command, next: Command): boolean {
  return (
    first.protocol === next.protocol &&
    first.purpose === next.purpose &&
    first.operation === next.operation &&
    first.jobId === next.jobId &&
    first.requestId === next.requestId &&
    first.audience === next.audience &&
    canonicalize(first.payload as unknown as CanonicalValue) === canonicalize(next.payload as unknown as CanonicalValue) &&
    first.commandId !== next.commandId &&
    first.nonce !== next.nonce &&
    first.signature !== next.signature &&
    next.issuedAt >= first.issuedAt
  );
}

// ---------------------------------------------------------------------------
// §11 Errors and §12 responses
// ---------------------------------------------------------------------------

export type ErrorClass = "protocol" | "payload" | "admission" | "merits" | "operation" | "conflict" | "indeterminate";

export interface ErrorDefinition {
  code: string;
  http: number;
  class: ErrorClass;
  operations: readonly Operation[];
  /** Lightagent source codes this maps from; "gateway" codes are new in the L2 gateway. */
  lightagent: readonly string[];
  /**
   * What a refusal with this code lets Web conclude for profile.create (§13.2):
   * "final": no copy of this transmission can ever take effect;
   * "transmission-only": this copy had no effect, other copies still may;
   * "indeterminate": this copy may have taken effect; "conflict": a Web defect;
   * "not-applicable": never answers profile.create.
   */
  createResolution: "final" | "transmission-only" | "indeterminate" | "conflict" | "not-applicable";
  note?: string;
}

/**
 * Refusals after the nonce is durably recorded (§10 steps 13–16) are final for
 * every copy (§9.2). Protocol-class refusals come before it, or are ambiguous
 * (EXPIRED at step 12 or 14), and depend on configuration or the clock.
 */
const CREATE_RESOLUTION: Readonly<Record<ErrorClass, ErrorDefinition["createResolution"]>> = {
  protocol: "transmission-only",
  payload: "final",
  admission: "final",
  merits: "final",
  operation: "not-applicable",
  conflict: "conflict",
  indeterminate: "indeterminate",
};

const ALL: readonly Operation[] = OPERATIONS;
const CREATE: readonly Operation[] = ["profile.create"];
const BY_OPERATION: readonly Operation[] = ["profile.status", "profile.revoke"];
const def = (
  code: string, http: number, cls: ErrorClass, operations: readonly Operation[], lightagent: readonly string[], note?: string,
): ErrorDefinition => ({
  code, http, class: cls, operations, lightagent, createResolution: CREATE_RESOLUTION[cls], ...(note === undefined ? {} : { note }),
});

export const ERRORS: readonly ErrorDefinition[] = [
  def("METHOD_NOT_ALLOWED", 405, "protocol", ALL, ["gateway"]),
  def("UNSUPPORTED_MEDIA_TYPE", 415, "protocol", ALL, ["unsupported_media_type"]),
  def("PAYLOAD_TOO_LARGE", 413, "protocol", ALL, ["payload_too_large"]),
  def("MALFORMED_JSON", 400, "protocol", ALL, ["invalid_request"]),
  def("DUPLICATE_KEY", 400, "protocol", ALL, ["gateway"]),
  def("INVALID_JSON_VALUE", 400, "protocol", ALL, ["gateway"]),
  def("INVALID_ENVELOPE", 400, "protocol", ALL, ["gateway"]),
  def("UNSUPPORTED_PROTOCOL", 400, "protocol", ALL, ["gateway"]),
  def("UNKNOWN_FIELD", 400, "protocol", ALL, ["invalid_request"]),
  def("MISSING_FIELD", 400, "protocol", ALL, ["invalid_request"]),
  def("WRONG_PURPOSE", 400, "protocol", ALL, ["gateway"]),
  def("UNSUPPORTED_OPERATION", 400, "protocol", ALL, ["gateway"]),
  def("INVALID_FIELD", 400, "protocol", ALL, ["invalid_request"]),
  def("INVALID_LIFETIME", 400, "protocol", ALL, ["gateway"]),
  def("NON_CANONICAL", 400, "protocol", ALL, ["gateway"]),
  def("UNKNOWN_KEY", 401, "protocol", ALL, ["gateway"]),
  def("KEY_REVOKED", 401, "protocol", ALL, ["gateway"]),
  def("BAD_SIGNATURE", 401, "protocol", ALL, ["gateway"]),
  def("WRONG_AUDIENCE", 403, "protocol", ALL, ["gateway"]),
  def("NOT_YET_VALID", 401, "protocol", ALL, ["gateway"]),
  def("EXPIRED", 401, "protocol", ALL, ["gateway"],
    "From §10 step 12 (admission), or for profile.create from step 14 (execution deadline re-checked under the ledger lock). Either way this transmission had no effect."),
  def("REPLAY_DETECTED", 409, "indeterminate", ALL, ["gateway"]),
  def("NONCE_STORE_UNAVAILABLE", 503, "protocol", ALL, ["gateway"]),
  def("LEDGER_CONTINUITY_FAILED", 503, "protocol", ALL, ["gateway"],
    "r4 (A9): the gateway fails closed because this harness id is retired or its provisioning ledger's continuity with the identity and profile stores cannot be established (§10.6). Transmission-only: never evidence; Web stops new operations to the harness and raises operator attention."),
  def("INVALID_PROFILE_ID", 400, "payload", ALL, ["invalid_profile_id"]),
  def("RESERVED_PROFILE_ID", 400, "payload", CREATE, ["reserved_profile_id"]),
  def("INVALID_ISSUER", 400, "payload", CREATE, ["invalid_issuer"]),
  def("INVALID_SUBJECT", 400, "payload", CREATE, ["invalid_subject"]),
  def("INVALID_DISPLAY_NAME", 400, "payload", CREATE, ["invalid_display_name"]),
  def("INVALID_TEMPLATE", 400, "payload", CREATE, ["invalid_template"],
    "As a refusal: the payload's template is not \"assistant\". Also an operation failure code: a recorded operation whose template the harness no longer knows ends failed with it."),
  def("INVALID_IDEMPOTENCY_KEY", 400, "payload", CREATE, ["invalid_idempotency_key", "missing_idempotency_key"]),
  def("INVALID_OPERATION_ID", 400, "payload", BY_OPERATION, ["gateway"]),
  def("UNAUTHENTICATED", 401, "admission", ALL, ["unauthenticated"]),
  def("NOT_A_PROVISIONER", 403, "admission", ALL, ["not_a_provisioner"]),
  def("CREDENTIAL_NOT_PROVISIONING_ONLY", 403, "admission", ALL, ["credential_not_provisioning_only"]),
  def("PROVISIONER_INACTIVE", 403, "admission", ALL, ["provisioner_inactive"]),
  def("PROVISIONER_REVOKED", 403, "admission", ALL, ["provisioner_revoked"]),
  def("PROFILE_OUTSIDE_CREDENTIAL", 403, "admission", CREATE, ["profile_outside_credential"]),
  def("ISSUER_NOT_ALLOWED", 403, "merits", CREATE, ["issuer_not_allowed"]),
  def("TEMPLATE_NOT_ALLOWED", 403, "merits", CREATE, ["template_not_allowed"]),
  def("QUOTA_EXCEEDED", 403, "merits", CREATE, ["quota_exceeded"]),
  def("LEDGER_FULL", 403, "merits", CREATE, ["ledger_full"]),
  def("PROFILE_UNAVAILABLE", 409, "merits", CREATE, ["profile_unavailable"]),
  def("PRINCIPAL_INACTIVE", 409, "merits", CREATE, ["principal_inactive"]),
  def("EXTERNAL_IDENTITY_CONFLICT", 409, "merits", CREATE, ["external_identity_conflict"]),
  def("IDEMPOTENCY_CONFLICT", 409, "conflict", CREATE, ["idempotency_conflict"]),
  def("UNKNOWN_OPERATION", 404, "operation", BY_OPERATION, ["unknown_operation"]),
  def("OPERATION_IN_PROGRESS", 409, "operation", ["profile.revoke"], ["operation_in_progress"]),
  def("NOT_REVOCABLE", 409, "operation", ["profile.revoke"], ["not_revocable"]),
  def("OWNERSHIP_CHANGED", 409, "operation", ["profile.revoke"], ["ownership_changed"]),
  def("STORAGE_UNAVAILABLE", 503, "indeterminate", ALL, ["storage_unavailable"]),
  def("STORAGE_CORRUPT", 503, "indeterminate", ALL, ["storage_corrupt"]),
  def("IDENTITY_UNAVAILABLE", 503, "indeterminate", ALL, ["identity_unavailable"]),
  def("INTERNAL_ERROR", 500, "indeterminate", ALL, ["gateway"]),
];

/** Codes that may appear in result.failure of a `failed` operation (§12.2). */
export const FAILURE_CODES = [
  "ISSUER_NOT_TRUSTED", "PRINCIPAL_INACTIVE", "EXTERNAL_IDENTITY_CONFLICT", "PROFILE_UNAVAILABLE", "OWNERSHIP_CHANGED",
  "PROVISIONER_REVOKED", "INVALID_TEMPLATE",
] as const;

export const OPERATION_STATES = ["pending", "profile_created", "completed", "failed", "revoked"] as const;
export type OperationState = (typeof OPERATION_STATES)[number];

/** A profile.create operation response is always a terminal service outcome (§12.2, CL1). */
export const TERMINAL_STATES: readonly OperationState[] = ["completed", "failed", "revoked"];

export interface OperationResult {
  operationId: string;
  state: OperationState;
  failure: string | null;
  principalId: string;
  profileId: string;
  template: string;
  ownerBound: boolean;
  createdUnix: number;
  updatedUnix: number;
}

export type ResponseOutcome =
  | { kind: "operation"; result: OperationResult; replayed: boolean | null }
  | { kind: "refused"; code: string; class: ErrorClass }
  | { kind: "uncertain"; reason: string };

const RESULT_FIELDS = ["createdUnix", "failure", "operationId", "ownerBound", "principalId", "profileId", "state", "template", "updatedUnix"];

function fields(value: JsonValue & { kind: "object" }): Map<string, JsonValue> {
  return new Map(value.members);
}

function exactKeys(map: Map<string, JsonValue>, expected: readonly string[]): boolean {
  return map.size === expected.length && expected.every((key) => map.has(key));
}

const strOf = (v: JsonValue | undefined) => (v?.kind === "string" ? v.value : undefined);
const safeInt = (v: JsonValue | undefined) =>
  v?.kind === "number" && CANONICAL_INTEGER.test(v.lexeme) && BigInt(v.lexeme) <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v.lexeme) : undefined;
const boolOf = (v: JsonValue | undefined) => (v?.kind === "true" ? true : v?.kind === "false" ? false : undefined);

/** §12.4 Web's classification of a harness response to `sent`. Anything unexpected is `uncertain`. */
export function classifyResponse(httpStatus: number, body: Uint8Array, sent: Command): ResponseOutcome {
  const uncertain = (reason: string): ResponseOutcome => ({ kind: "uncertain", reason });
  if (body.length > MAX_MESSAGE_BYTES) return uncertain("RESPONSE_TOO_LARGE");
  const parsed = parseStrictJson(body);
  if (!parsed.ok || parsed.value.kind !== "object") return uncertain("RESPONSE_INVALID");
  const top = fields(parsed.value);
  if (strOf(top.get("protocol")) !== PROTOCOL) return uncertain("RESPONSE_INVALID");

  if (httpStatus === 200 || httpStatus === 201) {
    const isCreate = sent.operation === "profile.create";
    const expected = ["audience", "commandId", "operation", "protocol", "result", ...(isCreate ? ["replayed"] : [])];
    if (!exactKeys(top, expected)) return uncertain("RESPONSE_INVALID");
    if (strOf(top.get("commandId")) !== sent.commandId) return uncertain("RESPONSE_INVALID");
    if (strOf(top.get("audience")) !== sent.audience) return uncertain("RESPONSE_INVALID");
    if (strOf(top.get("operation")) !== sent.operation) return uncertain("RESPONSE_INVALID");
    const replayed = isCreate ? boolOf(top.get("replayed")) : null;
    if (replayed === undefined) return uncertain("RESPONSE_INVALID");
    if (isCreate ? (httpStatus === 201) !== (replayed === false) : httpStatus !== 200) return uncertain("RESPONSE_INVALID");

    const resultValue = top.get("result");
    if (resultValue?.kind !== "object") return uncertain("RESPONSE_INVALID");
    const r = fields(resultValue);
    if (!exactKeys(r, RESULT_FIELDS)) return uncertain("RESPONSE_INVALID");
    const result = {
      operationId: strOf(r.get("operationId")),
      state: strOf(r.get("state")),
      failure: r.get("failure")?.kind === "null" ? null : strOf(r.get("failure")),
      principalId: strOf(r.get("principalId")),
      profileId: strOf(r.get("profileId")),
      template: strOf(r.get("template")),
      ownerBound: boolOf(r.get("ownerBound")),
      createdUnix: safeInt(r.get("createdUnix")),
      updatedUnix: safeInt(r.get("updatedUnix")),
    };
    if (
      result.operationId === undefined || !PATTERNS.operationId.test(result.operationId) ||
      result.state === undefined || !(OPERATION_STATES as readonly string[]).includes(result.state) ||
      result.failure === undefined ||
      result.principalId === undefined || !PATTERNS.principalId.test(result.principalId) ||
      result.profileId !== sent.payload.profileId ||
      result.template !== TEMPLATE ||
      result.ownerBound === undefined ||
      result.createdUnix === undefined || result.updatedUnix === undefined || result.updatedUnix < result.createdUnix
    ) {
      return uncertain("RESPONSE_INVALID");
    }
    if ((result.state === "failed") !== (result.failure !== null)) return uncertain("RESPONSE_INVALID");
    if (result.failure !== null && !(FAILURE_CODES as readonly string[]).includes(result.failure)) return uncertain("RESPONSE_INVALID");
    // ownerBound is current ownership, independent of state (§12.2, RC2): no cross-check here.
    if (isCreate && !TERMINAL_STATES.includes(result.state as OperationState)) return uncertain("RESPONSE_INVALID");
    if (!isCreate && result.operationId !== (sent.payload as OperationPayload).operationId) return uncertain("RESPONSE_INVALID");
    if (sent.operation === "profile.revoke" && result.state !== "revoked") return uncertain("RESPONSE_INVALID");
    return { kind: "operation", result: result as OperationResult, replayed };
  }

  if (!exactKeys(top, ["code", "commandId", "protocol"])) return uncertain("RESPONSE_INVALID");
  const commandId = top.get("commandId");
  if (!(commandId?.kind === "null" || strOf(commandId) === sent.commandId)) return uncertain("RESPONSE_INVALID");
  const code = strOf(top.get("code"));
  const definition = ERRORS.find((e) => e.code === code);
  if (!definition || definition.http !== httpStatus || !definition.operations.includes(sent.operation)) {
    return uncertain("RESPONSE_INVALID");
  }
  if (definition.class === "indeterminate") return uncertain(definition.code);
  return { kind: "refused", code: definition.code, class: definition.class };
}

// ---------------------------------------------------------------------------
// §13.2 Create resolution (Web state machine)
// ---------------------------------------------------------------------------

export type TransmissionOutcome =
  | { kind: "operation"; operationId: string; state: OperationState }
  | { kind: "refused"; code: string }
  | { kind: "uncertain" };

export interface Transmission {
  issuedAt: number;
  expiresAt: number;
  outcome: TransmissionOutcome;
}

export type CreateResolution =
  | { status: "resolved"; operationId: string; state: OperationState }
  | { status: "failed"; code: string }
  | { status: "attention"; code: string }
  | { status: "unresolved" };

const classOf = (code: string) => ERRORS.find((e) => e.code === code)?.class;

export interface ResolutionOptions {
  /**
   * r2 treated protocol-class refusals as final. r3 does not (§13.2): they are
   * refused before the nonce is durably recorded, so another copy of the same
   * transmission may still take effect. Kept only to reproduce r2 in models.
   */
  protocolRefusalsFinal?: boolean;
  /**
   * r3 let a PROFILE_UNAVAILABLE merits refusal rule out open transmissions.
   * r4 does not (§13.2 R3a): with an open transmission it signals a possible
   * ledger discontinuity (A9) and the job needs operator attention.
   */
  profileUnavailableRulesOut?: boolean;
}

/**
 * Decide what Web may conclude about one profile.create job from every
 * journaled transmission (§13.2, §13.10). Exhausted retries never produce
 * `failed`.
 */
export function resolveCreateJob(transmissions: readonly Transmission[], options: ResolutionOptions = {}): CreateResolution {
  const operations = transmissions.flatMap((t) => (t.outcome.kind === "operation" ? [t.outcome] : []));
  if (operations.length > 0) {
    const first = operations[0] as { operationId: string; state: OperationState };
    if (operations.some((o) => o.operationId !== first.operationId)) return { status: "attention", code: "OPERATION_MISMATCH" };
    const latest = operations[operations.length - 1] as { operationId: string; state: OperationState };
    return { status: "resolved", operationId: latest.operationId, state: latest.state };
  }
  const refusals = transmissions.flatMap((t) => (t.outcome.kind === "refused" ? [{ ...t, code: t.outcome.code }] : []));
  if (refusals.some((r) => classOf(r.code) === "conflict")) return { status: "attention", code: "IDEMPOTENCY_CONFLICT" };
  if (refusals.some((r) => classOf(r.code) === undefined)) return { status: "attention", code: "UNKNOWN_REFUSAL" };
  const payloadRefusal = refusals.find((r) => classOf(r.code) === "payload");
  if (payloadRefusal) return { status: "failed", code: payloadRefusal.code };
  if (refusals.length === 0) return { status: "unresolved" };
  if (refusals.some((r) => r.code === "LEDGER_CONTINUITY_FAILED")) return { status: "attention", code: "LEDGER_CONTINUITY_FAILED" };

  // Every transmission that is not finally refused (uncertain, or refused
  // only for this copy) must be ruled out by a merits refusal of a
  // transmission issued at or after its acceptance horizon (§13.2 rule R3).
  const finalRefusal = (code: string) => classOf(code) !== "protocol" || options.protocolRefusalsFinal === true;
  const open = transmissions.filter((t) => t.outcome.kind === "uncertain" || (t.outcome.kind === "refused" && !finalRefusal(t.outcome.code)));
  const profileUnavailableRulesOut = options.profileUnavailableRulesOut === true;
  if (!profileUnavailableRulesOut && open.length > 0 && refusals.some((r) => r.code === "PROFILE_UNAVAILABLE")) {
    return { status: "attention", code: "PROFILE_UNAVAILABLE_WHILE_OPEN" };
  }
  const merits = refusals.filter((r) => classOf(r.code) === "merits" && (profileUnavailableRulesOut || r.code !== "PROFILE_UNAVAILABLE"));
  const ruledOut = open.every((u) => merits.some((m) => m.issuedAt >= u.expiresAt + ACCEPTANCE_HORIZON_SECONDS));
  if (!ruledOut) return { status: "unresolved" };
  const latest = refusals.reduce((a, b) => (b.issuedAt >= a.issuedAt ? b : a));
  return { status: "failed", code: latest.code };
}

// ---------------------------------------------------------------------------
// §13.1 Ownership observations (RC2)
// ---------------------------------------------------------------------------

export type OwnershipAssessment =
  | "bound"
  | "unbound"
  | "bound-informational"
  | "attention:OWNERSHIP_LOST"
  | "attention:UNEXPECTED_BINDING";

/**
 * What Web concludes from `ownerBound`, which reports whether the operation's
 * principal owns the profile when the harness answers, independently of the
 * operation's (historical) state. It never says this request created a binding.
 */
export function assessOwnership(result: Pick<OperationResult, "state" | "ownerBound">): OwnershipAssessment {
  if (result.state === "completed") return result.ownerBound ? "bound" : "attention:OWNERSHIP_LOST";
  if (result.state === "revoked") return result.ownerBound ? "attention:UNEXPECTED_BINDING" : "unbound";
  return result.ownerBound ? "bound-informational" : "unbound";
}

// ---------------------------------------------------------------------------
// §10 step 14 Execution deadline (RC1)
// ---------------------------------------------------------------------------

/** The harness-clock instant from which a create may no longer start executing. */
export function executionDeadline(command: Pick<Command, "expiresAt">): number {
  return command.expiresAt + MAX_CLOCK_SKEW_SECONDS;
}

/**
 * §10 step 14: after acquiring the ledger lock and before the idempotency
 * lookup, refuse when the harness clock or the durable execution fence (RC5)
 * has reached the command's execution deadline.
 */
export function checkExecutionDeadline(command: Pick<Command, "expiresAt">, lockAcquiredAt: number, fence = 0): "proceed" | "EXPIRED" {
  const deadline = executionDeadline(command);
  return lockAcquiredAt >= deadline || deadline <= fence ? "EXPIRED" : "proceed";
}

/** RC5: the fence value after a create passes §10 step 15 (never decreases). */
export function advanceFence(fence: number, command: Pick<Command, "issuedAt">): number {
  return Math.max(fence, command.issuedAt - MAX_CLOCK_SKEW_SECONDS);
}

/**
 * A model of one harness serving the transmissions of one profile.create job
 * under PR #26's semantics: every call holds the ledger lock for its whole
 * duration (calls are totally ordered by lock acquisition), an idempotency
 * hit returns the recorded operation, a miss runs the merits checks (here: a
 * quota that is available only in some intervals), and nothing is written
 * before the operation is recorded. Times on the harness side are harness
 * clock; issuedAt/expiresAt are Web's stamps.
 */
export interface RaceAttempt {
  issuedAt: number;
  expiresAt: number;
  /** Harness clock at §10 step 12, or null if the request never arrived. */
  admittedAt: number | null;
  /** Harness clock when the ledger lock was acquired (≥ admittedAt). */
  lockAcquiredAt?: number;
  /** The harness clock when this call releases the lock; defaults to lockAcquiredAt. */
  releasedAt?: number;
  /** Web never receives this transmission's response (timeout, lost connection). */
  responseLost?: boolean;
  /** The call records the operation as pending and then fails with an indeterminate error. */
  crashAfterRecord?: boolean;
}

export interface RaceScenario {
  attempts: readonly RaceAttempt[];
  /** Harness-clock intervals [from, to) in which the provisioner's quota allows a new profile. */
  quotaAvailable: ReadonlyArray<readonly [number, number]>;
  /** Whether the harness implements §10 step 14. */
  executionDeadlineCheck: boolean;
}

export interface RaceResult {
  harness: string[];
  /** The final operation recorded for the key, if any. */
  operation: OperationState | null;
  web: CreateResolution;
  /** Web concluded `failed` although an operation exists (the RC1 defect). */
  unsafe: boolean;
}

export function simulateCreateRace(scenario: RaceScenario): RaceResult {
  const order = scenario.attempts
    .map((attempt, index) => ({ attempt, index }))
    .filter(({ attempt }) => attempt.admittedAt !== null)
    .sort((a, b) => (a.attempt.lockAcquiredAt ?? (a.attempt.admittedAt as number)) - (b.attempt.lockAcquiredAt ?? (b.attempt.admittedAt as number)));
  const harness: string[] = scenario.attempts.map(() => "NOT_RECEIVED");
  let operation: OperationState | null = null;
  let lockFreeAt = -Infinity;
  const quotaAt = (t: number) => scenario.quotaAvailable.some(([from, to]) => t >= from && t < to);

  for (const { attempt, index } of order) {
    const admittedAt = attempt.admittedAt as number;
    const lockAt = attempt.lockAcquiredAt ?? admittedAt;
    if (lockAt < admittedAt || lockAt < lockFreeAt) throw new Error(`attempt ${index}: lock acquired while held or before admission`);
    lockFreeAt = attempt.releasedAt ?? lockAt;
    if (admittedAt < attempt.issuedAt - MAX_CLOCK_SKEW_SECONDS) {
      harness[index] = "NOT_YET_VALID";
      continue;
    }
    if (admittedAt >= attempt.expiresAt + MAX_CLOCK_SKEW_SECONDS) {
      harness[index] = "EXPIRED";
      continue;
    }
    if (scenario.executionDeadlineCheck && checkExecutionDeadline(attempt, lockAt) === "EXPIRED") {
      harness[index] = "EXPIRED";
      continue;
    }
    if (operation !== null) {
      // Idempotency hit: resume drives a recorded operation to its terminal state.
      if (operation === "pending") operation = "completed";
      harness[index] = `OPERATION:${operation}`;
      continue;
    }
    if (!quotaAt(lockAt)) {
      harness[index] = "QUOTA_EXCEEDED";
      continue;
    }
    if (attempt.crashAfterRecord) {
      operation = "pending";
      harness[index] = "STORAGE_UNAVAILABLE";
      continue;
    }
    operation = "completed";
    harness[index] = "OPERATION:completed";
  }

  const transmissions: Transmission[] = scenario.attempts.map((attempt, index) => {
    const answer = harness[index] as string;
    if (attempt.responseLost || answer === "NOT_RECEIVED") return { ...attempt, outcome: { kind: "uncertain" } };
    if (answer.startsWith("OPERATION:")) {
      return { ...attempt, outcome: { kind: "operation", operationId: "0".repeat(32), state: answer.slice(10) as OperationState } };
    }
    if (classOf(answer) === "indeterminate") return { ...attempt, outcome: { kind: "uncertain" } };
    return { ...attempt, outcome: { kind: "refused", code: answer } };
  });
  const web = resolveCreateJob(transmissions.map(({ issuedAt, expiresAt, outcome }) => ({ issuedAt, expiresAt, outcome })));
  return { harness, operation, web, unsafe: web.status === "failed" && operation !== null };
}

// ---------------------------------------------------------------------------
// §13.2 Ordering model (RC5, RC6): one harness, one profile.create job
// ---------------------------------------------------------------------------

/**
 * Which rules the harness and Web follow. RULES_R3 is this revision; the
 * others reproduce r2 and the review's proposal so each counterexample can be
 * shown against the rule set it defeats.
 */
export interface OrderingRules {
  /** §10 step 14 wall-clock check (r2). */
  executionDeadline: boolean;
  /** RC5: step 14 also refuses when expiresAt + 30 ≤ fence; step 15 advances the fence. */
  fence: boolean;
  /** RC5: the fence advance is durable before the ledger lock is released (otherwise only after it). */
  fenceDurableBeforeUnlock: boolean;
  /** §9.2: nonce records survive a harness restart. */
  nonceDurable: boolean;
  /** §9.2: a nonce record is discarded only once fence ≥ expiresAt + 30 (otherwise by wall clock). */
  nonceRetainedUntilFenced: boolean;
  /** r2 Web rule: protocol-class refusals count as final (r3: they do not). */
  protocolRefusalsFinal: boolean;
  /** RC6: every transmission that can reach the harness is journaled before it is sent. */
  journalBeforeSend: boolean;
  /** r3 §10.5: a restore raises the fence to T + 150 (T = verified time of the restore). */
  restoreRaisesFence: boolean;
  /** r4 A9/§10.6: the gateway fails closed when the ledger no longer matches the identity store. */
  ledgerContinuityCheck: boolean;
  /** r3 Web rule; r4 (R3a): PROFILE_UNAVAILABLE never rules out an open transmission. */
  profileUnavailableRulesOut: boolean;
}

export const RULES_R2: OrderingRules = {
  executionDeadline: true, fence: false, fenceDurableBeforeUnlock: false, nonceDurable: false,
  nonceRetainedUntilFenced: false, protocolRefusalsFinal: true, journalBeforeSend: false,
  restoreRaisesFence: false, ledgerContinuityCheck: false, profileUnavailableRulesOut: true,
};
/** RC5 and RC6 exactly as the r2 review words them (fence durable "before the answer", nonce rules from r2). */
export const RULES_REVIEW_PROPOSAL: OrderingRules = {
  executionDeadline: true, fence: true, fenceDurableBeforeUnlock: false, nonceDurable: false,
  nonceRetainedUntilFenced: false, protocolRefusalsFinal: true, journalBeforeSend: true,
  restoreRaisesFence: false, ledgerContinuityCheck: false, profileUnavailableRulesOut: true,
};
export const RULES_R3: OrderingRules = {
  executionDeadline: true, fence: true, fenceDurableBeforeUnlock: true, nonceDurable: true,
  nonceRetainedUntilFenced: true, protocolRefusalsFinal: false, journalBeforeSend: true,
  restoreRaisesFence: true, ledgerContinuityCheck: false, profileUnavailableRulesOut: true,
};
/** This revision: r3 plus ledger continuity (A9, §10.6) and R3a. */
export const RULES_R4: OrderingRules = { ...RULES_R3, ledgerContinuityCheck: true, profileUnavailableRulesOut: false };

export interface ModelTransmission {
  /** Web stamps. Real time is Web's clock. */
  issuedAt: number;
  expiresAt: number;
  /** False: the Worker sent it but never journaled it (only possible without RC6). */
  journaled?: boolean;
}

/** One copy of a transmission reaching the harness (network duplicates are further copies). */
export interface ModelDelivery {
  transmission: number;
  /** Real time of §10 steps 1–12. */
  arrivesAt: number;
  /** Real time the ledger lock is acquired (steps 13–16); defaults to arrivesAt. */
  lockAt?: number;
  /** Seconds the lock is held (≥ 1); the answer leaves at lockAt + holdFor. */
  holdFor?: number;
  /** Whether Web receives this copy's answer (default: only the first copy of each transmission). */
  answerToWeb?: boolean;
  /** The call records the operation and then fails with an indeterminate error. */
  crashAfterRecord?: boolean;
}

export interface OrderingScenario {
  transmissions: readonly ModelTransmission[];
  deliveries: readonly ModelDelivery[];
  /** Harness clock = real time + offset; each entry applies from real time `from` (sorted). */
  harnessClock?: ReadonlyArray<{ from: number; offset: number }>;
  /** Real-time intervals [from, to) in which the quota admits a new profile. */
  quota: ReadonlyArray<readonly [number, number]>;
  /** Before this real time the signing key is not yet trusted (UNKNOWN_KEY, refused before the nonce). */
  keyTrustedFrom?: number;
  /** Real times of harness restarts: queued calls die, non-durable state is lost. */
  restarts?: readonly number[];
  /** Real times at which the harness runs nonce housekeeping (only then; safety must not depend on when it runs). */
  housekeeping?: readonly number[];
  /**
   * Recoveries (§10.5, §10.6). The harness stops (queued calls die), the named
   * stores are reset to an earlier point that predates every operation and
   * nonce in the model ("ledger": operations; "identity": ownership bindings
   * and provisioning transaction records; "nonces"; "fence": to `fenceTo`,
   * default 0), and the harness starts again at `at`.
   */
  recoveries?: ReadonlyArray<{ at: number; restore: ReadonlyArray<"ledger" | "identity" | "nonces" | "fence">; fenceTo?: number }>;
}

export interface OrderingResult {
  /** The answer each delivery produced ("KILLED" if a restart ended it while queued). */
  answers: string[];
  /** Operation for the key at the end, and the transmission whose call recorded it. */
  operation: { state: OperationState; recordedBy: number } | null;
  /** Owner binding (identity store) at the end, and the transmission whose call created it. */
  binding: { createdBy: number } | null;
  /** Whether the gateway was failing closed at the end (§10.6). */
  failedClosed: boolean;
  /** Web's resolution after the last answer. */
  web: CreateResolution;
  /** Earliest real time at which Web concluded `failed`, if ever. */
  failedAt: number | null;
  /** Web concluded `failed` although an operation was recorded by a transmission issued by then. */
  unsafe: boolean;
}

/**
 * Event-driven model of one harness and one create job. It encodes P2 (calls
 * serialized by the ledger lock), P3 (record before effect), P4 (terminal
 * create answers), the §10 step order, §9.2 nonces and the RC5 fence. It does
 * not model signatures: every delivery is a validly signed copy.
 */
export function simulateOrdering(scenario: OrderingScenario, rules: OrderingRules): OrderingResult {
  const clock = [...(scenario.harnessClock ?? [{ from: -Infinity, offset: 0 }])];
  const h = (t: number) => clock.reduce((offset, step) => (t >= step.from ? step.offset : offset), 0) + t;
  const quotaAt = (t: number) => scenario.quota.some(([from, to]) => t >= from && t < to);
  const restarts = [...(scenario.restarts ?? [])].sort((a, b) => a - b);
  const firstCopy = new Map<number, number>();
  scenario.deliveries.forEach((d, i) => {
    if (!firstCopy.has(d.transmission)) firstCopy.set(d.transmission, i);
  });

  // Kinds, in tie order: -1 recovery, 0 restart, 1 housekeeping, 2 arrival (steps 1–12), 3 lock (steps 13–16).
  type Event = { time: number; kind: -1 | 0 | 1 | 2 | 3; index: number };
  const recoveries = scenario.recoveries ?? [];
  const events: Event[] = [
    ...recoveries.map((r, index) => ({ time: r.at, kind: -1 as const, index })),
    ...restarts.map((time, index) => ({ time, kind: 0 as const, index })),
    ...(scenario.housekeeping ?? []).map((time, index) => ({ time, kind: 1 as const, index })),
    ...scenario.deliveries.map((d, index) => ({ time: d.arrivesAt, kind: 2 as const, index })),
    ...scenario.deliveries.map((d, index) => ({ time: d.lockAt ?? d.arrivesAt, kind: 3 as const, index })),
  ].sort((a, b) => a.time - b.time || a.kind - b.kind || a.index - b.index);

  const answers: string[] = scenario.deliveries.map(() => "NOT_RECEIVED");
  const answeredAt: number[] = scenario.deliveries.map(() => Infinity);
  const queued = new Set<number>();
  const nonces = new Map<number, { expiresAt: number; durable: boolean }>();
  let fence = 0;
  const pendingFence: Array<{ value: number; visibleAt: number }> = [];
  let lockFreeAt = -Infinity;
  let operation: { state: OperationState; recordedBy: number } | null = null;
  let binding: { createdBy: number } | null = null;
  let failedClosed = false;

  const visibleFence = (t: number) => {
    for (let i = pendingFence.length - 1; i >= 0; i -= 1) {
      const p = pendingFence[i] as { value: number; visibleAt: number };
      if (p.visibleAt <= t) {
        fence = Math.max(fence, p.value);
        pendingFence.splice(i, 1);
      }
    }
    return fence;
  };
  const purgeNonces = (t: number) => {
    const now = h(t);
    for (const [key, record] of nonces) {
      if (now < record.expiresAt + MAX_CLOCK_SKEW_SECONDS) continue;
      if (!rules.nonceRetainedUntilFenced) nonces.delete(key);
      else if (rules.fence) {
        // §9.2: raise the fence durably first, then discard the record.
        fence = Math.max(visibleFence(t), record.expiresAt + MAX_CLOCK_SKEW_SECONDS);
        nonces.delete(key);
      }
    }
  };

  for (const event of events) {
    visibleFence(event.time);
    if (event.kind === 1) purgeNonces(event.time);
    if (event.kind === -1) {
      // The harness was stopped for the recovery: queued calls die, pending fence writes are lost.
      const recovery = recoveries[event.index] as { at: number; restore: ReadonlyArray<string>; fenceTo?: number };
      for (const index of queued) answers[index] = "KILLED";
      queued.clear();
      pendingFence.length = 0;
      if (recovery.restore.includes("ledger")) operation = null;
      if (recovery.restore.includes("identity")) binding = null;
      if (recovery.restore.includes("nonces")) nonces.clear();
      if (recovery.restore.includes("fence")) fence = recovery.fenceTo ?? 0;
      if (rules.restoreRaisesFence) fence = Math.max(fence, recovery.at + 150);
      // §10.6 C2/C3: a binding whose operation the ledger lost, or a completed operation the identity store lost.
      const inconsistent = (binding !== null && operation === null) || (operation?.state === "completed" && binding === null);
      if (rules.ledgerContinuityCheck && inconsistent) failedClosed = true;
      continue;
    }
    if (event.kind === 0) {
      for (const index of queued) answers[index] = "KILLED";
      queued.clear();
      for (const [key, record] of nonces) if (!record.durable) nonces.delete(key);
      // A fence advance not yet durable is lost with the process.
      pendingFence.length = 0;
      continue;
    }
    if (event.kind === 1) continue;
    const delivery = scenario.deliveries[event.index] as ModelDelivery;
    const tx = scenario.transmissions[delivery.transmission] as ModelTransmission;
    if (event.kind === 2) {
      const now = h(event.time);
      const refuse = (code: string) => {
        answers[event.index] = code;
        answeredAt[event.index] = event.time;
      };
      if (failedClosed) refuse("LEDGER_CONTINUITY_FAILED");
      else if (scenario.keyTrustedFrom !== undefined && event.time < scenario.keyTrustedFrom) refuse("UNKNOWN_KEY");
      else if (tx.issuedAt > now + MAX_CLOCK_SKEW_SECONDS) refuse("NOT_YET_VALID");
      else if (now >= tx.expiresAt + MAX_CLOCK_SKEW_SECONDS) refuse("EXPIRED");
      else if (nonces.has(delivery.transmission)) refuse("REPLAY_DETECTED");
      else {
        nonces.set(delivery.transmission, { expiresAt: tx.expiresAt, durable: rules.nonceDurable });
        queued.add(event.index);
      }
      continue;
    }
    if (!queued.has(event.index)) continue;
    queued.delete(event.index);
    const lockAt = event.time;
    const hold = delivery.holdFor ?? 1;
    if (lockAt < delivery.arrivesAt || lockAt < lockFreeAt || hold < 1) throw new Error(`delivery ${event.index}: lock order violated`);
    lockFreeAt = lockAt + hold;
    answeredAt[event.index] = lockAt + hold;
    const now = h(lockAt);
    const deadline = tx.expiresAt + MAX_CLOCK_SKEW_SECONDS;
    if ((rules.executionDeadline && now >= deadline) || (rules.fence && deadline <= visibleFence(lockAt))) {
      answers[event.index] = "EXPIRED";
      continue;
    }
    if (rules.fence) {
      const value = Math.max(fence, tx.issuedAt - MAX_CLOCK_SKEW_SECONDS);
      if (rules.fenceDurableBeforeUnlock) fence = value;
      else pendingFence.push({ value, visibleAt: lockAt + hold + 1 });
    }
    const recorded = operation as { state: OperationState; recordedBy: number } | null;
    if (recorded !== null) {
      // Idempotency hit: resume drives a recorded operation to its terminal state.
      const state: OperationState = recorded.state === "pending" ? "completed" : recorded.state;
      if (recorded.state === "pending" && binding === null) binding = { createdBy: recorded.recordedBy };
      operation = { state, recordedBy: recorded.recordedBy };
      answers[event.index] = `OPERATION:${state}`;
    } else if (!quotaAt(lockAt)) {
      answers[event.index] = "QUOTA_EXCEEDED";
    } else if (binding !== null) {
      // PR #26 begin: the profile id is known to the identity store although this ledger has no operation.
      answers[event.index] = "PROFILE_UNAVAILABLE";
    } else if (delivery.crashAfterRecord) {
      operation = { state: "pending", recordedBy: delivery.transmission };
      answers[event.index] = "STORAGE_UNAVAILABLE";
    } else {
      operation = { state: "completed", recordedBy: delivery.transmission };
      binding = { createdBy: delivery.transmission };
      answers[event.index] = `OPERATION:${operation.state}`;
    }
  }

  // Web's view: journaled transmissions, outcomes from the answers it received so far.
  const outcomeAt = (index: number, t: number): TransmissionOutcome => {
    const d = firstCopy.get(index);
    const delivered = scenario.deliveries
      .map((delivery, i) => ({ delivery, i }))
      .filter(({ delivery, i }) => delivery.transmission === index && (delivery.answerToWeb ?? i === d) && (answeredAt[i] ?? Infinity) <= t);
    const answer = delivered.length > 0 ? (answers[(delivered[0] as { i: number }).i] as string) : "NOT_RECEIVED";
    if (answer.startsWith("OPERATION:")) return { kind: "operation", operationId: "0".repeat(32), state: answer.slice(10) as OperationState };
    const definition = ERRORS.find((e) => e.code === answer);
    if (!definition || definition.class === "indeterminate") return { kind: "uncertain" };
    return { kind: "refused", code: answer };
  };
  const view = (t: number): Transmission[] =>
    scenario.transmissions.flatMap((tx, index) =>
      tx.issuedAt <= t && (rules.journalBeforeSend || tx.journaled !== false) ? [{ issuedAt: tx.issuedAt, expiresAt: tx.expiresAt, outcome: outcomeAt(index, t) }] : [],
    );
  const webOptions: ResolutionOptions = { protocolRefusalsFinal: rules.protocolRefusalsFinal, profileUnavailableRulesOut: rules.profileUnavailableRulesOut };
  const checkpoints = [...new Set([...answeredAt.filter(Number.isFinite), ...scenario.transmissions.map((tx) => tx.issuedAt)])].sort((a, b) => a - b);
  let failedAt: number | null = null;
  for (const t of checkpoints) {
    if (resolveCreateJob(view(t), webOptions).status === "failed") {
      failedAt = t;
      break;
    }
  }
  const end = checkpoints.length > 0 ? (checkpoints[checkpoints.length - 1] as number) : 0;
  const web = resolveCreateJob(view(end), webOptions);
  const issuedBy = (index: number | undefined) => (index === undefined ? null : (scenario.transmissions[index] as ModelTransmission).issuedAt);
  const recordedAt = issuedBy(operation?.recordedBy);
  const boundAt = issuedBy(binding?.createdBy);
  // Unsafe: Web concluded failed while an operation or an owner binding from a transmission issued by then exists.
  const unsafe = failedAt !== null && ((recordedAt !== null && recordedAt <= failedAt) || (boundAt !== null && boundAt <= failedAt));
  return { answers, operation, binding, failedClosed, web, failedAt, unsafe };
}

/** Rule sets the ordering fixtures and randomized tests evaluate: r2, the review's proposal, r3, and r3 minus each rule. */
export const RULE_SETS: Readonly<Record<string, OrderingRules>> = {
  r2: RULES_R2,
  reviewProposal: RULES_REVIEW_PROPOSAL,
  r3: RULES_R3,
  r4: RULES_R4,
  "r4-without-continuity-check": { ...RULES_R4, ledgerContinuityCheck: false },
  "r4-profile-unavailable-rules-out": { ...RULES_R4, profileUnavailableRulesOut: true },
  "r4-restore-without-fence-raise": { ...RULES_R4, restoreRaisesFence: false },
  "r3-without-wall-clock-deadline": { ...RULES_R3, executionDeadline: false },
  "r3-without-fence": { ...RULES_R3, fence: false },
  "r3-fence-durable-only-after-unlock": { ...RULES_R3, fenceDurableBeforeUnlock: false },
  "r3-without-durable-nonces": { ...RULES_R3, nonceDurable: false },
  "r3-nonces-discarded-by-clock": { ...RULES_R3, nonceRetainedUntilFenced: false },
  "r3-protocol-refusals-final": { ...RULES_R3, protocolRefusalsFinal: true },
  "r3-without-journal": { ...RULES_R3, journalBeforeSend: false },
};

// ---------------------------------------------------------------------------
// §13.5 Reconciliation plan
// ---------------------------------------------------------------------------

export type ReconciliationStep = "send-create" | "revoke" | "confirm-status" | "operator-attention" | "none";

/**
 * The next step for one create job given its resolution and the profile's
 * desired state (R4–R6). An unresolved create is always driven forward with
 * the same logical command, even when the desired state is absent: Web must
 * learn the operation id before it can revoke it.
 */
export function planReconciliation(
  resolution: CreateResolution,
  desired: "present" | "absent",
  harness: "active" | "retired" = "active",
): ReconciliationStep {
  // §10.6: Web sends nothing to a retired harness id and never fails or migrates its jobs on its own.
  if (harness === "retired") {
    if (resolution.status === "failed") return "none";
    if (resolution.status === "resolved" && resolution.state === "revoked" && desired === "absent") return "none";
    if (resolution.status === "resolved" && resolution.state === "failed" && desired === "present") return "none";
    return "operator-attention";
  }
  switch (resolution.status) {
    case "unresolved":
      return "send-create";
    case "attention":
      return "operator-attention";
    case "failed":
      return "none";
    case "resolved":
      if (resolution.state === "completed") return desired === "absent" ? "revoke" : "none";
      if (resolution.state === "failed") return desired === "absent" ? "confirm-status" : "none";
      if (resolution.state === "revoked") return desired === "absent" ? "none" : "operator-attention";
      return "send-create";
  }
}

// ---------------------------------------------------------------------------
// §10.6 Ledger continuity check (A9): the gateway's fail-closed activation check
// ---------------------------------------------------------------------------

/**
 * What the harness can see at gateway start or activation. Operation ids are
 * PR #26's: the ledger's operations, the identity store's provisioning
 * transaction records (`provisioning:<op>`), and the profile store's
 * `.provisioning-operation` markers.
 */
export interface ContinuityInput {
  configuredHarnessId: string;
  /** null: no ledger file. */
  ledger: null | {
    /** The harness id stamped at explicit operator initialization; null if never stamped (e.g. auto-created). */
    harnessId: string | null;
    retired: boolean;
    operations: ReadonlyArray<{ operationId: string; state: OperationState }>;
  };
  identityProvisioningRecords: readonly string[];
  profileMarkers: readonly string[];
}

export type ContinuityVerdict = { serve: true } | { serve: false; reason: "NO_LEDGER" | "UNSTAMPED_LEDGER" | "HARNESS_ID_MISMATCH" | "RETIRED" | "LEDGER_BEHIND_STORES" | "STORES_BEHIND_LEDGER" };

/**
 * §10.6 C1–C3. Never infers a clean state from absence: a missing or
 * unstamped ledger fails closed even when every other store is empty, because
 * only an explicit operator initialization establishes a new harness id.
 */
export function checkLedgerContinuity(input: ContinuityInput): ContinuityVerdict {
  const { ledger } = input;
  if (ledger === null) return { serve: false, reason: "NO_LEDGER" };
  if (ledger.harnessId === null) return { serve: false, reason: "UNSTAMPED_LEDGER" };
  if (ledger.harnessId !== input.configuredHarnessId) return { serve: false, reason: "HARNESS_ID_MISMATCH" };
  if (ledger.retired) return { serve: false, reason: "RETIRED" };
  const known = new Set(ledger.operations.map((o) => o.operationId));
  // C2: every operation the identity or profile store references is in the ledger.
  if ([...input.identityProvisioningRecords, ...input.profileMarkers].some((id) => !known.has(id))) {
    return { serve: false, reason: "LEDGER_BEHIND_STORES" };
  }
  // C3: every operation that reached its identity transaction has its record in the identity store.
  const identity = new Set(input.identityProvisioningRecords);
  if (ledger.operations.some((o) => (o.state === "completed" || o.state === "revoked") && !identity.has(o.operationId))) {
    return { serve: false, reason: "STORES_BEHIND_LEDGER" };
  }
  return { serve: true };
}
