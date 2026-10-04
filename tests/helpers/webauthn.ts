/**
 * A software WebAuthn authenticator for tests: ES256 (P-256) credentials,
 * "none" attestation, produced with Web Crypto. Lets passkey registration and
 * authentication run through Better Auth's real SimpleWebAuthn verification.
 */

const encoder = new TextEncoder();

export function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// --- minimal CBOR encoder (maps, ints, byte/text strings) -------------------
type Cbor = number | string | Uint8Array | Map<Cbor, Cbor>;

function head(major: number, length: number): Uint8Array {
  if (length < 24) return new Uint8Array([(major << 5) | length]);
  if (length < 256) return new Uint8Array([(major << 5) | 24, length]);
  return new Uint8Array([(major << 5) | 25, length >> 8, length & 0xff]);
}

function cbor(value: Cbor): Uint8Array {
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") {
    const bytes = encoder.encode(value);
    return concat(head(3, bytes.length), bytes);
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  const entries = [...value].flatMap(([k, v]) => [cbor(k), cbor(v)]);
  return concat(head(5, value.size), ...entries);
}

async function sha256(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(data)));
}

/** Raw r||s (64 bytes) → ASN.1 DER, as WebAuthn ES256 signatures require. */
function derSignature(raw: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i += 1;
    let trimmed = bytes.slice(i);
    if ((trimmed[0] ?? 0) & 0x80) trimmed = concat(new Uint8Array([0]), trimmed);
    return concat(new Uint8Array([0x02, trimmed.length]), trimmed);
  };
  const body = concat(integer(raw.slice(0, 32)), integer(raw.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

export interface SoftCredential {
  id: Uint8Array;
  keys: CryptoKeyPair;
  counter: number;
}

export class SoftAuthenticator {
  readonly credentials: SoftCredential[] = [];

  constructor(
    readonly rpId: string,
    readonly origin: string,
  ) {}

  private async authData(flags: number, counter: number, attested?: Uint8Array): Promise<Uint8Array> {
    const count = new Uint8Array([counter >>> 24, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff]);
    return concat(await sha256(encoder.encode(this.rpId)), new Uint8Array([flags]), count, attested ?? new Uint8Array());
  }

  /** navigator.credentials.create() → RegistrationResponseJSON */
  async register(options: { challenge: string }, overrides: { origin?: string; type?: string } = {}) {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
    const fromB64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const cose = cbor(
      new Map<Cbor, Cbor>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, fromB64url(jwk.x ?? "")],
        [-3, fromB64url(jwk.y ?? "")],
      ]),
    );
    const id = crypto.getRandomValues(new Uint8Array(16));
    const attested = concat(new Uint8Array(16), new Uint8Array([0, id.length]), id, cose);
    const authData = await this.authData(0x45, 0, attested); // UP | UV | AT
    const clientData = encoder.encode(
      JSON.stringify({ type: overrides.type ?? "webauthn.create", challenge: options.challenge, origin: overrides.origin ?? this.origin, crossOrigin: false }),
    );
    const attestationObject = cbor(new Map<Cbor, Cbor>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    this.credentials.push({ id, keys, counter: 0 });
    return {
      id: b64url(id),
      rawId: b64url(id),
      type: "public-key",
      response: { clientDataJSON: b64url(clientData), attestationObject: b64url(attestationObject), transports: ["internal"] },
      authenticatorAttachment: "platform",
    };
  }

  /** navigator.credentials.get() → AuthenticationResponseJSON */
  async authenticate(options: { challenge: string }, credential = this.credentials[0]) {
    if (!credential) throw new Error("no credential registered");
    credential.counter += 1;
    const authData = await this.authData(0x05, credential.counter); // UP | UV
    const clientData = encoder.encode(JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin: this.origin, crossOrigin: false }));
    const signed = concat(authData, await sha256(clientData));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, credential.keys.privateKey, signed));
    return {
      id: b64url(credential.id),
      rawId: b64url(credential.id),
      type: "public-key",
      response: { clientDataJSON: b64url(clientData), authenticatorData: b64url(authData), signature: b64url(derSignature(raw)), userHandle: null },
      authenticatorAttachment: "platform",
    };
  }
}
