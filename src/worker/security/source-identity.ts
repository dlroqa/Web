/**
 * Network source identity for audit events, without storing raw IPs.
 *
 * The client address (CF-Connecting-IP) is reduced to an HMAC-SHA256 under
 * the AUDIT_SOURCE_HMAC_KEY Worker secret. Equal hashes mean "same source";
 * without the key the address cannot be recovered or brute-forced offline
 * (the IPv4 space is small enough that an unkeyed hash would be reversible).
 *
 * The key id is stored alongside each hash so the key can be rotated: hashes
 * are only comparable within one key id. When the secret is unset, events
 * carry no source hash (never a raw address).
 */
import type { SecurityMetadata } from "../db/json";
import { readSecret } from "../config/secrets";
import { base64ToBytes, hmacSha256Hex } from "../utils/crypto";

/** Bump when AUDIT_SOURCE_HMAC_KEY is rotated. */
export const SOURCE_KEY_ID = "k1";
const MIN_KEY_BYTES = 32;

export class SourceKeyError extends Error {
  override readonly name = "SourceKeyError";
}

export function decodeSourceKey(secret: string): Uint8Array {
  let key: Uint8Array;
  try {
    key = base64ToBytes(secret.trim());
  } catch {
    throw new SourceKeyError("AUDIT_SOURCE_HMAC_KEY must be base64");
  }
  if (key.byteLength < MIN_KEY_BYTES) {
    throw new SourceKeyError(`AUDIT_SOURCE_HMAC_KEY must be at least ${MIN_KEY_BYTES} bytes`);
  }
  return key;
}

/** Canonical text form so one address always hashes the same way. */
export function normalizeAddress(address: string): string {
  return address.trim().toLowerCase();
}

export async function hashSource(address: string, key: Uint8Array): Promise<string> {
  return hmacSha256Hex(key, `lightagent-audit-source:v1:${normalizeAddress(address)}`);
}

/** Build the security metadata for an incoming request. */
export async function securityMetadataFor(request: Request, env: Env): Promise<SecurityMetadata> {
  const metadata: SecurityMetadata = {};
  const country: unknown = (request as Request & { cf?: { country?: unknown } }).cf?.country;
  if (typeof country === "string" && /^[A-Z]{2}$/.test(country)) metadata.country = country;

  const address = request.headers.get("cf-connecting-ip");
  const secret = readSecret(env, "AUDIT_SOURCE_HMAC_KEY");
  if (address && secret) {
    metadata.sourceHash = await hashSource(address, decodeSourceKey(secret));
    metadata.sourceKeyId = SOURCE_KEY_ID;
  }
  return metadata;
}
