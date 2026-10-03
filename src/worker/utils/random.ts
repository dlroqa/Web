/** Cryptographically random identifiers. Never use Math.random for these. */

const ID_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";

/**
 * A random lowercase identifier with a type prefix, e.g. `req_k3…`.
 *
 * 26 base-36 characters ≈ 134 bits of entropy. Output matches Lightagent's
 * ProfileId rule (`^[a-z0-9][a-z0-9_-]{0,63}$`), so `agt_` ids can be used as
 * harness profile ids unchanged.
 */
export function randomId(prefix: string, length = 26): string {
  // Rejection sampling avoids modulo bias: 252 = 7 × 36.
  const out: string[] = [];
  while (out.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length * 2));
    for (const byte of bytes) {
      if (byte < 252 && out.length < length) {
        out.push(ID_ALPHABET[byte % 36] as string);
      }
    }
  }
  return `${prefix}_${out.join("")}`;
}

/** Base64 encoding of `byteLength` random bytes (no padding issues for CSP). */
export function randomBase64(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}
