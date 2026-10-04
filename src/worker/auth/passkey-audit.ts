/**
 * What the audit trail records about a passkey: enough to answer "which
 * registered passkey was added/renamed/removed?" without credential material.
 *
 *   target.id            the passkey row id (opaque; also shown to the owner)
 *   metadata.name        the owner's label for it
 *   metadata.fingerprint "sha256:" + the first 16 hex digits of SHA-256 of the
 *                        WebAuthn credential id: correlates with an
 *                        authenticator's credential without storing the id
 *
 * Never recorded: the credential id itself, the public key, counters,
 * attestation or assertion data.
 */
import type { AuditEventInput } from "../audit/audit";
import { sha256Hex } from "../utils/crypto";

export interface PasskeyIdentity {
  id: string;
  name?: string | null;
  credentialID?: string | null;
}

export async function passkeyFingerprint(credentialID: string): Promise<string> {
  return `sha256:${(await sha256Hex(credentialID)).slice(0, 16)}`;
}

/** The `target` and `metadata` of a passkey audit event. */
export async function passkeyAuditFields(passkey: PasskeyIdentity): Promise<Pick<AuditEventInput, "target" | "metadata">> {
  return {
    target: { type: "passkey", id: passkey.id },
    metadata: {
      name: passkey.name ? passkey.name.slice(0, 80) : null,
      fingerprint: passkey.credentialID ? await passkeyFingerprint(passkey.credentialID) : null,
    },
  };
}
