/**
 * Passkey ceremonies. WebAuthn itself is done by the browser and
 * @simplewebauthn/browser; options and verification come from Better Auth
 * through the Worker. No credential material is kept in JavaScript.
 */
import { startAuthentication, startRegistration, WebAuthnError } from "@simplewebauthn/browser";
import { api, ApiRequestError } from "./api";

export class PasskeyCancelled extends Error {}

type Options = Parameters<typeof startRegistration>[0]["optionsJSON"];
type AuthOptions = Parameters<typeof startAuthentication>[0]["optionsJSON"];

async function ceremony<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof WebAuthnError || (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError"))) {
      throw new PasskeyCancelled("The passkey request was cancelled or timed out.");
    }
    throw error;
  }
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", headers: { accept: "application/json" } });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: { code: string; message: string } } | null;
    throw new ApiRequestError((body?.error?.code as never) ?? "INTERNAL_ERROR", body?.error?.message ?? "Something went wrong.", response.status, null);
  }
  return (await response.json()) as T;
}

export async function signInWithPasskey(): Promise<void> {
  const options = await getJson<AuthOptions>("/api/auth/passkey/generate-authenticate-options");
  const assertion = await ceremony(() => startAuthentication({ optionsJSON: options }));
  const { clientExtensionResults: _ignored, ...response } = assertion;
  await api("/api/auth/passkey/verify-authentication", { method: "POST", body: { response } });
}

export async function addPasskey(name: string): Promise<void> {
  const options = await getJson<Options>(`/api/auth/passkey/generate-register-options?name=${encodeURIComponent(name)}`);
  const credential = await ceremony(() => startRegistration({ optionsJSON: options }));
  const { clientExtensionResults: _ignored, ...response } = credential;
  await api("/api/auth/passkey/verify-registration", { method: "POST", body: { response, name } });
}

export function passkeysSupported(): boolean {
  return typeof window.PublicKeyCredential === "function";
}
