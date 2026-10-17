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

/**
 * Ceremony options come back as Better Auth's JSON (not the API envelope);
 * errors in the envelope's shape. With a body, the request is a JSON POST.
 */
async function optionsJson<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(
    path,
    body === undefined
      ? { credentials: "same-origin", headers: { accept: "application/json" } }
      : { method: "POST", credentials: "same-origin", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify(body) },
  );
  if (!response.ok) {
    const error = (await response.json().catch(() => null)) as { error?: { code: string; message: string } } | null;
    throw new ApiRequestError((error?.error?.code as never) ?? "INTERNAL_ERROR", error?.error?.message ?? "Something went wrong.", response.status, null);
  }
  return (await response.json()) as T;
}

/**
 * Passkey sign-in. The options request spends `turnstileToken` (single use),
 * whatever happens afterwards; the caller resets the widget.
 */
export async function signInWithPasskey(turnstileToken: string): Promise<void> {
  const options = await optionsJson<AuthOptions>("/api/auth/passkey/generate-authenticate-options", { turnstileToken });
  const assertion = await ceremony(() => startAuthentication({ optionsJSON: options }));
  const { clientExtensionResults: _ignored, ...response } = assertion;
  await api("/api/auth/passkey/verify-authentication", { method: "POST", body: { response } });
}

export async function addPasskey(name: string): Promise<void> {
  const options = await optionsJson<Options>(`/api/auth/passkey/generate-register-options?name=${encodeURIComponent(name)}`);
  const credential = await ceremony(() => startRegistration({ optionsJSON: options }));
  const { clientExtensionResults: _ignored, ...response } = credential;
  await api("/api/auth/passkey/verify-registration", { method: "POST", body: { response, name } });
}

export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function";
}
