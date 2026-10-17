/**
 * Passkey sign-in from the browser (M3a): the options request is a JSON POST
 * carrying the Turnstile token, and the login page renders the widget
 * whenever a button on it spends a token. WebAuthn and the network are stubbed.
 */
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";

const webauthn = vi.hoisted(() => ({
  startAuthentication: vi.fn(async () => ({ id: "cred", rawId: "cred", type: "public-key", response: { signature: "sig" }, clientExtensionResults: {} })),
}));
vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication: webauthn.startAuthentication,
  startRegistration: vi.fn(),
  WebAuthnError: class WebAuthnError extends Error {},
}));

import { ApiRequestError } from "../../src/client/lib/api";
import { signInWithPasskey } from "../../src/client/lib/passkeys";
import { turnstileNeeded } from "../../src/client/lib/turnstile";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
type FetchFn = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
let fetchMock: Mock<FetchFn>;

beforeEach(() => {
  webauthn.startAuthentication.mockClear();
  fetchMock = vi.fn<FetchFn>();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("signInWithPasskey", () => {
  it("requests options with a JSON POST carrying the token, then verifies the assertion", async () => {
    fetchMock.mockResolvedValueOnce(json({ challenge: "c2lnbg", allowCredentials: [] })).mockResolvedValueOnce(json({ ok: true, data: { signedIn: true } }));
    await signInWithPasskey("turnstile-token-1");

    const [optionsUrl, optionsInit] = fetchMock.mock.calls[0] ?? [];
    expect(optionsUrl).toBe("/api/auth/passkey/generate-authenticate-options");
    expect(optionsInit?.method).toBe("POST");
    expect(optionsInit?.credentials).toBe("same-origin");
    expect(optionsInit?.headers).toMatchObject({ "content-type": "application/json" });
    expect(JSON.parse(String(optionsInit?.body))).toEqual({ turnstileToken: "turnstile-token-1" });

    expect(webauthn.startAuthentication).toHaveBeenCalledTimes(1);
    const [verifyUrl, verifyInit] = fetchMock.mock.calls[1] ?? [];
    expect(verifyUrl).toBe("/api/auth/passkey/verify-authentication");
    expect(verifyInit?.method).toBe("POST");
    // Client extension results are not sent on.
    expect(JSON.parse(String(verifyInit?.body))).toEqual({ response: { id: "cred", rawId: "cred", type: "public-key", response: { signature: "sig" } } });
  });

  it("stops before the ceremony when the token is refused", async () => {
    fetchMock.mockResolvedValueOnce(json({ ok: false, error: { code: "TURNSTILE_FAILED", message: "Human verification failed. Please try again." } }, 403));
    const error = await signInWithPasskey("spent-token").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiRequestError);
    expect((error as ApiRequestError).code).toBe("TURNSTILE_FAILED");
    expect((error as ApiRequestError).status).toBe(403);
    expect(webauthn.startAuthentication).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("turnstileNeeded", () => {
  const config = (providers: Array<"google" | "github">, turnstileSiteKey: string | null) => ({ providers, turnstileSiteKey });

  it("renders the widget for OAuth buttons, and for a passkey button alone", () => {
    expect(turnstileNeeded(config(["google"], "site-key"), false)).toBe(true);
    expect(turnstileNeeded(config([], "site-key"), true)).toBe(true);
    expect(turnstileNeeded(config(["github"], "site-key"), true)).toBe(true);
  });

  it("does not render it with nothing to protect or without a site key", () => {
    expect(turnstileNeeded(config([], "site-key"), false)).toBe(false);
    expect(turnstileNeeded(config(["google"], null), true)).toBe(false);
  });
});
