/**
 * Drive real sign-in flows through the Worker with the identity providers
 * replaced at the network boundary (fetch). Better Auth runs unmodified:
 * state cookies, PKCE, token exchange, id_token verification, account
 * creation, and session cookies are all real.
 */
import { vi, type MockInstance } from "vitest";
import { randomId } from "../../src/worker/utils/random";
import { CookieJar } from "./cookies";
import { BASE, call, type CallOptions } from "./worker";

export interface Identity {
  provider: "google" | "github";
  sub: string;
  email: string;
  emailVerified: boolean;
  name: string;
}

export function identity(provider: Identity["provider"], overrides: Partial<Identity> = {}): Identity {
  const sub = overrides.sub ?? String(Math.floor(Math.random() * 1e12));
  return { provider, sub, email: `${randomId("u")}@example.test`, emailVerified: true, name: "Test User", ...overrides };
}

function b64url(data: string | Uint8Array): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Records every outbound request body so tests can assert nothing leaks. */
export class FakeProviders {
  readonly codes = new Map<string, Identity & { nonce?: string }>();
  readonly outbound: string[] = [];
  readonly issuedTokens: string[] = [];
  private keys: CryptoKeyPair | undefined;
  private spy: MockInstance<typeof fetch> | undefined;
  turnstile: "pass" | "fail" = "pass";
  googleTokenStatus = 200;

  private async signingKeys(): Promise<CryptoKeyPair> {
    this.keys ??= (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    return this.keys;
  }

  private async idToken(who: Identity & { nonce?: string }): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: "RS256", kid: "test-key", typ: "JWT" }));
    const payload = b64url(
      JSON.stringify({
        iss: "https://accounts.google.com",
        aud: "test-google-client-id",
        sub: who.sub,
        email: who.email,
        email_verified: who.emailVerified,
        name: who.name,
        iat: now,
        exp: now + 600,
        ...(who.nonce ? { nonce: who.nonce } : {}),
      }),
    );
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", (await this.signingKeys()).privateKey, new TextEncoder().encode(`${header}.${payload}`));
    return `${header}.${payload}.${b64url(new Uint8Array(signature))}`;
  }

  private token(prefix: string): string {
    const token = `${prefix}-${randomId("tok")}`;
    this.issuedTokens.push(token);
    return token;
  }

  install(): this {
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    this.spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      const body = request.method === "GET" ? "" : await request.clone().text();
      this.outbound.push(`${request.method} ${url.origin}${url.pathname} ${body}`);
      const form = new URLSearchParams(body);
      switch (`${url.origin}${url.pathname}`) {
        case "https://challenges.cloudflare.com/turnstile/v0/siteverify":
          return this.turnstile === "pass"
            ? json({ success: true, "error-codes": [], hostname: "example.com", challenge_ts: new Date().toISOString(), metadata: { result_with_testing_key: true } })
            : json({ success: false, "error-codes": ["invalid-input-response"] });
        case "https://oauth2.googleapis.com/token": {
          const who = this.codes.get(form.get("code") ?? "");
          if (!who || this.googleTokenStatus !== 200) return json({ error: "invalid_grant", error_description: "secret provider detail" }, this.googleTokenStatus === 200 ? 400 : this.googleTokenStatus);
          return json({ access_token: this.token("google-access"), id_token: await this.idToken(who), expires_in: 3600, token_type: "Bearer", scope: "openid email profile" });
        }
        case "https://www.googleapis.com/oauth2/v3/certs": {
          const jwk = await crypto.subtle.exportKey("jwk", (await this.signingKeys()).publicKey);
          return json({ keys: [{ ...jwk, kid: "test-key", alg: "RS256", use: "sig" }] });
        }
        case "https://github.com/login/oauth/access_token": {
          const who = this.codes.get(form.get("code") ?? "");
          if (!who) return json({ error: "bad_verification_code" });
          return json({ access_token: `${this.token("github-access")}::${who.sub}`, token_type: "bearer", scope: "read:user,user:email" });
        }
        case "https://api.github.com/user":
        case "https://api.github.com/user/emails": {
          const sub = (request.headers.get("authorization") ?? "").split("::")[1];
          const who = [...this.codes.values()].find((w) => w.provider === "github" && w.sub === sub);
          if (!who) return json({ message: "Bad credentials" }, 401);
          if (url.pathname === "/user") return json({ id: Number(who.sub), login: `user${who.sub}`, name: who.name, email: who.email, avatar_url: null });
          return json([{ email: who.email, primary: true, verified: who.emailVerified, visibility: "private" }]);
        }
        default:
          throw new Error(`unexpected outbound request to ${url.origin}${url.pathname}`);
      }
    });
    return this;
  }

  restore(): void {
    this.spy?.mockRestore();
  }
}

export interface SignInResult {
  start: Response;
  callback: Response;
  location: string | null;
  authorizationUrl: URL;
}

/** Full OAuth sign-in: start (Turnstile + state) → provider → callback. */
export async function signIn(
  providers: FakeProviders,
  who: Identity,
  jar: CookieJar,
  options: CallOptions & { callbackURL?: string } = {},
): Promise<SignInResult> {
  const start = await call(
    "/api/auth/sign-in/social",
    {
      method: "POST",
      headers: { origin: BASE, "content-type": "application/json", cookie: jar.header() },
      body: JSON.stringify({ provider: who.provider, callbackURL: options.callbackURL ?? "/dashboard", turnstileToken: "XXXX.DUMMY.TOKEN.XXXX" }),
    },
    options,
  );
  jar.store(start);
  if (start.status !== 200) throw new Error(`sign-in start failed: ${start.status} ${await start.text()}`);
  const { data } = (await start.json()) as { data: { url: string } };
  const authorizationUrl = new URL(data.url);
  const state = authorizationUrl.searchParams.get("state") ?? "";
  const code = randomId("code");
  const nonce = authorizationUrl.searchParams.get("nonce") ?? undefined;
  providers.codes.set(code, { ...who, ...(nonce ? { nonce } : {}) });
  const callback = await call(`/api/auth/callback/${who.provider}?code=${code}&state=${encodeURIComponent(state)}`, { headers: { cookie: jar.header() } }, options);
  jar.store(callback);
  return { start, callback, location: callback.headers.get("location"), authorizationUrl };
}

/** GET an API path with the jar's cookies. */
export async function get(path: string, jar: CookieJar, options: CallOptions = {}): Promise<Response> {
  return call(path, { headers: { cookie: jar.header() } }, options);
}

/** Send a state-changing API request from the trusted origin with the jar's cookies. */
export async function send(method: string, path: string, jar: CookieJar, body?: unknown, options: CallOptions = {}): Promise<Response> {
  const response = await call(
    path,
    {
      method,
      headers: { origin: BASE, cookie: jar.header(), ...(body === undefined ? {} : { "content-type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    },
    options,
  );
  jar.store(response);
  return response;
}
