import { createExecutionContext, env as bindings, waitOnExecutionContext } from "cloudflare:test";
import { createWorker } from "../../src/worker/index";
import type { CspMode } from "../../src/worker/security/csp";

/** Matches the trusted development origin in wrangler.jsonc. */
export const BASE = "http://localhost:5173";

/** Shaped like Vite's production index.html with html.cspNonce set. */
export const SHELL_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Lightagent</title>
    <script type="module" crossorigin src="/assets/index-abc123.js" nonce="LIGHTAGENT_CSP_NONCE"></script>
    <link rel="stylesheet" crossorigin href="/assets/index-abc123.css" nonce="LIGHTAGENT_CSP_NONCE">
    <meta property="csp-nonce" nonce="LIGHTAGENT_CSP_NONCE">
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>`;

export interface FakeFile {
  body: string;
  type: string;
}

/** A stand-in for the ASSETS binding with `not_found_handling: "none"`. */
export function fakeAssets(files: Record<string, FakeFile> = {}): Fetcher {
  const all: Record<string, FakeFile> = { "/": { body: SHELL_HTML, type: "text/html; charset=utf-8" }, ...files };
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const file = all[url.pathname];
      return file
        ? new Response(file.body, { headers: { "content-type": file.type, etag: '"shell"' } })
        : new Response("", { status: 404 });
    },
    connect(): Socket {
      throw new Error("not supported in tests");
    },
  };
}

export function testEnv(overrides: Partial<Env> = {}): Env {
  return { ...bindings, ASSETS: fakeAssets(), ...overrides };
}

export interface CallOptions {
  mode?: CspMode;
  env?: Env;
}

/** A random TEST-NET-3 address, like a distinct real client. */
export function randomClientIp(): string {
  const [a = 0, b = 0] = crypto.getRandomValues(new Uint8Array(2));
  return `203.0.${a}.${b}`;
}

/**
 * Send a request through the Worker as the runtime would. Each request comes
 * from a random client address (CF-Connecting-IP) unless the test sets one,
 * so per-IP rate limits behave as they would for real, distinct clients.
 */
export async function call(path: string, init?: RequestInit, options: CallOptions = {}): Promise<Response> {
  const worker = createWorker({ cspMode: options.mode ?? "production" });
  const ctx = createExecutionContext();
  const request = new Request(`${BASE}${path}`, init);
  if (!request.headers.has("cf-connecting-ip")) request.headers.set("cf-connecting-ip", randomClientIp());
  const response = await worker.fetch(request, options.env ?? testEnv(), ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** Extract the script-src nonce authorized by a CSP header. */
export function cspNonce(csp: string | null): string | undefined {
  return csp?.match(/script-src [^;]*'nonce-([^']+)'/)?.[1];
}
