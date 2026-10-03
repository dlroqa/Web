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

/** Send a request through the Worker as the runtime would. */
export async function call(path: string, init?: RequestInit, options: CallOptions = {}): Promise<Response> {
  const worker = createWorker({ cspMode: options.mode ?? "production" });
  const ctx = createExecutionContext();
  const response = await worker.fetch(new Request(`${BASE}${path}`, init), options.env ?? testEnv(), ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

/** Extract the script-src nonce authorized by a CSP header. */
export function cspNonce(csp: string | null): string | undefined {
  return csp?.match(/script-src [^;]*'nonce-([^']+)'/)?.[1];
}
