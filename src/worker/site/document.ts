/**
 * HTML documents and non-hashed static files.
 *
 * Every HTML response is the built `index.html` with each `nonce` attribute
 * (written by Vite as a placeholder) replaced by a fresh per-response nonce
 * that the CSP header authorizes. Only elements Vite marked get the nonce; an
 * unmarked inline script is left without one and is blocked by the CSP.
 * Hashed files under /assets/* never reach this code (see wrangler.jsonc).
 */
import type { RequestContext } from "../http/context";
import { applyDocumentHeaders, applyStaticHeaders } from "../security/headers";
import { generateNonce, type CspMode } from "../security/csp";

function textResponse(status: number, text: string, ctx: RequestContext): Response {
  const response = new Response(text, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
  return applyStaticHeaders(response, ctx.config, ctx.url);
}

/** Paths whose last segment has a file extension (other than .html) are files. */
export function isFilePath(pathname: string): boolean {
  const last = pathname.slice(pathname.lastIndexOf("/") + 1);
  return last.includes(".") && !last.toLowerCase().endsWith(".html");
}

/**
 * Vite dev-server module paths, many without a file extension
 * (`/@vite/client`, `/@react-refresh`). Only honoured in development; a
 * production build has no such modules and serves the document instead.
 */
export function isViteDevPath(pathname: string): boolean {
  return pathname.startsWith("/@") || pathname.startsWith("/src/") || pathname.startsWith("/node_modules/");
}

export async function serveSite(ctx: RequestContext, mode: CspMode): Promise<Response> {
  const { request, url, env } = ctx;
  if (request.method !== "GET" && request.method !== "HEAD") {
    return textResponse(405, "Method not allowed.", ctx);
  }

  if (isFilePath(url.pathname) || (mode === "development" && isViteDevPath(url.pathname))) {
    const asset = await env.ASSETS.fetch(request);
    if (asset.status === 404) {
      await asset.body?.cancel();
      return textResponse(404, "Not found.", ctx);
    }
    return applyStaticHeaders(asset, ctx.config, url);
  }

  return serveDocument(ctx, mode);
}

export async function serveDocument(ctx: RequestContext, mode: CspMode): Promise<Response> {
  const { request, url, env, logger } = ctx;
  const shell = await env.ASSETS.fetch(new Request(new URL("/", url), { headers: { accept: "text/html" } }));
  const contentType = shell.headers.get("content-type") ?? "";
  if (!shell.ok || !contentType.toLowerCase().startsWith("text/html")) {
    await shell.body?.cancel();
    logger.error("document.shell_unavailable", { status: shell.status });
    return textResponse(500, "Something went wrong.", ctx);
  }

  const nonce = generateNonce();
  const rewritten = new HTMLRewriter()
    .on("[nonce]", {
      element(element) {
        element.setAttribute("nonce", nonce);
      },
    })
    .transform(shell);

  const body = request.method === "HEAD" ? null : rewritten.body;
  if (body === null) await rewritten.body?.cancel();
  const response = applyDocumentHeaders(new Response(body, { status: 200 }), nonce, mode, ctx.config, url);
  response.headers.set("x-request-id", ctx.requestId);
  return response;
}
