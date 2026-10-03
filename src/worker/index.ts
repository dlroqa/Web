/**
 * Lightagent control-plane Worker.
 *
 * Only `/api/*` and `/health` reach this handler (see `assets.run_worker_first`
 * in wrangler.jsonc); every other path is served from static assets.
 */

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
} as const;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

export default {
  async fetch(request: Request, _env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (pathname === "/health") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json({ ok: false, error: { code: "METHOD_NOT_ALLOWED", message: "Method not allowed." } }, 405);
      }
      // Deliberately minimal: no versions, bindings, or upstream details.
      return json({ status: "ok" });
    }

    return json({ ok: false, error: { code: "NOT_FOUND", message: "Not found." } }, 404);
  },
} satisfies ExportedHandler<Env>;
