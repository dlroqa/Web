/**
 * Lightagent control-plane Worker.
 *
 * Every request except hashed /assets/* comes here (wrangler.jsonc
 * `run_worker_first`). API paths return JSON; everything else is the SPA
 * document (with a per-response CSP nonce) or a static file.
 */
import { handleApi, isApiPath } from "./api/router";
import { ConfigError, loadConfig, type AppConfig } from "./config/config";
import { DbError, toApiError } from "./db/errors";
import { newRequestId, type RequestContext } from "./http/context";
import { ApiError } from "./http/errors";
import { jsonError } from "./http/responses";
import type { CspMode } from "./security/csp";
import { applyStaticHeaders } from "./security/headers";
import { serveSite } from "./site/document";
import { createLogger, describeError } from "./utils/log";

export interface WorkerOptions {
  /** "development" only under `vite dev`; production builds always use "production". */
  cspMode: CspMode;
}

function plainError(status: number, config: AppConfig | undefined, url: URL): Response {
  const text = status === 500 ? "Something went wrong." : "Request failed.";
  const response = new Response(text, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
  return applyStaticHeaders(response, config, url);
}

export function createWorker(options: WorkerOptions) {
  return {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
      const startedAt = Date.now();
      const requestId = newRequestId();
      const url = new URL(request.url);
      const isApi = isApiPath(url.pathname);
      const logger = createLogger({ requestId });

      let config: AppConfig;
      try {
        config = loadConfig(env);
      } catch (error) {
        logger.error("config.invalid", error instanceof ConfigError ? { detail: error.message } : describeError(error));
        return isApi
          ? jsonError("INTERNAL_ERROR", { requestId, config: undefined, url })
          : plainError(500, undefined, url);
      }

      const context: RequestContext = {
        requestId,
        request,
        url,
        env,
        config,
        logger,
        waitUntil: (promise) => ctx.waitUntil(promise),
      };
      const meta = { requestId, config, url };

      let response: Response;
      try {
        response = isApi ? await handleApi(context) : await serveSite(context, options.cspMode);
      } catch (thrown) {
        // Database errors become stable API errors; raw SQL text never escapes.
        const error = thrown instanceof DbError ? toApiError(thrown) : thrown;
        if (error instanceof ApiError) {
          logger.warn("request.rejected", { code: error.code, reason: error.logReason });
          response = isApi ? jsonError(error, meta) : plainError(error.status, config, url);
        } else {
          logger.error("request.failed", describeError(error));
          response = isApi ? jsonError("INTERNAL_ERROR", meta) : plainError(500, config, url);
        }
      }

      if (isApi) {
        // Path only: query strings may carry values that should not be logged.
        logger.info("api.request", { method: request.method, path: url.pathname, status: response.status, durationMs: Date.now() - startedAt });
      }
      return response;
    },
  } satisfies ExportedHandler<Env>;
}

export default createWorker({ cspMode: import.meta.env.DEV ? "development" : "production" });
