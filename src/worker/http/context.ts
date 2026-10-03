import type { AppConfig } from "../config/config";
import type { Logger } from "../utils/log";
import { randomId } from "../utils/random";

/** Per-request state, passed explicitly (never stored at module scope). */
export interface RequestContext {
  readonly requestId: string;
  readonly request: Request;
  readonly url: URL;
  readonly env: Env;
  readonly config: AppConfig;
  readonly logger: Logger;
  readonly waitUntil: (promise: Promise<unknown>) => void;
}

/**
 * A fresh random request id (`req_…`). Never derived from user ids, emails,
 * session ids, or IP addresses, and never accepted from the client.
 */
export function newRequestId(): string {
  return randomId("req");
}
