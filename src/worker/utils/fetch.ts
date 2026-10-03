/**
 * Outbound HTTP with a mandatory finite timeout.
 *
 * Every external call (Turnstile, OAuth back-channel, Lightagent provisioning)
 * goes through `fetchWithTimeout`. Redirects are not followed by default, so a
 * compromised or misconfigured upstream cannot bounce the Worker to another
 * host (SSRF). No retries happen here; callers decide what is safe to retry.
 */

export const DEFAULT_TIMEOUT_MS = 5_000;
export const MAX_TIMEOUT_MS = 30_000;

export class UpstreamTimeoutError extends Error {
  override readonly name = "UpstreamTimeoutError";
  constructor(readonly timeoutMs: number) {
    super(`upstream request exceeded ${timeoutMs} ms`);
  }
}

export class UpstreamNetworkError extends Error {
  override readonly name = "UpstreamNetworkError";
}

export class UpstreamResponseTooLargeError extends Error {
  override readonly name = "UpstreamResponseTooLargeError";
}

export type FetchFn = (input: Request | string | URL, init?: RequestInit) => Promise<Response>;

export interface TimeoutOptions {
  timeoutMs?: number;
  /** An additional caller signal (e.g. the incoming request's). */
  signal?: AbortSignal;
  /** Injected for tests; defaults to the global fetch. */
  fetchFn?: FetchFn;
}

export async function fetchWithTimeout(
  input: string | URL,
  init: RequestInit = {},
  options: TimeoutOptions = {},
): Promise<Response> {
  const timeoutMs = Math.min(Math.max(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1), MAX_TIMEOUT_MS);
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const signal = options.signal ? AbortSignal.any([timeoutSignal, options.signal]) : timeoutSignal;
  const fetchFn = options.fetchFn ?? fetch;
  try {
    return await fetchFn(input, { redirect: "manual", ...init, signal });
  } catch (error) {
    if (timeoutSignal.aborted) {
      throw new UpstreamTimeoutError(timeoutMs);
    }
    if (options.signal?.aborted) {
      throw error;
    }
    throw new UpstreamNetworkError("upstream request failed", { cause: error });
  }
}

/** Read at most `maxBytes` of a body as text; larger bodies are rejected. */
export async function readBoundedText(body: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<string> {
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new UpstreamResponseTooLargeError(`body exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(merged);
}
