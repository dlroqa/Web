import { describe, expect, it } from "vitest";
import {
  fetchWithTimeout,
  readBoundedText,
  UpstreamNetworkError,
  UpstreamResponseTooLargeError,
  UpstreamTimeoutError,
  type FetchFn,
} from "../../src/worker/utils/fetch";

/** A fetch that never answers but honours its abort signal. */
const hanging: FetchFn = (_input, init) =>
  new Promise((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
  });

describe("fetchWithTimeout", () => {
  it("aborts a hanging request after the timeout", async () => {
    const started = Date.now();
    await expect(fetchWithTimeout("https://upstream.test", {}, { timeoutMs: 50, fetchFn: hanging })).rejects.toBeInstanceOf(UpstreamTimeoutError);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("clamps absurd timeouts to a finite maximum", async () => {
    let seen: AbortSignal | undefined;
    const capture: FetchFn = async (_i, init) => {
      seen = init?.signal ?? undefined;
      return new Response("ok");
    };
    await fetchWithTimeout("https://upstream.test", {}, { timeoutMs: Number.POSITIVE_INFINITY, fetchFn: capture });
    expect(seen).toBeInstanceOf(AbortSignal);
  });

  it("does not follow redirects by default", async () => {
    let redirect: RequestInit["redirect"];
    const capture: FetchFn = async (_i, init) => {
      redirect = init?.redirect;
      return new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } });
    };
    const response = await fetchWithTimeout("https://upstream.test", {}, { fetchFn: capture });
    expect(redirect).toBe("manual");
    expect(response.status).toBe(302);
  });

  it("wraps network failures without exposing their details", async () => {
    const failing: FetchFn = () => Promise.reject(new TypeError("connect ECONNREFUSED 10.0.0.5:8735"));
    await expect(fetchWithTimeout("https://upstream.test", {}, { fetchFn: failing })).rejects.toBeInstanceOf(UpstreamNetworkError);
  });

  it("propagates a caller abort as an abort, not a timeout", async () => {
    const controller = new AbortController();
    const pending = fetchWithTimeout("https://upstream.test", {}, { timeoutMs: 5_000, signal: controller.signal, fetchFn: hanging });
    controller.abort();
    await expect(pending).rejects.not.toBeInstanceOf(UpstreamTimeoutError);
  });
});

describe("readBoundedText", () => {
  it("reads bodies within the limit", async () => {
    expect(await readBoundedText(new Response("hello").body, 10)).toBe("hello");
  });

  it("rejects bodies over the limit", async () => {
    await expect(readBoundedText(new Response("x".repeat(100)).body, 10)).rejects.toBeInstanceOf(UpstreamResponseTooLargeError);
  });

  it("rejects invalid UTF-8", async () => {
    await expect(readBoundedText(new Response(new Uint8Array([0xff, 0xfe])).body, 10)).rejects.toThrow();
  });
});
