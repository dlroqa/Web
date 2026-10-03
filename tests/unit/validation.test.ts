import { describe, expect, it } from "vitest";
import { z } from "../../src/shared/zod";
import { ApiError } from "../../src/worker/http/errors";
import { parseJsonBody, parseQuery } from "../../src/worker/http/validation";

const CreateAgent = z.object({ agentName: z.string().trim().min(1).max(80) }).strict();

function jsonRequest(body: string, contentType = "application/json"): Request {
  return new Request("http://localhost/api/x", { method: "POST", body, headers: { "content-type": contentType } });
}

async function rejection(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("expected rejection");
}

describe("parseJsonBody", () => {
  it("returns validated, trimmed data", async () => {
    await expect(parseJsonBody(jsonRequest('{"agentName":"  My Agent "}'), CreateAgent)).resolves.toEqual({ agentName: "My Agent" });
  });

  it("accepts a charset parameter", async () => {
    await expect(parseJsonBody(jsonRequest('{"agentName":"a"}', "application/json; charset=utf-8"), CreateAgent)).resolves.toBeDefined();
  });

  it.each(["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", "application/jsonx"])(
    "rejects %s (blocks simple cross-site form posts)",
    async (type) => {
      expect((await rejection(parseJsonBody(jsonRequest('{"agentName":"a"}', type), CreateAgent))).code).toBe("UNSUPPORTED_MEDIA_TYPE");
    },
  );

  it("rejects malformed JSON", async () => {
    expect((await rejection(parseJsonBody(jsonRequest("{nope"), CreateAgent))).code).toBe("INVALID_REQUEST");
  });

  it("rejects bodies over the limit while streaming", async () => {
    const big = JSON.stringify({ agentName: "x".repeat(20_000) });
    expect((await rejection(parseJsonBody(jsonRequest(big), CreateAgent))).code).toBe("PAYLOAD_TOO_LARGE");
  });

  it("rejects privilege-escalation fields under a strict schema", async () => {
    const error = await rejection(
      parseJsonBody(jsonRequest('{"agentName":"a","admin":true,"userId":"usr_other","permissions":{"mcp":true}}'), CreateAgent),
    );
    expect(error.code).toBe("INVALID_REQUEST");
    expect(error.issues?.[0]?.code).toBe("unrecognized_keys");
  });

  it("never reflects input values in issues", async () => {
    const payload = "<script>alert(1)</script>".repeat(10);
    const error = await rejection(parseJsonBody(jsonRequest(JSON.stringify({ agentName: payload })), CreateAgent));
    expect(JSON.stringify(error.issues)).not.toContain("script");
  });
});

describe("parseQuery", () => {
  const Query = z.object({ page: z.coerce.number().int().min(1) }).strict();

  it("parses single-valued parameters", () => {
    expect(parseQuery(new URL("http://x/?page=2"), Query)).toEqual({ page: 2 });
  });

  it("rejects duplicated parameters (parameter pollution)", () => {
    expect(() => parseQuery(new URL("http://x/?page=1&page=2"), Query)).toThrow(ApiError);
  });
});
