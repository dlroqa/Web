/**
 * Same-origin API client. The session lives in an HttpOnly cookie the
 * browser sends automatically; nothing here stores or reads credentials.
 * UI behaviour branches on `code`, never on message text.
 */
import type { ErrorCode } from "../../shared/errors";

export class ApiRequestError extends Error {
  constructor(
    readonly code: ErrorCode | "NETWORK_ERROR",
    message: string,
    readonly status: number,
    readonly requestId: string | null,
  ) {
    super(message);
  }
}

interface Envelope<T> {
  ok: boolean;
  data?: T;
  error?: { code: ErrorCode; message: string };
  requestId?: string;
}

export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: init.method ?? "GET",
      credentials: "same-origin",
      headers: init.body === undefined ? { accept: "application/json" } : { accept: "application/json", "content-type": "application/json" },
      ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
    });
  } catch {
    throw new ApiRequestError("NETWORK_ERROR", "Could not reach the server. Check your connection and try again.", 0, null);
  }
  let envelope: Envelope<T>;
  try {
    envelope = (await response.json()) as Envelope<T>;
  } catch {
    throw new ApiRequestError("INTERNAL_ERROR", "Something went wrong.", response.status, null);
  }
  if (!response.ok || !envelope.ok) {
    throw new ApiRequestError(envelope.error?.code ?? "INTERNAL_ERROR", envelope.error?.message ?? "Something went wrong.", response.status, envelope.requestId ?? null);
  }
  return envelope.data as T;
}

export interface Me {
  id: string;
  displayName: string | null;
  status: "active" | "pending" | "suspended" | "disabled";
}

export interface PublicConfig {
  signInAvailable: boolean;
  providers: Array<"google" | "github">;
  passkeys: boolean;
  turnstileSiteKey: string | null;
}

export interface SessionInfo {
  id: string;
  device: string;
  createdAt: number | null;
  lastActiveAt: number | null;
  expiresAt: number | null;
  current: boolean;
}

export interface PasskeyInfo {
  id: string;
  name: string | null;
  deviceType: "synced" | "device-bound";
  backedUp: boolean;
  createdAt: number | null;
}

export interface ActivityEvent {
  id: string;
  timestamp: number;
  action: string;
  result: "success" | "failure" | "denied";
  country: string | null;
}
