/**
 * Same-origin API client. The session lives in an HttpOnly cookie the
 * browser sends automatically; nothing here stores or reads credentials.
 * UI behaviour branches on `code`, never on message text.
 */
import type { AccountStatus } from "../../shared/access";
import type { ErrorCode } from "../../shared/errors";

/**
 * Why a request showed that the session no longer holds: it expired or was
 * revoked (401), or the account's status changed (403). The session provider
 * subscribes and moves the whole app to the right state; pages don't.
 */
export type SessionSignal = "expired" | "status-changed";
const signalListeners = new Set<(signal: SessionSignal) => void>();

export function onSessionSignal(listener: (signal: SessionSignal) => void): () => void {
  signalListeners.add(listener);
  return () => signalListeners.delete(listener);
}

function emit(signal: SessionSignal): void {
  for (const listener of signalListeners) listener(signal);
}

/** The session probe answers "am I signed in?" itself; it never signals. */
const PROBE_PATHS = new Set(["/api/session", "/api/config"]);

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
    const code = envelope.error?.code ?? "INTERNAL_ERROR";
    if (!PROBE_PATHS.has(path)) {
      if (code === "AUTH_REQUIRED") emit("expired");
      else if (code === "ACCOUNT_DISABLED" || code === "ACCOUNT_PENDING") emit("status-changed");
    }
    throw new ApiRequestError(code, envelope.error?.message ?? "Something went wrong.", response.status, envelope.requestId ?? null);
  }
  return envelope.data as T;
}

export interface Me {
  id: string;
  displayName: string | null;
  status: AccountStatus;
}

export interface Overview {
  displayName: string | null;
  status: AccountStatus;
  signIn: { providers: Array<"google" | "github">; passkeys: number };
  sessions: { active: number; currentExpiresAt: number | null };
  agents: { count: number };
}

export interface AgentSummary {
  id: string;
  name: string;
  status: string;
  createdAt: number;
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
