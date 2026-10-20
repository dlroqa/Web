/**
 * Cloudflare Turnstile, loaded only on the login page from its exact origin
 * (allowed by the CSP). The token is single-use; reset after each attempt.
 */
import type { PublicConfig } from "./api";

interface TurnstileApi {
  render(container: HTMLElement, options: Record<string, unknown>): string;
  reset(widgetId: string): void;
  remove(widgetId: string): void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

/**
 * Whether the login page needs the widget: some button on it spends a token
 * (OAuth sign-in start, passkey sign-in options).
 */
export function turnstileNeeded(config: Pick<PublicConfig, "providers" | "turnstileSiteKey">, passkeyButton: boolean): boolean {
  return config.turnstileSiteKey !== null && (config.providers.length > 0 || passkeyButton);
}

/**
 * Where the widget is, driven by its callbacks. Only "ready" holds a token;
 * the login page shows every other state, so a sign-in button never waits
 * silently (P2: an `interaction-only` widget gave no sign at all).
 */
export type TurnstileState = "loading" | "pending" | "interactive" | "ready" | "expired" | "error" | "timeout" | "unsupported";

export type TurnstileEvent =
  | "rendered" // turnstile.render returned
  | "token" // callback
  | "expired" // expired-callback (the widget refreshes on its own)
  | "error" // error-callback, or the script failed to load (the widget retries on its own)
  | "timeout" // timeout-callback (an interactive challenge was not answered)
  | "unsupported" // unsupported-callback
  | "interactive" // before-interactive-callback
  | "interacted" // after-interactive-callback
  | "slow" // no token TURNSTILE_SLOW_MS after loading started (watchdog)
  | "reset"; // the token was spent or the user asked to retry

/** No token this long after the widget starts loading: say so (it keeps trying). */
export const TURNSTILE_SLOW_MS = 15_000;

export function nextTurnstileState(state: TurnstileState, event: TurnstileEvent): TurnstileState {
  switch (event) {
    case "token":
      return "ready";
    case "rendered":
      return state === "loading" ? "pending" : state;
    case "interacted":
      return state === "interactive" ? "pending" : state;
    case "slow":
      return state === "loading" || state === "pending" ? "timeout" : state;
    case "reset":
      return state === "unsupported" ? state : "pending";
    default:
      return event;
  }
}

const STATUS: Record<Exclude<TurnstileState, "ready">, string> = {
  loading: "Verifying your browser…",
  pending: "Verifying your browser…",
  interactive: "Please complete the verification check below.",
  expired: "The verification check expired. Refreshing it…",
  error: "The verification check failed. Try again, or refresh the page.",
  timeout: "The verification check is taking longer than usual. Try again, or refresh the page.",
  unsupported: "This browser can't complete the verification check. Try another browser.",
};

/** The line shown under the sign-in buttons; null once a token is in hand. */
export function turnstileStatus(state: TurnstileState): string | null {
  return state === "ready" ? null : STATUS[state];
}

/** States that offer a manual retry (a widget reset, never a new widget). */
export function turnstileRetryable(state: TurnstileState): boolean {
  return state === "error" || state === "timeout" || state === "expired";
}

/**
 * Why a sign-in button pressed now must not spend a request, or null when it
 * may (a token is in hand). No token, no request: the options and sign-in
 * start requests are only ever sent with a token.
 */
export function signInBlocked(state: TurnstileState, token: string | null): { tone: "info" | "error"; text: string } | null {
  if (token) return null;
  const failed = turnstileRetryable(state) || state === "unsupported";
  return { tone: failed ? "error" : "info", text: turnstileStatus(state) ?? STATUS.pending };
}

const SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
let loading: Promise<TurnstileApi> | null = null;

export function loadTurnstile(): Promise<TurnstileApi> {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  loading ??= new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = SCRIPT_URL;
    script.async = true;
    script.onload = () => (window.turnstile ? resolve(window.turnstile) : reject(new Error("Turnstile unavailable")));
    script.onerror = () => {
      loading = null;
      reject(new Error("Turnstile failed to load"));
    };
    document.head.appendChild(script);
  });
  return loading;
}
