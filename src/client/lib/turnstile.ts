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
