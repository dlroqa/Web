import { useEffect, useReducer, useRef, useState } from "react";
import { api, ApiRequestError, type PublicConfig } from "../lib/api";
import { PasskeyCancelled, passkeysSupported, signInWithPasskey } from "../lib/passkeys";
import { safeReturnPath, usePageTitle, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import {
  loadTurnstile,
  nextTurnstileState,
  signInBlocked,
  turnstileNeeded,
  turnstileRetryable,
  turnstileStatus,
  TURNSTILE_SLOW_MS,
  type TurnstileState,
} from "../lib/turnstile";
import { Alert } from "../components/ui";
import { GitHubMark, GoogleMark, KeyIcon, LogoMark } from "../components/icons";

/** Messages for the error codes the server may put on /login?error=… */
const CALLBACK_ERRORS: Record<string, string> = {
  account_not_linked: "This email is already registered with a different sign-in method. Use that method to sign in.",
  account_disabled: "This account is not active. Contact support if you think this is a mistake.",
  access_denied: "Sign-in was cancelled.",
  unable_to_create_session: "This account can't sign in right now. Contact support if you think this is a mistake.",
  state_mismatch: "Your sign-in session expired. Please try again.",
};

/** Why the user is here, from ?reason= (only these values are honored). */
const REASON_MESSAGES: Record<string, string> = {
  expired: "Your session expired. Please sign in again.",
  "signed-out": "You've been signed out.",
};

function subtitle(providers: Array<"google" | "github">): string {
  const names = providers.map((p) => (p === "google" ? "Google" : "GitHub"));
  return names.length === 0 ? "Use your passkey to sign in." : `Use a passkey, or continue with your ${names.join(" or ")} account.`;
}

/** The verification state under the sign-in buttons, with a retry once it failed. */
export function TurnstileStatus({ state, onRetry, disabled }: { state: TurnstileState; onRetry: () => void; disabled: boolean }) {
  const text = turnstileStatus(state);
  if (text === null) return null;
  return (
    <>
      <p className="muted small" role="status" aria-live="polite">
        {text}
      </p>
      {turnstileRetryable(state) ? (
        <button type="button" className="button button-ghost" onClick={onRetry} disabled={disabled}>
          Try the verification check again
        </button>
      ) : null}
    </>
  );
}

export function Login() {
  usePageTitle("Sign in");
  const { search, navigate } = useRouter();
  const { session, refresh } = useSession();
  const returnTo = safeReturnPath(search.get("returnTo"));
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [message, setMessage] = useState<{ tone: "error" | "info"; text: string } | null>(() => {
    const code = search.get("error");
    if (code) return { tone: "error", text: CALLBACK_ERRORS[code] ?? "Sign-in didn't complete. Please try again." };
    const reason = search.get("reason");
    if (reason && Object.hasOwn(REASON_MESSAGES, reason)) return { tone: "info", text: REASON_MESSAGES[reason] ?? "" };
    return null;
  });
  const [busy, setBusy] = useState<"passkey" | "google" | "github" | null>(null);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [turnstileState, turnstileEvent] = useReducer(nextTurnstileState, "loading");
  const widgetRef = useRef<HTMLDivElement>(null);
  const widgetId = useRef<string | null>(null);
  const widgetNeeded = config !== null && turnstileNeeded(config, config.passkeys && passkeysSupported());

  useEffect(() => {
    if (session.state === "signed-in") navigate(returnTo, { replace: true });
  }, [session, navigate, returnTo]);

  useEffect(() => {
    api<PublicConfig>("/api/config")
      .then(setConfig)
      .catch(() => setMessage({ tone: "error", text: "Sign-in options couldn't be loaded. Please refresh." }));
  }, []);

  useEffect(() => {
    const siteKey = config?.turnstileSiteKey;
    const container = widgetRef.current;
    if (!siteKey || !container || !turnstileNeeded(config, config.passkeys && passkeysSupported())) return;
    let cancelled = false;
    loadTurnstile()
      .then((turnstile) => {
        if (cancelled || widgetId.current) return;
        widgetId.current = turnstile.render(container, {
          sitekey: siteKey,
          action: "login",
          appearance: "interaction-only",
          callback: (token: string) => {
            setTurnstileToken(token);
            turnstileEvent("token");
          },
          "expired-callback": () => {
            setTurnstileToken(null);
            turnstileEvent("expired");
          },
          // Returns nothing (not "handled"), so the widget still retries on its own.
          "error-callback": () => {
            setTurnstileToken(null);
            turnstileEvent("error");
          },
          "timeout-callback": () => {
            setTurnstileToken(null);
            turnstileEvent("timeout");
          },
          "unsupported-callback": () => turnstileEvent("unsupported"),
          "before-interactive-callback": () => turnstileEvent("interactive"),
          "after-interactive-callback": () => turnstileEvent("interacted"),
        });
        turnstileEvent("rendered");
      })
      .catch(() => {
        turnstileEvent("error");
        setMessage({ tone: "error", text: "The verification check couldn't load. Please refresh the page." });
      });
    return () => {
      cancelled = true;
      // Leaving the page: no callback may outlive it, and a later visit renders afresh.
      if (widgetId.current) window.turnstile?.remove(widgetId.current);
      widgetId.current = null;
    };
  }, [config]);

  // No token long after the widget started loading: say so instead of waiting silently.
  useEffect(() => {
    if (!widgetNeeded || (turnstileState !== "loading" && turnstileState !== "pending")) return;
    const timer = window.setTimeout(() => turnstileEvent("slow"), TURNSTILE_SLOW_MS);
    return () => window.clearTimeout(timer);
  }, [widgetNeeded, turnstileState]);

  // Same widget, new challenge: reset never renders a second widget.
  const resetTurnstile = () => {
    setTurnstileToken(null);
    turnstileEvent("reset");
    if (widgetId.current) window.turnstile?.reset(widgetId.current);
  };

  /** True when a sign-in button must wait for a token; the page then says why. */
  function waitForTurnstile(): boolean {
    const blocked = signInBlocked(turnstileState, turnstileToken);
    if (blocked) setMessage(blocked);
    return blocked !== null;
  }

  async function oauth(provider: "google" | "github") {
    if (waitForTurnstile()) return;
    setBusy(provider);
    setMessage(null);
    try {
      const { url } = await api<{ url: string }>("/api/auth/sign-in/social", { method: "POST", body: { provider, callbackURL: returnTo, turnstileToken } });
      window.location.assign(url);
    } catch (error) {
      setBusy(null);
      resetTurnstile();
      setMessage({ tone: "error", text: error instanceof ApiRequestError ? error.message : "Sign-in failed. Please try again." });
    }
  }

  async function passkey() {
    if (!config?.turnstileSiteKey) {
      setMessage({ tone: "error", text: "The verification check couldn't load. Please refresh the page." });
      return;
    }
    if (waitForTurnstile() || !turnstileToken) return;
    setBusy("passkey");
    setMessage(null);
    try {
      await signInWithPasskey(turnstileToken);
      await refresh();
      navigate(returnTo, { replace: true });
    } catch (error) {
      // The options request spent the token, whatever failed afterwards
      // (including a cancelled ceremony): the next attempt needs a new one.
      resetTurnstile();
      setMessage({
        tone: "error",
        text:
          error instanceof PasskeyCancelled
            ? "No passkey was used. If you haven't added one yet, sign in with Google or GitHub first, then add a passkey under Security."
            : error instanceof ApiRequestError && error.code === "ACCOUNT_DISABLED"
              ? (CALLBACK_ERRORS["account_disabled"] ?? error.message)
              : error instanceof ApiRequestError
                ? error.message
              : "Passkey sign-in failed. Please try again.",
      });
    } finally {
      setBusy(null);
    }
  }

  const providers = config?.providers ?? [];
  const unavailable = config !== null && !config.signInAvailable;

  return (
    <div className="auth-page">
      <main className="auth-card" id="main">
        <div className="auth-brand">
          <LogoMark />
          <h1>Sign in to Lightagent</h1>
          <p className="muted">{subtitle(providers)}</p>
        </div>

        {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
        {unavailable ? <Alert tone="info">Sign-in isn't available on this deployment yet.</Alert> : null}
        {session.state === "blocked" ? <Alert tone="error">This account is not active. Contact support if you think this is a mistake.</Alert> : null}

        <div className="auth-actions">
          {config?.passkeys && passkeysSupported() ? (
            <button type="button" className="button button-primary button-block" onClick={passkey} disabled={busy !== null}>
              <KeyIcon />
              <span>{busy === "passkey" ? "Waiting for your passkey…" : "Continue with passkey"}</span>
            </button>
          ) : null}

          {providers.length > 0 ? <div className="divider" role="separator"><span>or</span></div> : null}

          {providers.includes("google") ? (
            <button type="button" className="button button-secondary button-block" onClick={() => oauth("google")} disabled={busy !== null}>
              <GoogleMark />
              <span>{busy === "google" ? "Redirecting to Google…" : "Continue with Google"}</span>
            </button>
          ) : null}
          {providers.includes("github") ? (
            <button type="button" className="button button-secondary button-block" onClick={() => oauth("github")} disabled={busy !== null}>
              <GitHubMark />
              <span>{busy === "github" ? "Redirecting to GitHub…" : "Continue with GitHub"}</span>
            </button>
          ) : null}
          <div ref={widgetRef} className="turnstile" aria-label="Browser verification" data-turnstile-state={turnstileState} />
          {widgetNeeded ? <TurnstileStatus state={turnstileState} onRetry={resetTurnstile} disabled={busy !== null} /> : null}
        </div>

        <p className="fineprint muted">New here? Signing in creates your account. Adding an agent is a separate step.</p>
      </main>
    </div>
  );
}
