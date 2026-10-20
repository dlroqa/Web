/**
 * M3.1: the login page never waits silently for Turnstile (P2, Safari macOS:
 * a passkey click gave no sign and sent no request). The widget's state
 * machine, the click gate (no token, no request), the status line, and the
 * Login wiring (callbacks, watchdog, reset without a second widget, cleanup).
 * No browser here: real clicks in Safari remain an operator check in P2.
 */
import { readFileSync } from "node:fs";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import {
  nextTurnstileState,
  signInBlocked,
  turnstileRetryable,
  turnstileStatus,
  TURNSTILE_SLOW_MS,
  type TurnstileEvent,
  type TurnstileState,
} from "../../src/client/lib/turnstile";
import { TurnstileStatus } from "../../src/client/pages/Login";

const STATES: TurnstileState[] = ["loading", "pending", "interactive", "ready", "expired", "error", "timeout", "unsupported"];
const run = (events: TurnstileEvent[], from: TurnstileState = "loading") => events.reduce(nextTurnstileState, from);

describe("Turnstile state machine", () => {
  it("a delayed token moves the page from verifying to ready", () => {
    expect(run(["rendered"])).toBe("pending");
    expect(run(["rendered", "token"])).toBe("ready");
    expect(run(["rendered", "interactive", "interacted", "token"])).toBe("ready");
  });

  it("the watchdog turns a silent wait into a timeout, and only a wait", () => {
    expect(TURNSTILE_SLOW_MS).toBe(15_000);
    expect(run(["slow"])).toBe("timeout");
    expect(run(["rendered", "slow"])).toBe("timeout");
    for (const state of ["ready", "interactive", "expired", "error", "unsupported"] as const) expect(nextTurnstileState(state, "slow")).toBe(state);
    // A token after the timeout still lets the user in.
    expect(run(["rendered", "slow", "token"])).toBe("ready");
  });

  it("expired and failed tokens, and a spent token, reset to verifying", () => {
    expect(run(["rendered", "token", "expired"])).toBe("expired");
    expect(run(["rendered", "error"])).toBe("error");
    for (const state of ["ready", "expired", "error", "timeout", "pending"] as const) expect(nextTurnstileState(state, "reset")).toBe("pending");
    expect(nextTurnstileState("unsupported", "reset")).toBe("unsupported");
  });

  it("late lifecycle events do not undo a newer state", () => {
    expect(nextTurnstileState("ready", "rendered")).toBe("ready");
    expect(nextTurnstileState("ready", "interacted")).toBe("ready");
    expect(nextTurnstileState("error", "interacted")).toBe("error");
  });
});

describe("sign-in gate: no token, no request", () => {
  it("blocks every state without a token, with visible text", () => {
    for (const state of STATES) {
      const blocked = signInBlocked(state, null);
      expect(blocked, state).not.toBeNull();
      expect(blocked?.text.length, state).toBeGreaterThan(10);
    }
  });

  it("a click while verifying is informational; after a failure it is an error", () => {
    expect(signInBlocked("loading", null)).toEqual({ tone: "info", text: "Verifying your browser…" });
    expect(signInBlocked("pending", null)?.tone).toBe("info");
    expect(signInBlocked("interactive", null)).toEqual({ tone: "info", text: "Please complete the verification check below." });
    for (const state of ["expired", "error", "timeout", "unsupported"] as const) expect(signInBlocked(state, null)?.tone, state).toBe("error");
  });

  it("lets the existing flow proceed once a token is in hand", () => {
    expect(signInBlocked("ready", "tok")).toBeNull();
  });
});

describe("status line", () => {
  it("shows every state but ready, as a polite live region", () => {
    for (const state of STATES) {
      const out = renderToString(<TurnstileStatus state={state} onRetry={() => undefined} disabled={false} />);
      if (state === "ready") {
        expect(out).toBe("");
        expect(turnstileStatus(state)).toBeNull();
      } else {
        expect(out, state).toContain('role="status"');
        expect(out, state).toContain('aria-live="polite"');
      }
    }
  });

  it("offers a retry only after a failure, and not while a sign-in is running", () => {
    for (const state of STATES) {
      const out = renderToString(<TurnstileStatus state={state} onRetry={() => undefined} disabled={false} />);
      expect(out.includes("Try the verification check again"), state).toBe(turnstileRetryable(state));
    }
    expect(renderToString(<TurnstileStatus state="timeout" onRetry={() => undefined} disabled />)).toMatch(/<button[^>]*disabled/);
  });
});

describe("Login wiring", () => {
  const source = readFileSync("src/client/pages/Login.tsx", "utf8");
  const body = (name: string) => {
    const start = source.indexOf(`async function ${name}(`);
    expect(start, name).toBeGreaterThan(-1);
    return source.slice(start, source.indexOf("\n  }\n", start));
  };

  it("handles every widget callback", () => {
    for (const name of ["callback:", '"expired-callback"', '"error-callback"', '"timeout-callback"', '"unsupported-callback"', '"before-interactive-callback"', '"after-interactive-callback"']) {
      expect(source, name).toContain(name);
    }
    expect(source).toContain('appearance: "interaction-only"');
    expect(source).toContain('action: "login"');
  });

  it("renders one widget: render is guarded, retry resets, leaving removes", () => {
    expect(source.match(/turnstile\.render\(/g)).toHaveLength(1);
    expect(source).toMatch(/if \(cancelled \|\| widgetId\.current\) return;\s*widgetId\.current = turnstile\.render\(/);
    const reset = source.slice(source.indexOf("const resetTurnstile"), source.indexOf("};", source.indexOf("const resetTurnstile")));
    expect(reset).toContain("window.turnstile?.reset(widgetId.current)");
    expect(reset).not.toContain("render");
    expect(source).toMatch(/window\.turnstile\?\.remove\(widgetId\.current\);\s*widgetId\.current = null;/);
  });

  it("the watchdog timer is cleared and runs only while waiting", () => {
    expect(source).toMatch(/window\.setTimeout\(\(\) => turnstileEvent\("slow"\), TURNSTILE_SLOW_MS\);\s*return \(\) => window\.clearTimeout\(timer\);/);
    expect(source).toContain('if (!widgetNeeded || (turnstileState !== "loading" && turnstileState !== "pending")) return;');
  });

  it("passkey options and sign-in start are requested only after the token gate", () => {
    const passkey = body("passkey");
    const gate = passkey.indexOf("if (waitForTurnstile() || !turnstileToken) return;");
    expect(gate).toBeGreaterThan(-1);
    expect(passkey.indexOf("signInWithPasskey(turnstileToken)")).toBeGreaterThan(gate);
    const oauth = body("oauth");
    expect(oauth.indexOf("if (waitForTurnstile()) return;")).toBeGreaterThan(-1);
    expect(oauth.indexOf('api<{ url: string }>("/api/auth/sign-in/social"')).toBeGreaterThan(oauth.indexOf("if (waitForTurnstile()) return;"));
  });

  it("a cancelled or failed passkey attempt leaves the page usable", () => {
    const passkey = body("passkey");
    expect(passkey).toMatch(/catch \(error\) \{[\s\S]*resetTurnstile\(\);[\s\S]*PasskeyCancelled[\s\S]*finally \{\s*setBusy\(null\);/);
  });

  it("the page shows the status line whenever the widget is needed", () => {
    expect(source).toContain("{widgetNeeded ? <TurnstileStatus state={turnstileState} onRetry={resetTurnstile} disabled={busy !== null} /> : null}");
    expect(source).toContain("data-turnstile-state={turnstileState}");
  });
});
