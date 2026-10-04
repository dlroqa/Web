/**
 * The route gate: what to render for a path, given the session. One
 * function, driven by the shared access policy (src/shared/access.ts) that
 * the server's requirePrincipal also uses. The gate only decides what to
 * show; every API behind these pages enforces the same rule on the server.
 *
 * Nothing protected renders until the session is resolved: loading,
 * unavailable, signed-out, pending, and blocked states each get their own
 * screen without the app navigation.
 */
import type { ReactNode } from "react";
import { decideAccess, isReturnPath, pageAccess, type AccessDecision, type AccountStatus } from "../../shared/access";
import { usePageTitle } from "../lib/router";
import type { SessionState } from "../lib/session";
import { useSession } from "../lib/session";
import { LogoMark } from "./icons";
import { Alert } from "./ui";

export type GateResult =
  | { kind: "loading" }
  | { kind: "unavailable"; message: string }
  | { kind: "redirect"; to: string }
  | { kind: "pending" }
  | { kind: "blocked"; status: "suspended" | "disabled" }
  | { kind: "page" };

function statusOf(session: SessionState): AccountStatus | null {
  if (session.state === "signed-in") return session.me.status;
  if (session.state === "blocked") return session.status;
  return null;
}

/** The login URL for a signed-out visitor of `path` (only allowlisted return paths are kept). */
export function loginUrl(path: string, reason: "expired" | "signed-out" | null): string {
  const params = new URLSearchParams();
  if (isReturnPath(path)) params.set("returnTo", path);
  if (reason) params.set("reason", reason);
  const query = params.toString();
  return query ? `/login?${query}` : "/login";
}

/** Decide what `path` shows for `session`. Pure; used by the app and by tests. */
export function gate(path: string, session: SessionState): GateResult {
  if (path === "/login") return { kind: "page" };
  if (session.state === "loading") return { kind: "loading" };
  if (session.state === "unavailable") return { kind: "unavailable", message: session.message };
  if (path === "/") return { kind: "redirect", to: session.state === "signed-in" ? "/dashboard" : "/login" };

  const decision: AccessDecision = decideAccess(pageAccess(path), statusOf(session));
  switch (decision) {
    case "allow":
      return { kind: "page" };
    case "sign-in":
      return { kind: "redirect", to: loginUrl(path, session.state === "signed-out" ? session.reason : null) };
    case "pending":
      return { kind: "pending" };
    case "blocked":
      return { kind: "blocked", status: session.state === "blocked" ? session.status : "suspended" };
  }
}

function StatusCard({ title, children }: { title: string; children: ReactNode }) {
  usePageTitle(title);
  return (
    <div className="auth-page">
      <main className="auth-card" id="main" aria-labelledby="status-title">
        <div className="auth-brand">
          <LogoMark />
          <h1 id="status-title">{title}</h1>
        </div>
        {children}
      </main>
    </div>
  );
}

export function LoadingScreen({ label = "Loading your account…" }: { label?: string }) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="visually-hidden">{label}</span>
    </div>
  );
}

export function UnavailableScreen({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <StatusCard title="Can't reach Lightagent">
      <Alert tone="error">{message}</Alert>
      <button type="button" className="button button-primary button-block" onClick={onRetry}>
        Try again
      </button>
    </StatusCard>
  );
}

/** Signed in, but the account is not approved yet. No application pages or navigation. */
export function PendingScreen() {
  const { session, refresh, signOut } = useSession();
  const name = session.state === "signed-in" ? session.me.displayName : null;
  return (
    <StatusCard title="Your account is awaiting approval">
      <p className="muted center">
        {name ? <>Thanks for signing in, {name}. </> : <>Thanks for signing in. </>}
        An administrator needs to approve your account before you can use Lightagent. You don't need to do anything else; check back later.
      </p>
      <div className="auth-actions">
        <button type="button" className="button button-secondary button-block" onClick={() => void refresh()}>
          Check again
        </button>
        <button type="button" className="button button-ghost button-block" onClick={() => void signOut()}>
          Sign out
        </button>
      </div>
    </StatusCard>
  );
}

export function BlockedScreen({ status }: { status: "suspended" | "disabled" }) {
  const { signOut } = useSession();
  return (
    <StatusCard title="This account is not active">
      <Alert tone="error">
        {status === "disabled"
          ? "This account has been disabled. Contact support if you think this is a mistake."
          : "This account has been suspended. Contact support if you think this is a mistake."}
      </Alert>
      <button type="button" className="button button-secondary button-block" onClick={() => void signOut()}>
        Sign out
      </button>
    </StatusCard>
  );
}
