/**
 * The signed-in application identity, from /api/session. The server is the
 * authority: this state only decides what to render, and it is refreshed
 * whenever an API call shows the session ended (401) or the account's status
 * changed (403). Nothing here stores or reads credentials.
 */
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiRequestError, onSessionSignal, type Me } from "./api";

export type SessionState =
  | { state: "loading" }
  | { state: "signed-out"; reason: "expired" | "signed-out" | null }
  | { state: "signed-in"; me: Me }
  | { state: "blocked"; status: "suspended" | "disabled" }
  | { state: "unavailable"; message: string };

export interface SessionValue {
  session: SessionState;
  refresh: () => Promise<void>;
  /** Sign out of this browser. */
  signOut: () => Promise<void>;
  /** The server already ended this browser's session (e.g. sign out everywhere). */
  markSignedOut: (reason: "expired" | "signed-out") => void;
}

export const SessionContext = createContext<SessionValue | null>(null);

interface Probe {
  signedIn: boolean;
  blocked?: boolean;
  status?: "suspended" | "disabled";
  me?: Me;
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionState>({ state: "loading" });

  const refresh = useCallback(async () => {
    try {
      const probe = await api<Probe>("/api/session");
      if (probe.signedIn && probe.me) setSession({ state: "signed-in", me: probe.me });
      else if (probe.blocked) setSession({ state: "blocked", status: probe.status === "disabled" ? "disabled" : "suspended" });
      else setSession((previous) => ({ state: "signed-out", reason: previous.state === "signed-in" ? "expired" : null }));
    } catch (error) {
      if (error instanceof ApiRequestError && error.code === "AUTH_UNAVAILABLE") setSession({ state: "signed-out", reason: null });
      else setSession({ state: "unavailable", message: error instanceof ApiRequestError && error.code === "NETWORK_ERROR" ? error.message : "Lightagent is temporarily unavailable." });
    }
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api("/api/auth/sign-out", { method: "POST", body: {} });
    } finally {
      setSession({ state: "signed-out", reason: "signed-out" });
    }
  }, []);

  const markSignedOut = useCallback((reason: "expired" | "signed-out") => setSession({ state: "signed-out", reason }), []);

  useEffect(() => {
    void refresh();
    return onSessionSignal((signal) => {
      if (signal === "expired") {
        // Only a session that was valid can "expire"; anything else is just signed out.
        setSession((previous) => (previous.state === "signed-in" ? { state: "signed-out", reason: "expired" } : previous));
      } else {
        void refresh();
      }
    });
  }, [refresh]);

  return <SessionContext.Provider value={{ session, refresh, signOut, markSignedOut }}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession outside SessionProvider");
  return value;
}
