/** The signed-in application identity, from /api/me (the canonical source). */
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiRequestError, type Me } from "./api";

type SessionState =
  | { state: "loading" }
  | { state: "signed-out" }
  | { state: "signed-in"; me: Me }
  | { state: "blocked"; code: "ACCOUNT_DISABLED" }
  | { state: "error"; message: string };

interface SessionValue {
  session: SessionState;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionState>({ state: "loading" });

  const refresh = useCallback(async () => {
    try {
      const probe = await api<{ signedIn: boolean; blocked?: boolean; me?: Me }>("/api/session");
      if (probe.signedIn && probe.me) setSession({ state: "signed-in", me: probe.me });
      else if (probe.blocked) setSession({ state: "blocked", code: "ACCOUNT_DISABLED" });
      else setSession({ state: "signed-out" });
    } catch (error) {
      if (error instanceof ApiRequestError && error.code === "AUTH_UNAVAILABLE") setSession({ state: "signed-out" });
      else setSession({ state: "error", message: error instanceof Error ? error.message : "Something went wrong." });
    }
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api("/api/auth/sign-out", { method: "POST", body: {} });
    } finally {
      setSession({ state: "signed-out" });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return <SessionContext.Provider value={{ session, refresh, signOut }}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession outside SessionProvider");
  return value;
}
