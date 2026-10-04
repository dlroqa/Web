import { useEffect, type ReactNode } from "react";
import { BlockedScreen, gate, LoadingScreen, PendingScreen, UnavailableScreen } from "./components/AccessGate";
import { Shell } from "./components/Shell";
import { RouterProvider, useRouter } from "./lib/router";
import { SessionProvider, useSession } from "./lib/session";
import { Agents } from "./pages/Agents";
import { Dashboard } from "./pages/Dashboard";
import { Login } from "./pages/Login";
import { NotFound } from "./pages/NotFound";
import { Security } from "./pages/Security";
import { Sessions } from "./pages/Sessions";
import { Settings } from "./pages/Settings";

/** Application pages (all `active` in src/shared/access.ts). */
export function pageFor(path: string): ReactNode {
  switch (path) {
    case "/dashboard":
      return <Dashboard />;
    case "/agents":
      return <Agents />;
    case "/security":
      return <Security />;
    case "/sessions":
      return <Sessions />;
    case "/settings":
      return <Settings />;
    default:
      return <NotFound />;
  }
}

export function AppRoutes() {
  const { path, navigate } = useRouter();
  const { session, refresh } = useSession();
  const result = gate(path, session);

  useEffect(() => {
    if (result.kind === "redirect") navigate(result.to, { replace: true });
  }, [result.kind, result.kind === "redirect" ? result.to : null, navigate]);

  if (path === "/login") return <Login />;
  switch (result.kind) {
    case "loading":
    case "redirect":
      return <LoadingScreen />;
    case "unavailable":
      return <UnavailableScreen message={result.message} onRetry={() => void refresh()} />;
    case "pending":
      return <PendingScreen />;
    case "blocked":
      return <BlockedScreen status={result.status} />;
    case "page":
      return <Shell>{pageFor(path)}</Shell>;
  }
}

export function App() {
  return (
    <RouterProvider>
      <SessionProvider>
        <AppRoutes />
      </SessionProvider>
    </RouterProvider>
  );
}
