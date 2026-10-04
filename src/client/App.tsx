import { useEffect } from "react";
import { Shell } from "./components/Shell";
import { Alert } from "./components/ui";
import { RouterProvider, useRouter, RETURN_PATHS } from "./lib/router";
import { SessionProvider, useSession } from "./lib/session";
import { ComingSoon, Dashboard } from "./pages/Dashboard";
import { Login } from "./pages/Login";
import { Security } from "./pages/Security";

function Routes() {
  const { path, navigate } = useRouter();
  const { session } = useSession();
  const isPublic = path === "/login" || path === "/register";

  useEffect(() => {
    if (path === "/" || path === "/register") {
      navigate(session.state === "signed-in" ? "/dashboard" : "/login", { replace: true });
    } else if (!isPublic && (session.state === "signed-out" || session.state === "blocked")) {
      const returnTo = (RETURN_PATHS as readonly string[]).includes(path) ? `?returnTo=${path}` : "";
      navigate(`/login${returnTo}`, { replace: true });
    }
  }, [path, session, navigate, isPublic]);

  if (path === "/login") return <Login />;
  if (session.state === "loading") return <div className="loading" aria-busy="true" aria-label="Loading" />;
  if (session.state === "error") {
    return (
      <div className="auth-page">
        <main className="auth-card" id="main">
          <Alert tone="error">{session.message}</Alert>
        </main>
      </div>
    );
  }
  if (session.state !== "signed-in") return null;

  let page;
  if (path === "/dashboard") page = <Dashboard me={session.me} />;
  else if (path === "/security" || path === "/sessions") page = <Security />;
  else if (path === "/agents" || path.startsWith("/agents/")) page = <ComingSoon title="Agents" text="Creating and managing agents arrives in a later release." />;
  else if (path === "/settings") page = <ComingSoon title="Settings" text="Account settings arrive in a later release." />;
  else page = <ComingSoon title="Page not found" text="This page doesn't exist." />;
  return <Shell>{page}</Shell>;
}

export function App() {
  return (
    <RouterProvider>
      <SessionProvider>
        <Routes />
      </SessionProvider>
    </RouterProvider>
  );
}
