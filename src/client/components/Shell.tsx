import { useEffect, useRef, type ReactNode } from "react";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import { LogoMark, LogoutIcon } from "./icons";

export const NAV = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/agents", label: "Agents" },
  { to: "/security", label: "Security" },
  { to: "/sessions", label: "Sessions" },
  { to: "/settings", label: "Settings" },
] as const;

/** The signed-in app frame. Only rendered once the gate has allowed the page. */
export function Shell({ children }: { children: ReactNode }) {
  const { path, navigate } = useRouter();
  const { session, signOut } = useSession();
  const name = session.state === "signed-in" ? (session.me.displayName ?? "Your account") : "";
  const main = useRef<HTMLElement>(null);
  const firstPath = useRef(path);

  // After client-side navigation, move focus to the new page (not on first load).
  useEffect(() => {
    if (path !== firstPath.current) {
      firstPath.current = "";
      main.current?.focus();
    }
  }, [path]);

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <Link to="/dashboard" className="brand-link">
          <LogoMark />
          <span>Lightagent</span>
        </Link>
        <nav aria-label="Main" className="nav">
          {NAV.map((item) => (
            <Link key={item.to} to={item.to} className="nav-link" current={path === item.to || path.startsWith(`${item.to}/`)}>
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="account">
          <span className="account-name" title={name}>
            {name}
          </span>
          <button
            type="button"
            className="button button-ghost"
            onClick={async () => {
              await signOut();
              navigate("/login", { replace: true });
            }}
          >
            <LogoutIcon />
            <span>Sign out</span>
          </button>
        </div>
      </header>
      <main id="main" className="main" tabIndex={-1} ref={main}>
        {children}
      </main>
    </div>
  );
}
