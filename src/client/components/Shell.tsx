import type { ReactNode } from "react";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import { LogoMark, LogoutIcon } from "./icons";

const NAV = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/agents", label: "Agents" },
  { to: "/security", label: "Security" },
  { to: "/settings", label: "Settings" },
];

export function Shell({ children }: { children: ReactNode }) {
  const { path, navigate } = useRouter();
  const { session, signOut } = useSession();
  const name = session.state === "signed-in" ? (session.me.displayName ?? "Your account") : "";
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
          <span className="account-name">{name}</span>
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
      <main id="main" className="main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
