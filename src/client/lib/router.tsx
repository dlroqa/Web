/** A minimal history router: enough for a handful of pages, no dependency. */
import { createContext, useCallback, useContext, useEffect, useState, type MouseEvent, type ReactNode } from "react";

interface RouterValue {
  path: string;
  search: URLSearchParams;
  navigate: (to: string, options?: { replace?: boolean }) => void;
}

const RouterContext = createContext<RouterValue | null>(null);

/** Pages a sign-in may return to (mirrors the server's allowlist). */
export const RETURN_PATHS = ["/dashboard", "/agents", "/security", "/settings"] as const;
export type ReturnPath = (typeof RETURN_PATHS)[number];

export function safeReturnPath(value: string | null): ReturnPath {
  return (RETURN_PATHS as readonly string[]).includes(value ?? "") ? (value as ReturnPath) : "/dashboard";
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [location, setLocation] = useState(() => ({ path: window.location.pathname, search: window.location.search }));

  useEffect(() => {
    const onPop = () => setLocation({ path: window.location.pathname, search: window.location.search });
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const navigate = useCallback((to: string, options: { replace?: boolean } = {}) => {
    const url = new URL(to, window.location.origin);
    if (url.origin !== window.location.origin) return; // never navigate off-site
    if (options.replace) window.history.replaceState(null, "", url.pathname + url.search);
    else window.history.pushState(null, "", url.pathname + url.search);
    setLocation({ path: url.pathname, search: url.search });
    window.scrollTo(0, 0);
  }, []);

  return (
    <RouterContext.Provider value={{ path: location.path, search: new URLSearchParams(location.search), navigate }}>
      {children}
    </RouterContext.Provider>
  );
}

export function useRouter(): RouterValue {
  const value = useContext(RouterContext);
  if (!value) throw new Error("useRouter outside RouterProvider");
  return value;
}

export function Link({ to, className, children, current }: { to: string; className?: string; children: ReactNode; current?: boolean }) {
  const { navigate } = useRouter();
  const onClick = (event: MouseEvent<HTMLAnchorElement>) => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    event.preventDefault();
    navigate(to);
  };
  return (
    <a href={to} className={className} onClick={onClick} aria-current={current ? "page" : undefined}>
      {children}
    </a>
  );
}
