import { useCallback, useEffect, useState, type ReactNode } from "react";
import { api, ApiRequestError } from "../lib/api";
import { usePageTitle } from "../lib/router";

export function Alert({ tone = "info", children }: { tone?: "info" | "error" | "success" | "warning"; children: ReactNode }) {
  return (
    <div className={`alert alert-${tone}`} role={tone === "error" ? "alert" : "status"} aria-live="polite">
      {children}
    </div>
  );
}

const slug = (text: string) => text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

export function Card({ title, icon, description, action, children }: { title: string; icon?: ReactNode; description?: string; action?: ReactNode; children?: ReactNode }) {
  const id = `card-${slug(title)}`;
  return (
    <section className="card" aria-labelledby={id}>
      <header className="card-header">
        <div className="card-title-row">
          {icon}
          <h2 id={id}>{title}</h2>
        </div>
        {action}
      </header>
      {description ? <p className="card-description">{description}</p> : null}
      {children}
    </section>
  );
}

/** Page heading; also sets the document title. */
export function PageHeader({ title, description }: { title: string; description?: string }) {
  usePageTitle(title);
  return (
    <header className="page-header">
      <h1>{title}</h1>
      {description ? <p className="muted">{description}</p> : null}
    </header>
  );
}

export function formatTime(ms: number | null): string {
  if (ms === null) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(ms);
}

/** A user-facing message for a failed request: our stable messages only, never raw server text. */
export function describeError(error: unknown): string {
  return error instanceof ApiRequestError ? error.message : "Something went wrong. Please try again.";
}

export interface Resource<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/**
 * Load one API resource for a page. Expired sessions and status changes are
 * handled globally (the gate takes over); this only surfaces other errors.
 */
export function useResource<T>(path: string): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await api<T>(path));
      setError(null);
    } catch (failure) {
      setError(describeError(failure));
    } finally {
      setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { data, error, loading, reload };
}

/** Loading text, an error with a retry button, or the content. Keeps layout stable and announced. */
export function ResourceState<T>({ resource, label, children }: { resource: Resource<T>; label: string; children: (data: T) => ReactNode }) {
  if (resource.data !== null) return <>{children(resource.data)}</>;
  if (resource.error) {
    return (
      <div className="stack">
        <Alert tone="error">{resource.error}</Alert>
        <div>
          <button type="button" className="button button-secondary" onClick={() => void resource.reload()}>
            Try again
          </button>
        </div>
      </div>
    );
  }
  return (
    <p className="muted" role="status" aria-live="polite">
      Loading {label}…
    </p>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const tone = status === "active" ? "badge-accent" : "badge-warn";
  const label = status.charAt(0).toUpperCase() + status.slice(1);
  return <span className={`badge ${tone}`}>{label}</span>;
}
