import type { ReactNode } from "react";

export function Alert({ tone = "info", children }: { tone?: "info" | "error" | "success" | "warning"; children: ReactNode }) {
  return (
    <div className={`alert alert-${tone}`} role={tone === "error" ? "alert" : "status"} aria-live="polite">
      {children}
    </div>
  );
}

export function Card({ title, icon, description, action, children }: { title: string; icon?: ReactNode; description?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="card" aria-labelledby={`card-${title}`}>
      <header className="card-header">
        <div className="card-title-row">
          {icon}
          <h2 id={`card-${title}`}>{title}</h2>
        </div>
        {action}
      </header>
      {description ? <p className="card-description">{description}</p> : null}
      {children}
    </section>
  );
}

export function formatTime(ms: number | null): string {
  if (ms === null) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(ms);
}
