import { useRef, useState, type FormEvent } from "react";
import { Alert, Card, describeError, PageHeader, StatusBadge } from "../components/ui";
import { api, type Me } from "../lib/api";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";

/** Same rule as the server (NameSchema): 1–80 characters after trimming, no control characters. */
export function validateDisplayName(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) return "Enter a name.";
  if (trimmed.length > 80) return "Use 80 characters or fewer.";
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return "Remove special control characters.";
  return null;
}

export function Settings() {
  const { session, refresh, signOut } = useSession();
  const { navigate } = useRouter();
  const me = session.state === "signed-in" ? session.me : null;
  const [name, setName] = useState(me?.displayName ?? "");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ tone: "error" | "success"; text: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  async function save(event: FormEvent) {
    event.preventDefault();
    setNotice(null);
    const problem = validateDisplayName(name);
    setFieldError(problem);
    if (problem) {
      input.current?.focus();
      return;
    }
    setSaving(true);
    try {
      const updated = await api<Me>("/api/me", { method: "PATCH", body: { displayName: name.trim() } });
      setName(updated.displayName ?? "");
      await refresh();
      setNotice({ tone: "success", text: "Name saved." });
    } catch (error) {
      setNotice({ tone: "error", text: describeError(error) });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="page">
      <PageHeader title="Settings" description="Your account details." />
      {notice ? <Alert tone={notice.tone}>{notice.text}</Alert> : null}

      <Card title="Profile">
        <form className="form" onSubmit={(e) => void save(e)} noValidate>
          <div className="field">
            <label htmlFor="display-name">Display name</label>
            <input
              ref={input}
              id="display-name"
              name="displayName"
              type="text"
              autoComplete="name"
              maxLength={80}
              value={name}
              onChange={(e) => setName(e.target.value)}
              aria-invalid={fieldError ? true : undefined}
              aria-describedby={fieldError ? "display-name-error display-name-help" : "display-name-help"}
            />
            <p id="display-name-help" className="muted small">
              Shown on your dashboard. Up to 80 characters.
            </p>
            {fieldError ? (
              <p id="display-name-error" className="field-error" role="alert">
                {fieldError}
              </p>
            ) : null}
          </div>
          <div>
            <button type="submit" className="button button-primary" disabled={saving}>
              {saving ? "Saving…" : "Save name"}
            </button>
          </div>
        </form>
      </Card>

      <Card title="Account">
        <dl className="facts">
          <div>
            <dt>Status</dt>
            <dd>{me ? <StatusBadge status={me.status} /> : "—"}</dd>
          </div>
        </dl>
        <p className="muted small">
          Sign-in methods and passkeys are on the <Link to="/security">Security</Link> page.
        </p>
      </Card>

      <Card title="Sign out" description="Sign out of this browser, or end every session from the Sessions page.">
        <div className="row-actions">
          <button
            type="button"
            className="button button-secondary"
            onClick={async () => {
              await signOut();
              navigate("/login?reason=signed-out", { replace: true });
            }}
          >
            Sign out of this browser
          </button>
          <Link to="/sessions" className="button button-ghost">
            Manage sessions
          </Link>
        </div>
      </Card>
    </div>
  );
}
