import { useCallback, useEffect, useState } from "react";
import { Alert, Card, formatTime } from "../components/ui";
import { ActivityIcon, DeviceIcon, KeyIcon, ShieldIcon } from "../components/icons";
import { api, ApiRequestError, type ActivityEvent, type PasskeyInfo, type SessionInfo } from "../lib/api";
import { addPasskey, PasskeyCancelled, passkeysSupported } from "../lib/passkeys";
import { useRouter } from "../lib/router";
import { useSession } from "../lib/session";

const ACTION_LABELS: Record<string, string> = {
  "auth.account.created": "Account created",
  "auth.login.success": "Signed in",
  "auth.login.failure": "Sign-in blocked",
  "auth.logout": "Signed out",
  "auth.passkey.add": "Passkey added",
  "auth.passkey.remove": "Passkey removed",
  "auth.passkey.rename": "Passkey renamed",
  "auth.session.revoke": "Session revoked",
  "auth.session.revoke_all": "Signed out everywhere",
};

type Notice = { tone: "error" | "success" | "info"; text: string } | null;

function explain(error: unknown): string {
  if (error instanceof PasskeyCancelled) return "No passkey was created.";
  if (error instanceof ApiRequestError && error.code === "REAUTH_REQUIRED") return "For your security, sign out and sign in again, then retry within 10 minutes.";
  return error instanceof Error ? error.message : "Something went wrong.";
}

export function Security() {
  const { navigate } = useRouter();
  const { refresh } = useSession();
  const [methods, setMethods] = useState<{ providers: string[]; passkeys: number } | null>(null);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[] | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);
  const [activity, setActivity] = useState<ActivityEvent[] | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [newName, setNewName] = useState("");

  const load = useCallback(async () => {
    try {
      const [m, p, s, a] = await Promise.all([
        api<{ providers: string[]; passkeys: number }>("/api/security/methods"),
        api<PasskeyInfo[]>("/api/security/passkeys"),
        api<SessionInfo[]>("/api/security/sessions"),
        api<ActivityEvent[]>("/api/security/activity"),
      ]);
      setMethods(m);
      setPasskeys(p);
      setSessions(s);
      setActivity(a);
    } catch (error) {
      setNotice({ tone: "error", text: explain(error) });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function run(key: string, action: () => Promise<void>, success: string) {
    setBusy(key);
    setNotice(null);
    try {
      await action();
      setNotice({ tone: "success", text: success });
      await load();
    } catch (error) {
      setNotice({ tone: "error", text: explain(error) });
    } finally {
      setBusy(null);
      setConfirming(null);
    }
  }

  const providerLabel = (p: string) => (p === "google" ? "Google" : p === "github" ? "GitHub" : p);

  return (
    <div className="page">
      <header className="page-header">
        <h1>Security</h1>
        <p className="muted">Manage how you sign in and where you're signed in.</p>
      </header>
      {notice ? <Alert tone={notice.tone}>{notice.text}</Alert> : null}

      <Card title="Sign-in methods" icon={<ShieldIcon />}>
        {methods === null ? (
          <p className="muted">Loading…</p>
        ) : (
          <ul className="list">
            {methods.providers.map((p) => (
              <li key={p} className="list-row">
                <span>{providerLabel(p)}</span>
                <span className="badge">Connected</span>
              </li>
            ))}
            <li className="list-row">
              <span>Passkeys</span>
              <span className="badge">{methods.passkeys === 0 ? "None yet" : `${methods.passkeys} added`}</span>
            </li>
          </ul>
        )}
      </Card>

      <Card
        title="Passkeys"
        icon={<KeyIcon />}
        description="Passkeys use your device's screen lock or a security key. They can't be phished or reused on other sites."
      >
        {passkeysSupported() ? (
          <form
            className="inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              const name = newName.trim() || "My passkey";
              void run("add", async () => addPasskey(name), "Passkey added.").then(() => setNewName(""));
            }}
          >
            <label htmlFor="passkey-name">Passkey name</label>
            <div className="inline-form-row">
              <input id="passkey-name" type="text" maxLength={80} placeholder="e.g. MacBook Touch ID" value={newName} onChange={(e) => setNewName(e.target.value)} autoComplete="off" />
              <button type="submit" className="button button-primary" disabled={busy !== null}>
                {busy === "add" ? "Waiting for your device…" : "Add passkey"}
              </button>
            </div>
          </form>
        ) : (
          <Alert tone="info">This browser doesn't support passkeys.</Alert>
        )}
        {passkeys && passkeys.length > 0 ? (
          <ul className="list">
            {passkeys.map((p) => (
              <li key={p.id} className="list-row">
                <div>
                  <div className="row-title">{p.name ?? "Passkey"}</div>
                  <div className="muted small">
                    {p.deviceType === "synced" ? "Synced passkey" : "Device-bound passkey"} · Added {formatTime(p.createdAt)}
                  </div>
                </div>
                {confirming === p.id ? (
                  <div className="row-actions">
                    <button type="button" className="button button-ghost" onClick={() => setConfirming(null)}>
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="button button-danger"
                      disabled={busy !== null}
                      onClick={() => run(p.id, () => api(`/api/security/passkeys/${encodeURIComponent(p.id)}`, { method: "DELETE" }), "Passkey removed.")}
                    >
                      Remove
                    </button>
                  </div>
                ) : (
                  <button type="button" className="button button-ghost" onClick={() => setConfirming(p.id)}>
                    Remove…
                  </button>
                )}
              </li>
            ))}
          </ul>
        ) : passkeys ? (
          <p className="muted small">No passkeys yet.</p>
        ) : null}
      </Card>

      <Card
        title="Active sessions"
        icon={<DeviceIcon />}
        action={
          confirming === "all" ? (
            <div className="row-actions">
              <button type="button" className="button button-ghost" onClick={() => setConfirming(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="button button-danger"
                disabled={busy !== null}
                onClick={async () => {
                  setBusy("all");
                  try {
                    await api("/api/security/sessions/revoke-all", { method: "POST" });
                  } finally {
                    await refresh();
                    navigate("/login", { replace: true });
                  }
                }}
              >
                Sign out everywhere
              </button>
            </div>
          ) : (
            <button type="button" className="button button-ghost" onClick={() => setConfirming("all")}>
              Sign out all sessions…
            </button>
          )
        }
      >
        {sessions === null ? (
          <p className="muted">Loading…</p>
        ) : (
          <ul className="list">
            {sessions.map((s) => (
              <li key={s.id} className="list-row">
                <div>
                  <div className="row-title">
                    {s.device} {s.current ? <span className="badge badge-accent">This device</span> : null}
                  </div>
                  <div className="muted small">
                    Signed in {formatTime(s.createdAt)} · Last active {formatTime(s.lastActiveAt)}
                  </div>
                </div>
                {s.current ? null : (
                  <button
                    type="button"
                    className="button button-ghost"
                    disabled={busy !== null}
                    onClick={() => run(s.id, () => api(`/api/security/sessions/${encodeURIComponent(s.id)}`, { method: "DELETE" }), "Session signed out.")}
                  >
                    Sign out
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Recent security activity" icon={<ActivityIcon />}>
        {activity === null ? (
          <p className="muted">Loading…</p>
        ) : activity.length === 0 ? (
          <p className="muted small">No activity yet.</p>
        ) : (
          <ul className="list">
            {activity.map((e) => (
              <li key={e.id} className="list-row">
                <span>
                  {ACTION_LABELS[e.action] ?? e.action}
                  {e.result !== "success" ? <span className="badge badge-warn">{e.result}</span> : null}
                </span>
                <span className="muted small tabular">
                  {formatTime(e.timestamp)}
                  {e.country ? ` · ${e.country}` : ""}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
