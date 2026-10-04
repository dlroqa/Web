import { useState } from "react";
import { DeviceIcon } from "../components/icons";
import { Alert, Card, describeError, formatTime, PageHeader, ResourceState, useResource } from "../components/ui";
import { api, type SessionInfo } from "../lib/api";
import { useRouter } from "../lib/router";
import { useSession } from "../lib/session";

/** One row per session: opaque id, coarse device, times. The API never returns tokens. */
export function SessionList({ sessions, busy, onRevoke }: { sessions: SessionInfo[]; busy: boolean; onRevoke: (session: SessionInfo) => void }) {
  return (
    <ul className="list">
      {sessions.map((s) => (
        <li key={s.id} className="list-row">
          <div>
            <div className="row-title">
              {s.device}
              {s.current ? <span className="badge badge-accent">This browser</span> : null}
            </div>
            <div className="muted small tabular">
              Signed in {formatTime(s.createdAt)} · Ends {formatTime(s.expiresAt)}
            </div>
          </div>
          {s.current ? null : (
            <button type="button" className="button button-ghost" disabled={busy} onClick={() => onRevoke(s)} aria-label={`Sign out ${s.device}, signed in ${formatTime(s.createdAt)}`}>
              Sign out
            </button>
          )}
        </li>
      ))}
    </ul>
  );
}

export function Sessions() {
  const { navigate } = useRouter();
  const { markSignedOut } = useSession();
  const sessions = useResource<SessionInfo[]>("/api/security/sessions");
  const [notice, setNotice] = useState<{ tone: "error" | "success"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmAll, setConfirmAll] = useState(false);

  async function revoke(session: SessionInfo) {
    setBusy(true);
    setNotice(null);
    try {
      await api(`/api/security/sessions/${encodeURIComponent(session.id)}`, { method: "DELETE" });
      setNotice({ tone: "success", text: `Signed out ${session.device}.` });
      await sessions.reload();
    } catch (error) {
      setNotice({ tone: "error", text: describeError(error) });
    } finally {
      setBusy(false);
    }
  }

  async function signOutEverywhere() {
    setBusy(true);
    setNotice(null);
    try {
      await api("/api/security/sessions/revoke-all", { method: "POST" });
      // The server ended this browser's session too and cleared its cookie.
      markSignedOut("signed-out");
      navigate("/login?reason=signed-out", { replace: true });
    } catch (error) {
      setNotice({ tone: "error", text: describeError(error) });
      setBusy(false);
      setConfirmAll(false);
    }
  }

  return (
    <div className="page">
      <PageHeader title="Sessions" description="Browsers where you're signed in. Each session ends 24 hours after sign-in." />
      {notice ? <Alert tone={notice.tone}>{notice.text}</Alert> : null}
      <Card title="Signed-in browsers" icon={<DeviceIcon />}>
        <ResourceState resource={sessions} label="sessions">
          {(list) => <SessionList sessions={list} busy={busy} onRevoke={(s) => void revoke(s)} />}
        </ResourceState>
      </Card>
      <Card title="Sign out everywhere" description="Ends every session, including this one. You'll need to sign in again on every device.">
        {confirmAll ? (
          <div className="row-actions" role="group" aria-label="Confirm signing out everywhere">
            <button type="button" className="button button-ghost" onClick={() => setConfirmAll(false)} disabled={busy}>
              Cancel
            </button>
            <button type="button" className="button button-danger" onClick={() => void signOutEverywhere()} disabled={busy}>
              {busy ? "Signing out…" : "Yes, sign out everywhere"}
            </button>
          </div>
        ) : (
          <div>
            <button type="button" className="button button-secondary" onClick={() => setConfirmAll(true)}>
              Sign out everywhere…
            </button>
          </div>
        )}
      </Card>
    </div>
  );
}
