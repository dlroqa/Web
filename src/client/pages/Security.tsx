import { useState } from "react";
import { ActivityIcon, KeyIcon, ShieldIcon } from "../components/icons";
import { Alert, Card, describeError, formatTime, PageHeader, ResourceState, useResource } from "../components/ui";
import { api, ApiRequestError, type ActivityEvent, type PasskeyInfo } from "../lib/api";
import { addPasskey, PasskeyCancelled, passkeysSupported } from "../lib/passkeys";
import { Link } from "../lib/router";

/** User-facing names for the caller's own audit events. Anything else is a generic event. */
export const ACTION_LABELS: Readonly<Record<string, string>> = {
  "auth.account.created": "Account created",
  "auth.login.success": "Signed in",
  "auth.login.failure": "Sign-in blocked",
  "auth.logout": "Signed out",
  "auth.passkey.add": "Passkey added",
  "auth.passkey.remove": "Passkey removed",
  "auth.passkey.rename": "Passkey renamed",
  "auth.session.revoke": "Session signed out",
  "auth.session.revoke_all": "Signed out everywhere",
  "account.profile.update": "Display name changed",
};

const RESULT_LABELS = { failure: "Failed", denied: "Blocked" } as const;

export function ActivityList({ events }: { events: ActivityEvent[] }) {
  if (events.length === 0) return <p className="muted small">No activity yet.</p>;
  return (
    <ul className="list">
      {events.map((event) => (
        <li key={event.id} className="list-row">
          <span>
            {ACTION_LABELS[event.action] ?? "Account event"}
            {event.result !== "success" ? <span className="badge badge-warn">{RESULT_LABELS[event.result]}</span> : null}
          </span>
          <span className="muted small tabular">
            <time dateTime={new Date(event.timestamp).toISOString()}>{formatTime(event.timestamp)}</time>
            {event.country ? ` · ${event.country}` : ""}
          </span>
        </li>
      ))}
    </ul>
  );
}

function passkeyError(error: unknown): string {
  if (error instanceof PasskeyCancelled) return "No passkey was created.";
  if (error instanceof ApiRequestError && error.code === "REAUTH_REQUIRED") {
    return "For your security, this needs a recent sign-in. Sign out, sign in again, then retry within 10 minutes.";
  }
  return describeError(error);
}

export function Security() {
  const methods = useResource<{ providers: string[]; passkeys: number }>("/api/security/methods");
  const passkeys = useResource<PasskeyInfo[]>("/api/security/passkeys");
  const activity = useResource<ActivityEvent[]>("/api/security/activity");
  const [notice, setNotice] = useState<{ tone: "error" | "success"; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [newName, setNewName] = useState("");

  async function run(key: string, action: () => Promise<unknown>, success: string) {
    setBusy(key);
    setNotice(null);
    try {
      await action();
      setNotice({ tone: "success", text: success });
      await Promise.all([methods.reload(), passkeys.reload(), activity.reload()]);
      return true;
    } catch (error) {
      setNotice({ tone: "error", text: passkeyError(error) });
      return false;
    } finally {
      setBusy(null);
      setConfirming(null);
    }
  }

  const providerLabel = (p: string) => (p === "google" ? "Google" : p === "github" ? "GitHub" : "Other");

  return (
    <div className="page">
      <PageHeader title="Security" description="How you sign in, and your recent account activity." />
      {notice ? <Alert tone={notice.tone}>{notice.text}</Alert> : null}

      <Card title="Sign-in methods" icon={<ShieldIcon />}>
        <ResourceState resource={methods} label="sign-in methods">
          {(data) => (
            <ul className="list">
              {data.providers.map((p) => (
                <li key={p} className="list-row">
                  <span>{providerLabel(p)}</span>
                  <span className="badge">Connected</span>
                </li>
              ))}
              <li className="list-row">
                <span>Passkeys</span>
                <span className="badge">{data.passkeys === 0 ? "None yet" : `${data.passkeys} added`}</span>
              </li>
            </ul>
          )}
        </ResourceState>
        <p className="muted small">
          Where you're signed in is on the <Link to="/sessions">Sessions</Link> page.
        </p>
      </Card>

      <Card title="Passkeys" icon={<KeyIcon />} description="Passkeys use your device's screen lock or a security key. They can't be phished or reused on other sites.">
        {passkeysSupported() ? (
          <form
            className="inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              const name = newName.trim() || "My passkey";
              void run("add", () => addPasskey(name), "Passkey added.").then((ok) => ok && setNewName(""));
            }}
          >
            <label htmlFor="passkey-name">Name for a new passkey</label>
            <div className="inline-form-row">
              <input id="passkey-name" type="text" maxLength={80} placeholder="e.g. MacBook Touch ID" value={newName} onChange={(e) => setNewName(e.target.value)} autoComplete="off" aria-describedby="passkey-name-help" />
              <button type="submit" className="button button-primary" disabled={busy !== null}>
                {busy === "add" ? "Waiting for your device…" : "Add passkey"}
              </button>
            </div>
            <p id="passkey-name-help" className="muted small">
              Adding or removing a passkey needs a sign-in within the last 10 minutes.
            </p>
          </form>
        ) : (
          <Alert tone="info">This browser doesn't support passkeys.</Alert>
        )}
        <ResourceState resource={passkeys} label="passkeys">
          {(list) =>
            list.length === 0 ? (
              <p className="muted small">No passkeys yet.</p>
            ) : (
              <ul className="list">
                {list.map((p) => (
                  <li key={p.id} className="list-row">
                    <div>
                      <div className="row-title">{p.name ?? "Passkey"}</div>
                      <div className="muted small">
                        {p.deviceType === "synced" ? "Synced passkey" : "Device-bound passkey"} · Added {formatTime(p.createdAt)}
                      </div>
                    </div>
                    {confirming === p.id ? (
                      <div className="row-actions" role="group" aria-label={`Confirm removing ${p.name ?? "this passkey"}`}>
                        <button type="button" className="button button-ghost" onClick={() => setConfirming(null)}>
                          Cancel
                        </button>
                        <button
                          type="button"
                          className="button button-danger"
                          disabled={busy !== null}
                          onClick={() => void run(p.id, () => api(`/api/security/passkeys/${encodeURIComponent(p.id)}`, { method: "DELETE" }), "Passkey removed.")}
                        >
                          Remove passkey
                        </button>
                      </div>
                    ) : (
                      <button type="button" className="button button-ghost" onClick={() => setConfirming(p.id)} aria-label={`Remove ${p.name ?? "passkey"}…`}>
                        Remove…
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </ResourceState>
      </Card>

      <Card title="Recent security activity" icon={<ActivityIcon />}>
        <ResourceState resource={activity} label="activity">
          {(events) => <ActivityList events={events} />}
        </ResourceState>
      </Card>
    </div>
  );
}
