import { DeviceIcon, KeyIcon, ShieldIcon } from "../components/icons";
import { Card, formatTime, PageHeader, ResourceState, StatusBadge, useResource } from "../components/ui";
import type { Overview } from "../lib/api";
import { Link } from "../lib/router";

const PROVIDER_NAMES = { google: "Google", github: "GitHub" } as const;

/** Presentational dashboard: safe account information only (no internal ids, tokens, or infrastructure). */
export function DashboardView({ overview }: { overview: Overview }) {
  const methods = [...overview.signIn.providers.map((p) => PROVIDER_NAMES[p]), ...(overview.signIn.passkeys > 0 ? [`${overview.signIn.passkeys} passkey${overview.signIn.passkeys === 1 ? "" : "s"}`] : [])];
  return (
    <div className="grid">
      <Card title="Account" icon={<ShieldIcon />}>
        <dl className="facts">
          <div>
            <dt>Name</dt>
            <dd>{overview.displayName ?? "Not set"}</dd>
          </div>
          <div>
            <dt>Status</dt>
            <dd>
              <StatusBadge status={overview.status} />
            </dd>
          </div>
        </dl>
        <Link to="/settings" className="button button-secondary">
          Account settings
        </Link>
      </Card>

      <Card title="Sign-in security" icon={<KeyIcon />}>
        <dl className="facts">
          <div>
            <dt>Sign-in methods</dt>
            <dd>{methods.length > 0 ? methods.join(", ") : "None"}</dd>
          </div>
        </dl>
        {overview.signIn.passkeys === 0 ? <p className="muted small">Add a passkey for faster, phishing-resistant sign-in.</p> : null}
        <Link to="/security" className="button button-secondary">
          Review security
        </Link>
      </Card>

      <Card title="Sessions" icon={<DeviceIcon />}>
        <dl className="facts">
          <div>
            <dt>Signed-in browsers</dt>
            <dd className="tabular">{overview.sessions.active}</dd>
          </div>
          <div>
            <dt>This session ends</dt>
            <dd className="tabular">{formatTime(overview.sessions.currentExpiresAt)}</dd>
          </div>
        </dl>
        <Link to="/sessions" className="button button-secondary">
          Manage sessions
        </Link>
      </Card>

      <Card title="Agents">
        <dl className="facts">
          <div>
            <dt>Agents</dt>
            <dd className="tabular">{overview.agents.count}</dd>
          </div>
        </dl>
        <p className="muted small">Creating agents arrives in a later release. Signing in never creates an agent.</p>
        <Link to="/agents" className="button button-secondary">
          View agents
        </Link>
      </Card>
    </div>
  );
}

export function Dashboard() {
  const overview = useResource<Overview>("/api/account/overview");
  const name = overview.data?.displayName;
  return (
    <div className="page">
      <PageHeader title="Dashboard" description={name ? `Welcome, ${name}.` : "Welcome to your Lightagent account."} />
      <ResourceState resource={overview} label="your account">
        {(data) => <DashboardView overview={data} />}
      </ResourceState>
    </div>
  );
}
