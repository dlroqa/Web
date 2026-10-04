import { Card, formatTime, PageHeader, ResourceState, StatusBadge, useResource } from "../components/ui";
import type { AgentSummary } from "../lib/api";

/** Read-only until provisioning ships: there is no way to create an agent here. */
export function AgentsView({ agents }: { agents: AgentSummary[] }) {
  if (agents.length === 0) {
    return (
      <Card title="No agents yet" description="Creating and managing Lightagent agents arrives in a later release.">
        <p className="muted small">Your account and your agents are separate: signing in never creates an agent, and nothing here contacts an agent service.</p>
      </Card>
    );
  }
  return (
    <Card title="Your agents">
      <ul className="list">
        {agents.map((agent) => (
          <li key={agent.id} className="list-row">
            <div>
              <div className="row-title">{agent.name}</div>
              <div className="muted small">Created {formatTime(agent.createdAt)}</div>
            </div>
            <StatusBadge status={agent.status} />
          </li>
        ))}
      </ul>
    </Card>
  );
}

export function Agents() {
  const agents = useResource<AgentSummary[]>("/api/agents");
  return (
    <div className="page">
      <PageHeader title="Agents" description="Agents you own." />
      <ResourceState resource={agents} label="agents">
        {(data) => <AgentsView agents={data} />}
      </ResourceState>
    </div>
  );
}
