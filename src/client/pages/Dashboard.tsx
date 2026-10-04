import { Alert, Card } from "../components/ui";
import { ShieldIcon } from "../components/icons";
import { Link } from "../lib/router";
import type { Me } from "../lib/api";

export function Dashboard({ me }: { me: Me }) {
  return (
    <div className="page">
      <header className="page-header">
        <h1>{me.displayName ? `Welcome, ${me.displayName}` : "Welcome"}</h1>
        <p className="muted">Your Lightagent account</p>
      </header>
      {me.status === "pending" ? (
        <Alert tone="warning">Your account is awaiting approval. You can secure your account now; agents become available once it's approved.</Alert>
      ) : null}
      <div className="grid">
        <Card title="Agents" description="Creating and managing Lightagent agents is coming soon.">
          <p className="muted small">Your account and your agents are separate: signing in never creates an agent.</p>
        </Card>
        <Card title="Account security" icon={<ShieldIcon />} description="Add a passkey for faster, phishing-resistant sign-in.">
          <Link to="/security" className="button button-secondary">
            Review security
          </Link>
        </Card>
      </div>
    </div>
  );
}

export function ComingSoon({ title, text }: { title: string; text: string }) {
  return (
    <div className="page">
      <header className="page-header">
        <h1>{title}</h1>
      </header>
      <Card title={title} description={text}>
        <Link to="/dashboard" className="button button-secondary">
          Back to dashboard
        </Link>
      </Card>
    </div>
  );
}
