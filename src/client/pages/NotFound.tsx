import { Card, PageHeader } from "../components/ui";
import { Link } from "../lib/router";

export function NotFound() {
  return (
    <div className="page">
      <PageHeader title="Page not found" />
      <Card title="This page doesn't exist" description="Check the address, or go back to your dashboard.">
        <Link to="/dashboard" className="button button-secondary">
          Back to dashboard
        </Link>
      </Card>
    </div>
  );
}
