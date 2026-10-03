import Link from "next/link";

import { requireOrganizationAccess } from "../../../lib/organizations";

type OrganizationPageProps = {
  params: Promise<{
    slug: string;
  }>;
};

export default async function OrganizationPage({
  params,
}: OrganizationPageProps) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);

  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot workspace</p>
        <h1 className="dashboard-title">{membership.organization.name}</h1>
        <p className="lede">
          Organization access verified. Your current role is{" "}
          <strong>{membership.role}</strong>.
        </p>

        <div className="panel">
          <div>
            <p className="panel-label">Security posture</p>
            <p className="panel-value">Not scanned yet</p>
          </div>
        </div>

        <div className="empty-state">
          <h2>Connect Microsoft 365</h2>
          <p>
            The next development milestone will connect this organization to a
            Microsoft tenant and begin importing security evidence.
          </p>
        </div>

        <p className="back-link">
          <Link href="/dashboard">Back to organizations</Link>
        </p>
      </section>
    </main>
  );
}
