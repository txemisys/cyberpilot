import Link from "next/link";

import { getCurrentUserOrganizations } from "../../lib/session";

export default async function DashboardPage() {
  const { session, memberships } = await getCurrentUserOrganizations();

  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot</p>
        <h1 className="dashboard-title">Security workspace</h1>
        <p className="lede">
          Signed in as <strong>{session.user.email}</strong>.
        </p>

        <div className="panel">
          <div>
            <p className="panel-label">Organizations</p>
            <p className="panel-value">{memberships.length}</p>
          </div>
        </div>

        {memberships.length === 0 ? (
          <div className="empty-state">
            <h2>No organization access yet</h2>
            <p>
              Your identity is authenticated, but no CyberPilot organization
              membership has been granted.
            </p>
            <p className="action-link">
              <Link href="/onboarding">Create an organization</Link>
            </p>
          </div>
        ) : (
          <>
            <div className="organization-list">
              {memberships.map(({ organization, role }) => (
                <Link
                  className="organization-card"
                  href={`/organizations/${organization.slug}`}
                  key={organization.id}
                >
                  <div>
                    <h2>{organization.name}</h2>
                    <p>{organization.slug}</p>
                  </div>
                  <span className="role-badge">{role}</span>
                </Link>
              ))}
            </div>

            <p className="action-link">
              <Link href="/onboarding">Create another organization</Link>
            </p>
          </>
        )}
      </section>
    </main>
  );
}
