import { db } from "@cyberpilot/database";
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

  const [integration, findings] = await Promise.all([
    db.integration.findUnique({
      where: {
        organizationId_provider: {
          organizationId: membership.organization.id,
          provider: "MICROSOFT_365",
        },
      },
      select: {
        id: true,
        status: true,
        displayName: true,
        connectedAt: true,
        lastSyncAt: true,
        lastErrorAt: true,
      },
    }),
    db.securityFinding.findMany({
      where: {
        organizationId: membership.organization.id,
        status: "OPEN",
      },
      orderBy: [
        {
          severity: "desc",
        },
        {
          lastSeenAt: "desc",
        },
      ],
      select: {
        id: true,
        title: true,
        description: true,
        severity: true,
        lastSeenAt: true,
      },
    }),
  ]);

  const canManageIntegrations =
    membership.role === "OWNER" || membership.role === "ADMIN";

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
            <p className="panel-label">Open findings</p>
            <p className="panel-value">{findings.length}</p>
          </div>
        </div>

        <div className="empty-state">
          <h2>Microsoft 365</h2>

          {integration?.status === "CONNECTED" ? (
            <>
              <p>
                Connected
                {integration.displayName
                  ? ` to ${integration.displayName}`
                  : ""}.
              </p>
              <p>
                Last inventory sync:{" "}
                {integration.lastSyncAt
                  ? integration.lastSyncAt.toISOString()
                  : "not run yet"}.
              </p>

              {integration.lastErrorAt ? (
                <p className="auth-error">
                  The last inventory synchronization failed.
                </p>
              ) : null}

              {canManageIntegrations ? (
                <form
                  action={`/api/organizations/${membership.organization.slug}/integrations/microsoft-365/sync`}
                  method="post"
                  className="sync-form"
                >
                  <button className="primary-button" type="submit">
                    Sync Microsoft 365
                  </button>
                </form>
              ) : null}
            </>
          ) : (
            <>
              <p>
                Connect this workspace to its Microsoft 365 tenant to begin
                collecting identity and privileged-role security evidence.
              </p>

              {canManageIntegrations ? (
                <p className="action-link">
                  <Link
                    href={`/api/organizations/${membership.organization.slug}/integrations/microsoft-365/connect`}
                  >
                    Connect Microsoft 365
                  </Link>
                </p>
              ) : (
                <p>
                  An organization owner or administrator must connect Microsoft
                  365.
                </p>
              )}
            </>
          )}
        </div>

        <section className="findings-section">
          <div className="section-heading">
            <p className="eyebrow">Security findings</p>
            <h2>Current evidence-backed risks</h2>
          </div>

          {findings.length === 0 ? (
            <div className="empty-state">
              <p>
                No open findings yet. Connect and synchronize Microsoft 365 to
                evaluate the first identity-security rules.
              </p>
            </div>
          ) : (
            <div className="finding-list">
              {findings.map((finding) => (
                <article className="finding-card" key={finding.id}>
                  <div className="finding-header">
                    <h3>{finding.title}</h3>
                    <span className="role-badge">{finding.severity}</span>
                  </div>
                  <p>{finding.description}</p>
                  <p className="finding-meta">
                    Last observed {finding.lastSeenAt.toISOString()}
                  </p>
                </article>
              ))}
            </div>
          )}
        </section>

        <p className="back-link">
          <Link href="/dashboard">Back to organizations</Link>
        </p>
      </section>
    </main>
  );
}
