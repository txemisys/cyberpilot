import { db } from "@cyberpilot/database";
import { calculateCyberScore } from "@cyberpilot/risk-engine";
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

  const [integration, findings, administratorIdentities] = await Promise.all([
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
        mfaEvidenceStatus: true,
        mfaEvidenceCheckedAt: true,
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
        ruleId: true,
        title: true,
        description: true,
        severity: true,
        evidence: true,
        firstSeenAt: true,
        lastSeenAt: true,
      },
    }),
    db.directoryIdentity.findMany({
      where: {
        integration: {
          organizationId: membership.organization.id,
          provider: "MICROSOFT_365",
        },
        accountEnabled: true,
        isAdmin: true,
      },
      select: {
        id: true,
        isMfaCapable: true,
        authenticationObservedAt: true,
      },
    }),
  ]);

  const administratorsWithMfaEvidence = administratorIdentities.filter(
    (identity) => identity.authenticationObservedAt !== null,
  );
  const mfaCapableAdministrators = administratorsWithMfaEvidence.filter(
    (identity) => identity.isMfaCapable === true,
  );

  const cyberScore = calculateCyberScore(
    findings.map((finding) => ({
      id: finding.id,
      ruleId: finding.ruleId,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
    })),
  );

  const hasCompletedScan = integration?.lastSyncAt !== null && integration?.lastSyncAt !== undefined;
  const scoreCoverageIsPartial =
    integration?.mfaEvidenceStatus === "PERMISSION_REQUIRED" ||
    integration?.mfaEvidenceStatus === "ERROR" ||
    cyberScore.unsupportedFindingCount > 0;

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
            <p className="panel-label">CyberScore v0</p>
            <p className="panel-value">
              {hasCompletedScan ? cyberScore.score : "—"}
            </p>
            <p className="score-caption">
              {hasCompletedScan
                ? scoreCoverageIsPartial
                  ? "Partial evidence coverage"
                  : "Current supported controls"
                : "Run the first scan"}
            </p>
          </div>
          <div>
            <p className="panel-label">Open findings</p>
            <p className="panel-value">{findings.length}</p>
          </div>
          <div>
            <p className="panel-label">MFA-capable administrators</p>
            <p className="panel-value">
              {mfaCapableAdministrators.length}/
              {administratorsWithMfaEvidence.length}
            </p>
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

              {integration.mfaEvidenceStatus === "PERMISSION_REQUIRED" ? (
                <div className="permission-warning">
                  <strong>MFA evidence permission required</strong>
                  <p>
                    CyberPilot can continue reading users and privileged roles,
                    but Microsoft has not granted access to authentication
                    registration evidence. Grant the updated Microsoft 365
                    consent to enable administrator MFA findings.
                  </p>
                  {canManageIntegrations ? (
                    <p className="action-link">
                      <Link
                        href={`/api/organizations/${membership.organization.slug}/integrations/microsoft-365/connect`}
                      >
                        Grant MFA reporting permission
                      </Link>
                    </p>
                  ) : null}
                </div>
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


        <section className="priority-section">
          <div className="section-heading">
            <p className="eyebrow">Priorities</p>
            <h2>Top actions</h2>
          </div>

          {!hasCompletedScan ? (
            <div className="empty-state">
              <p>
                Run a Microsoft 365 synchronization before CyberPilot can
                prioritize security actions.
              </p>
            </div>
          ) : cyberScore.topActions.length === 0 ? (
            <div className="empty-state">
              <p>
                No supported open findings currently require prioritized
                action.
              </p>
            </div>
          ) : (
            <ol className="priority-list">
              {cyberScore.topActions.map((action) => (
                <li className="priority-card" key={action.id}>
                  <div className="priority-header">
                    <div>
                      <p className="priority-score">
                        {action.priorityScore.toFixed(1)} risk points
                      </p>
                      <h3>{action.title}</h3>
                    </div>
                    <span className="role-badge">{action.severity}</span>
                  </div>
                  <p>{action.remediation}</p>
                  <p className="priority-rationale">{action.rationale}</p>
                </li>
              ))}
            </ol>
          )}

          {hasCompletedScan ? (
            <details className="score-details">
              <summary>How this CyberScore was calculated</summary>
              <p>
                CyberScore v0 starts at 100 and deducts risk points only for
                rules currently supported by CyberPilot. Repeated findings from
                the same rule are capped to avoid one control dominating the
                entire posture score.
              </p>
              <dl className="finding-evidence">
                <div>
                  <dt>Risk points</dt>
                  <dd>{cyberScore.totalRiskPoints.toFixed(1)}</dd>
                </div>
                <div>
                  <dt>Scored findings</dt>
                  <dd>{cyberScore.supportedFindingCount}</dd>
                </div>
                <div>
                  <dt>Unscored findings</dt>
                  <dd>{cyberScore.unsupportedFindingCount}</dd>
                </div>
              </dl>
            </details>
          ) : null}
        </section>

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
                  <dl className="finding-evidence">
                    <div>
                      <dt>Rule</dt>
                      <dd>{finding.ruleId}</dd>
                    </div>
                    <div>
                      <dt>First seen</dt>
                      <dd>{finding.firstSeenAt.toISOString()}</dd>
                    </div>
                    <div>
                      <dt>Last observed</dt>
                      <dd>{finding.lastSeenAt.toISOString()}</dd>
                    </div>
                  </dl>
                  <details className="evidence-details">
                    <summary>Evidence</summary>
                    <pre>
                      {JSON.stringify(finding.evidence, null, 2)}
                    </pre>
                  </details>
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
