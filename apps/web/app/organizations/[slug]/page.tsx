import { db } from "@cyberpilot/database";
import { isMicrosoftRemediationExecutorConfigured } from "@cyberpilot/integrations/microsoft-365";
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

  const [
    integration,
    findings,
    administratorIdentities,
    domains,
    scoreHistory,
    remediations,
  ] = await Promise.all([
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
        remediationStatus: true,
        remediationCheckedAt: true,
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
    db.domain.findMany({
      where: {
        organizationId: membership.organization.id,
      },
      orderBy: [
        {
          isDefault: "desc",
        },
        {
          name: "asc",
        },
      ],
      select: {
        id: true,
        name: true,
        isDefault: true,
        isInitial: true,
        spfStatus: true,
        dmarcStatus: true,
        dmarcPolicy: true,
        dkimStatus: true,
        dnsObservedAt: true,
      },
    }),
    db.securityScore.findMany({
      where: {
        organizationId: membership.organization.id,
      },
      orderBy: {
        calculatedAt: "desc",
      },
      take: 8,
      select: {
        id: true,
        modelVersion: true,
        score: true,
        riskPoints: true,
        coverage: true,
        supportedFindingCount: true,
        unsupportedFindingCount: true,
        calculatedAt: true,
      },
    }),
    db.remediation.findMany({
      where: {
        organizationId: membership.organization.id,
        status: {
          in: ["PROPOSED", "APPROVED", "EXECUTING", "FAILED", "VERIFIED"],
        },
      },
      orderBy: {
        createdAt: "desc",
      },
      take: 12,
      select: {
        id: true,
        playbookId: true,
        mode: true,
        status: true,
        title: true,
        summary: true,
        steps: true,
        verification: true,
        actionType: true,
        failureCode: true,
        approvedAt: true,
        completedAt: true,
        createdAt: true,
        finding: {
          select: {
            id: true,
            title: true,
            severity: true,
            status: true,
          },
        },
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
  const domainCoverageIsPartial = domains.some(
    (domain) =>
      !domain.isInitial &&
      (domain.spfStatus === "ERROR" ||
        domain.dmarcStatus === "ERROR" ||
        domain.dkimStatus === "ERROR"),
  );

  const scoreCoverageIsPartial =
    integration?.mfaEvidenceStatus === "PERMISSION_REQUIRED" ||
    integration?.mfaEvidenceStatus === "ERROR" ||
    domainCoverageIsPartial ||
    cyberScore.unsupportedFindingCount > 0;

  const latestScoreSnapshot = scoreHistory[0];
  const previousScoreSnapshot = scoreHistory[1];
  const scoreDelta =
    latestScoreSnapshot &&
    previousScoreSnapshot &&
    latestScoreSnapshot.modelVersion === previousScoreSnapshot.modelVersion
      ? latestScoreSnapshot.score - previousScoreSnapshot.score
      : null;

  const canManageIntegrations =
    membership.role === "OWNER" || membership.role === "ADMIN";
  const remediationExecutorConfigured =
    isMicrosoftRemediationExecutorConfigured();
  const remediationExecutorAvailable =
    remediationExecutorConfigured &&
    integration?.remediationStatus === "AVAILABLE";

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

              <div className="remediation-capability">
                <strong>Automated remediation</strong>
                <p>
                  Status: {integration.remediationStatus}
                  {integration.remediationCheckedAt
                    ? ` · checked ${integration.remediationCheckedAt.toISOString()}`
                    : ""}
                </p>

                {!remediationExecutorConfigured ? (
                  <p>
                    The isolated remediation application is not configured on
                    the CyberPilot server.
                  </p>
                ) : integration.remediationStatus !== "AVAILABLE" &&
                  canManageIntegrations ? (
                  <p className="action-link">
                    <Link
                      href={`/api/organizations/${membership.organization.slug}/integrations/microsoft-365/remediation/connect`}
                    >
                      Grant remediation permission
                    </Link>
                  </p>
                ) : integration.remediationStatus === "AVAILABLE" ? (
                  <p>
                    Tenant-scoped remediation permission has been verified.
                  </p>
                ) : null}
              </div>

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





        <section className="remediation-section">
          <div className="section-heading">
            <p className="eyebrow">Fix</p>
            <h2>Remediation playbooks</h2>
          </div>

          {remediations.length === 0 ? (
            <div className="empty-state">
              <p>
                CyberPilot will propose a remediation playbook when a supported
                finding is detected.
              </p>
            </div>
          ) : (
            <div className="remediation-list">
              {remediations.map((remediation) => {
                const steps = Array.isArray(remediation.steps)
                  ? remediation.steps.filter(
                      (step): step is string => typeof step === "string",
                    )
                  : [];
                const verification = Array.isArray(remediation.verification)
                  ? remediation.verification.filter(
                      (step): step is string => typeof step === "string",
                    )
                  : [];

                return (
                  <article className="remediation-card" key={remediation.id}>
                    <div className="remediation-heading">
                      <div>
                        <p className="priority-score">
                          {remediation.mode} · {remediation.status}
                        </p>
                        <h3>{remediation.title}</h3>
                      </div>
                      <span className="role-badge">
                        {remediation.finding.severity}
                      </span>
                    </div>

                    <p>{remediation.summary}</p>
                    <p className="remediation-source">
                      Finding: {remediation.finding.title}
                    </p>

                    <div className="remediation-columns">
                      <div>
                        <h4>Steps</h4>
                        <ol>
                          {steps.map((step, index) => (
                            <li key={`${remediation.id}-step-${index}`}>
                              {step}
                            </li>
                          ))}
                        </ol>
                      </div>
                      <div>
                        <h4>Verification</h4>
                        <ol>
                          {verification.map((step, index) => (
                            <li key={`${remediation.id}-verify-${index}`}>
                              {step}
                            </li>
                          ))}
                        </ol>
                      </div>
                    </div>

                    {remediation.failureCode ? (
                      <p className="auth-error">
                        Last execution failed: {remediation.failureCode}
                      </p>
                    ) : null}

                    {canManageIntegrations &&
                    remediation.status === "PROPOSED" &&
                    remediation.finding.status === "OPEN" ? (
                      <form
                        action={`/api/organizations/${membership.organization.slug}/remediations/${remediation.id}/approve`}
                        method="post"
                        className="remediation-actions"
                      >
                        <button className="primary-button" type="submit">
                          Approve playbook
                        </button>
                      </form>
                    ) : null}

                    {canManageIntegrations &&
                    remediation.mode === "AUTOMATED" &&
                    remediation.status === "APPROVED" &&
                    remediation.finding.status === "OPEN" ? (
                      remediationExecutorAvailable ? (
                        <form
                          action={`/api/organizations/${membership.organization.slug}/remediations/${remediation.id}/execute`}
                          method="post"
                          className="remediation-actions"
                        >
                          <button className="primary-button" type="submit">
                            Execute approved remediation
                          </button>
                        </form>
                      ) : (
                        <p className="permission-warning">
                          Automated execution is approved, but the isolated
                          Microsoft remediation permission has not been verified
                          for this tenant.
                        </p>
                      )
                    ) : null}

                    {remediation.mode === "GUIDED" &&
                    remediation.status === "APPROVED" ? (
                      <p className="remediation-status">
                        Approved for guided execution. Complete the steps above,
                        then synchronize CyberPilot to verify the control.
                      </p>
                    ) : null}

                    {remediation.status === "VERIFIED" ? (
                      <p className="remediation-status">
                        Verified successfully
                        {remediation.completedAt
                          ? ` at ${remediation.completedAt.toISOString()}`
                          : ""}.
                      </p>
                    ) : null}
                  </article>
                );
              })}
            </div>
          )}
        </section>

        <section className="history-section">
          <div className="section-heading">
            <p className="eyebrow">Posture history</p>
            <h2>Security trend</h2>
          </div>

          {scoreHistory.length === 0 ? (
            <div className="empty-state">
              <p>
                CyberPilot will create a posture snapshot after each successful
                security synchronization.
              </p>
            </div>
          ) : (
            <>
              <div className="history-summary">
                <div>
                  <p className="panel-label">Latest snapshot</p>
                  <p className="panel-value">{latestScoreSnapshot?.score}</p>
                </div>
                <div>
                  <p className="panel-label">Change</p>
                  <p className="panel-value">
                    {scoreDelta === null
                      ? "—"
                      : scoreDelta > 0
                        ? `+${scoreDelta}`
                        : scoreDelta}
                  </p>
                </div>
                <div>
                  <p className="panel-label">Coverage</p>
                  <p className="history-coverage">
                    {latestScoreSnapshot?.coverage ?? "—"}
                  </p>
                </div>
              </div>

              <div className="history-list">
                {scoreHistory.map((snapshot) => (
                  <article className="history-row" key={snapshot.id}>
                    <div>
                      <strong>{snapshot.score}/100</strong>
                      <span>
                        {snapshot.riskPoints.toFixed(1)} risk points
                      </span>
                    </div>
                    <div>
                      <span>{snapshot.coverage}</span>
                      <span>
                        {snapshot.supportedFindingCount} scored /{" "}
                        {snapshot.unsupportedFindingCount} unscored
                      </span>
                    </div>
                    <div>
                      <span>CyberScore {snapshot.modelVersion}</span>
                      <time dateTime={snapshot.calculatedAt.toISOString()}>
                        {snapshot.calculatedAt.toISOString()}
                      </time>
                    </div>
                  </article>
                ))}
              </div>
            </>
          )}
        </section>

        <section className="domain-section">
          <div className="section-heading">
            <p className="eyebrow">Domain security</p>
            <h2>Email authentication posture</h2>
          </div>

          {domains.length === 0 ? (
            <div className="empty-state">
              <p>
                No verified Microsoft 365 domains have been synchronized yet.
              </p>
            </div>
          ) : (
            <div className="domain-list">
              {domains.map((domain) => (
                <article className="domain-card" key={domain.id}>
                  <div className="domain-heading">
                    <div>
                      <h3>{domain.name}</h3>
                      <p>
                        {domain.isInitial
                          ? "Microsoft initial domain"
                          : domain.isDefault
                            ? "Default custom domain"
                            : "Verified custom domain"}
                      </p>
                    </div>
                    {domain.dnsObservedAt ? (
                      <span className="domain-observed">
                        Checked {domain.dnsObservedAt.toISOString()}
                      </span>
                    ) : null}
                  </div>

                  <dl className="domain-signals">
                    <div>
                      <dt>SPF</dt>
                      <dd>{domain.spfStatus}</dd>
                    </div>
                    <div>
                      <dt>DMARC</dt>
                      <dd>
                        {domain.dmarcStatus}
                        {domain.dmarcPolicy
                          ? ` (p=${domain.dmarcPolicy})`
                          : ""}
                      </dd>
                    </div>
                    <div>
                      <dt>Microsoft 365 DKIM DNS</dt>
                      <dd>{domain.dkimStatus}</dd>
                    </div>
                  </dl>

                  {domain.isInitial ? (
                    <p className="domain-note">
                      CyberPilot records this domain for inventory but does not
                      create custom-domain email-authentication findings for it.
                    </p>
                  ) : null}
                </article>
              ))}
            </div>
          )}
        </section>

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
