import { db } from "@cyberpilot/database";
import Link from "next/link";

import {
  buildExecutiveReport,
  type ExecutiveReportFinding,
} from "../../../../lib/executive-report";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { PrintReportButton } from "../../../../components/print-report-button";

type ReportPageProps = {
  params: Promise<{
    slug: string;
  }>;
};

export default async function ExecutiveReportPage({
  params,
}: ReportPageProps) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);

  const [
    integration,
    findings,
    domains,
    snapshots,
    baselineSnapshot,
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
          mode: true,
          displayName: true,
          lastSyncAt: true,
        },
      }),
      db.securityFinding.findMany({
        where: {
          organizationId: membership.organization.id,
          status: "OPEN",
        },
        orderBy: [{ severity: "desc" }, { lastSeenAt: "desc" }],
        select: {
          id: true,
          ruleId: true,
          title: true,
          description: true,
          severity: true,
          firstSeenAt: true,
          lastSeenAt: true,
        },
      }),
      db.domain.findMany({
        where: {
          organizationId: membership.organization.id,
        },
        orderBy: [{ isDefault: "desc" }, { name: "asc" }],
        select: {
          name: true,
          isDefault: true,
          isInitial: true,
          spfStatus: true,
          dmarcStatus: true,
          dmarcPolicy: true,
          dkimStatus: true,
        },
      }),
      db.securityScore.findMany({
        where: {
          organizationId: membership.organization.id,
        },
        orderBy: {
          calculatedAt: "desc",
        },
        take: 2,
        select: {
          score: true,
          riskPoints: true,
          coverage: true,
          modelVersion: true,
          calculatedAt: true,
        },
      }),
      db.securityScore.findFirst({
        where: {
          organizationId: membership.organization.id,
        },
        orderBy: {
          calculatedAt: "asc",
        },
        select: {
          score: true,
          riskPoints: true,
          coverage: true,
          modelVersion: true,
          calculatedAt: true,
        },
      }),
      db.remediation.findMany({
        where: {
          organizationId: membership.organization.id,
        },
        orderBy: {
          createdAt: "desc",
        },
        take: 20,
        select: {
          title: true,
          mode: true,
          status: true,
          completedAt: true,
          finding: {
            select: {
              title: true,
              status: true,
            },
          },
        },
      }),
    ]);

  const report = buildExecutiveReport({
    organizationName: membership.organization.name,
    integrationMode: integration?.mode ?? null,
    integrationDisplayName: integration?.displayName ?? null,
    lastSyncAt: integration?.lastSyncAt ?? null,
    snapshot: snapshots[0] ?? null,
    previousSnapshot: snapshots[1] ?? null,
    baselineSnapshot: baselineSnapshot ?? null,
    findings: findings as ExecutiveReportFinding[],
    domains,
    remediations: remediations
      .filter(
        (remediation) =>
          remediation.status === "VERIFIED" ||
          remediation.finding.status === "OPEN",
      )
      .map((remediation) => ({
        title: remediation.title,
        mode: remediation.mode,
        status: remediation.status,
        completedAt: remediation.completedAt,
        findingTitle: remediation.finding.title,
      })),
  });

  const score = report.snapshot?.score ?? null;
  const coverage = report.snapshot?.coverage ?? null;

  return (
    <main className="report-shell">
      <div className="report-toolbar no-print">
        <div className="report-print-note">
          For a clean PDF, disable <strong>Headers and footers</strong> in the
          browser print dialog.
        </div>
        <Link href={`/organizations/${slug}`} className="secondary-button">
          Back to workspace
        </Link>
        <PrintReportButton />
      </div>

      <article className="executive-report">
        <header className="report-header">
          <div>
            <p className="eyebrow">CyberPilot · Executive Security Report</p>
            <h1>{report.organizationName}</h1>
            <p className="report-meta">
              Generated {report.generatedAt.toISOString()}
            </p>
          </div>
          <div className="report-score-block">
            <span>CyberScore {report.snapshot?.modelVersion ?? "v0"}</span>
            <strong>{score ?? "—"}</strong>
            <span>{coverage ?? "NO SNAPSHOT"}</span>
          </div>
        </header>

        {report.isLab ? (
          <section className="report-warning">
            <strong>LAB REPORT — SYNTHETIC EVIDENCE</strong>
            <p>
              This report was generated from deterministic CyberPilot Lab data.
              It does not represent a real Microsoft 365 tenant.
            </p>
          </section>
        ) : null}

        <section className="report-summary-grid">
          <div>
            <span>Open findings</span>
            <strong>{report.findings.length}</strong>
          </div>
          <div>
            <span>Risk points</span>
            <strong>
              {report.snapshot
                ? report.snapshot.riskPoints.toFixed(1)
                : report.currentRisk.totalRiskPoints.toFixed(1)}
            </strong>
          </div>
          <div>
            <span>Improvement since baseline</span>
            <strong>
              {report.baselineDelta === null
                ? "—"
                : report.baselineDelta > 0
                  ? `+${report.baselineDelta}`
                  : report.baselineDelta}
            </strong>
          </div>
          <div>
            <span>Verified remediations</span>
            <strong>{report.verifiedRemediations.length}</strong>
          </div>
        </section>

        <section className="report-section">
          <h2>Executive summary</h2>
          <p>
            CyberPilot currently reports {report.findings.length} open
            evidence-backed finding{report.findings.length === 1 ? "" : "s"}.
            {report.snapshot
              ? ` The latest immutable CyberScore snapshot is ${report.snapshot.score}/100 with ${report.snapshot.coverage.toLowerCase()} evidence coverage.`
              : " No immutable CyberScore snapshot is available yet."}
            {report.baselineDelta !== null && report.baselineDelta !== 0
              ? ` This is a ${report.baselineDelta > 0 ? "+" : ""}${report.baselineDelta}-point change from the first comparable snapshot.`
              : ""}
          </p>
          <p>
            This report prioritizes only controls currently supported by
            CyberPilot. CyberScore is not a certification, compliance attestation,
            breach prediction, or guarantee of security.
          </p>
          <dl className="report-facts">
            <div>
              <dt>Microsoft 365 source</dt>
              <dd>
                {report.integrationDisplayName ??
                  (report.integrationMode === "LAB"
                    ? "CyberPilot Microsoft 365 Lab"
                    : "Not connected")}
              </dd>
            </div>
            <div>
              <dt>Evidence mode</dt>
              <dd>{report.integrationMode ?? "NONE"}</dd>
            </div>
            <div>
              <dt>Last inventory sync</dt>
              <dd>{report.lastSyncAt?.toISOString() ?? "Not run"}</dd>
            </div>
            <div>
              <dt>Snapshot time</dt>
              <dd>{report.snapshot?.calculatedAt.toISOString() ?? "Unavailable"}</dd>
            </div>
          </dl>
        </section>

        <section className="report-section">
          <h2>Top priorities</h2>
          {report.currentRisk.topActions.length === 0 ? (
            <p>No currently supported open findings require prioritized action.</p>
          ) : (
            <ol className="report-priority-list">
              {report.currentRisk.topActions.map((action) => (
                <li key={action.id}>
                  <div className="report-item-heading">
                    <strong>{action.title}</strong>
                    <span>{action.severity}</span>
                  </div>
                  <p>{action.remediation}</p>
                  <p className="report-muted">
                    {action.riskPoints.toFixed(1)} risk points · {action.rationale}
                  </p>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section className="report-section">
          <h2>Open findings</h2>
          <p className="report-muted">
            Critical {report.severityCounts.CRITICAL} · High{" "}
            {report.severityCounts.HIGH} · Medium {report.severityCounts.MEDIUM} ·
            Low {report.severityCounts.LOW} · Info {report.severityCounts.INFO}
          </p>
          {report.findings.length === 0 ? (
            <p>No open findings.</p>
          ) : (
            <div className="report-table-wrap">
              <table className="report-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Rule</th>
                    <th>Last observed</th>
                  </tr>
                </thead>
                <tbody>
                  {report.findings.map((finding) => (
                    <tr key={finding.id}>
                      <td>{finding.severity}</td>
                      <td>
                        <strong>{finding.title}</strong>
                        <span>{finding.description}</span>
                      </td>
                      <td>{finding.ruleId}</td>
                      <td>{finding.lastSeenAt.toISOString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="report-section">
          <h2>Email authentication posture</h2>
          {report.domains.length === 0 ? (
            <p>No domain evidence available.</p>
          ) : (
            <table className="report-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>SPF</th>
                  <th>DMARC</th>
                  <th>Microsoft 365 DKIM DNS</th>
                </tr>
              </thead>
              <tbody>
                {report.domains.map((domain) => (
                  <tr key={domain.name}>
                    <td>
                      {domain.name}
                      {domain.isInitial ? " · initial" : domain.isDefault ? " · default" : ""}
                    </td>
                    <td>{domain.spfStatus}</td>
                    <td>
                      {domain.dmarcStatus}
                      {domain.dmarcPolicy ? ` (p=${domain.dmarcPolicy})` : ""}
                    </td>
                    <td>{domain.dkimStatus}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="report-section">
          <h2>Remediation evidence</h2>
          {report.remediations.length === 0 ? (
            <p>No remediation records.</p>
          ) : (
            <table className="report-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Mode</th>
                  <th>Playbook</th>
                  <th>Finding</th>
                  <th>Completed</th>
                </tr>
              </thead>
              <tbody>
                {report.remediations.map((remediation, index) => (
                  <tr key={`${remediation.title}-${index}`}>
                    <td>{remediation.status}</td>
                    <td>{remediation.mode}</td>
                    <td>{remediation.title}</td>
                    <td>{remediation.findingTitle}</td>
                    <td>{remediation.completedAt?.toISOString() ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <footer className="report-footer">
          <p>
            CyberPilot report generated from stored evidence and immutable score
            snapshots. Findings reflect only currently implemented controls.
          </p>
        </footer>
      </article>
    </main>
  );
}
