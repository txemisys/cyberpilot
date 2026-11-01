import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import {
  loadAuditPortfolio, type AuditPortfolioReport,
} from "../../../../../../../lib/work-integrity-audit-portfolio";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{
    limit?: string; cursor?: string;
    onlyReviewed?: string; historyLimit?: string;
  }>;
};
export default async function AuditPortfolioPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { session, membership } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-portfolio`;
  const api = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-portfolio`;
  let report: AuditPortfolioReport | null = null;
  let error: string | null = null;
  try {
    report = await loadAuditPortfolio({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, query);
  } catch (caught) {
    if (caught instanceof WorkInputError) error = caught.message;
    else {
      console.error("Audit portfolio page failed",
        caught instanceof Error ? caught.message : "unknown");
      error = "Unable to read audit portfolio.";
    }
  }
  const makeQuery = (extra: Record<string, string | null>) => {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query))
      if (value !== undefined) params.set(key, value);
    for (const [key, value] of Object.entries(extra)) {
      if (value === null) params.delete(key);
      else params.set(key, value);
    }
    return params.toString();
  };
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Operational audit oversight</p>
        <h1 className="dashboard-title">Stored integrity review portfolio</h1>
        <p className="lede">
          Inspect actual organization-scoped work and the continuity of its
          recorded human review events. Each item is independently checked
          against its stored audit chain and current work revision.
        </p>
        <p className="permission-warning">
          This portfolio reports only the selected bounded work-item page.
          Review records cannot establish that a remediation, security
          control or compliance obligation was successfully verified.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/analyst-queue`}>
            Return to operational integrity queue
          </Link>
        </p>
        <p className="action-link">
          <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-ledger`}>
            Browse recorded human integrity review events
          </Link>
        </p>
        <form action={base} method="get" className="remediation-actions">
          <label htmlFor="portfolio-limit">Work items per cursor page</label>
          <select id="portfolio-limit" name="limit"
            defaultValue={query.limit ?? "20"}>
            <option value="10">10</option>
            <option value="20">20</option>
            <option value="50">50</option>
          </select>
          <label htmlFor="portfolio-history">Audit events per work item</label>
          <select id="portfolio-history" name="historyLimit"
            defaultValue={query.historyLimit ?? "500"}>
            <option value="100">100</option>
            <option value="500">500</option>
            <option value="1000">1,000</option>
            <option value="2000">2,000</option>
          </select>
          <label htmlFor="portfolio-reviewed">Recorded review</label>
          <select id="portfolio-reviewed" name="onlyReviewed"
            defaultValue={query.onlyReviewed ?? "false"}>
            <option value="false">Include unreviewed</option>
            <option value="true">Show reviewed on this source page</option>
          </select>
          <button className="secondary-button" type="submit">
            Inspect work and audit records
          </button>
          <Link href={base}>Reset</Link>
        </form>
        {error ? <p className="auth-error" role="alert">{error}</p> : null}
        {report ? (
          <section aria-label="Tenant-scoped audit portfolio results">
            <p>
              Captured at {report.generatedAt}. Inspected
              {" "}{report.examinedWorkItems} actual work items.
              {" "}{report.counts.total} match the selected review filter.
            </p>
            <div className="panel" aria-label="Audit coverage counts">
              <div><p className="panel-label">Review chain complete</p>
                <p className="panel-value">{report.counts.complete}</p></div>
              <div><p className="panel-label">No review recorded</p>
                <p className="panel-value">{report.counts.noReview}</p></div>
              <div><p className="panel-label">Coverage incomplete</p>
                <p className="panel-value">{report.counts.partial}</p></div>
              <div><p className="panel-label">Inconsistent audit chain</p>
                <p className="panel-value">{report.counts.inconsistent}</p></div>
            </div>
            <p>
              {report.counts.errors} audit-chain errors,
              {" "}{report.counts.warnings} warnings and
              {" "}{report.counts.unknowns} unresolved links
              among the returned work items.
            </p>
            <p className="action-link">
              <a href={`${api}?${makeQuery({ format: "csv" })}`}>
                Download portfolio CSV
              </a>
            </p>
            <section aria-label="Audited work item details">
              <h2>Work requiring review attention</h2>
              {report.rows.length === 0 ? (
                <p>No work items match this review selection on the current
                  source page. Other pages may contain matching work.</p>
              ) : (
                <div className="remediation-list">
                  {report.rows.map(row => (
                    <article key={row.workItemId} className="remediation-card">
                      <div className="remediation-heading">
                        <h3>{row.title}</h3>
                        <span className="role-badge">
                          {row.reviewCoverage.replaceAll("_", " ")}
                        </span>
                      </div>
                      <p>Work ID: {row.workItemId}</p>
                      <p>Operational status: {row.status}. Revision {row.revision}.</p>
                      <p>Assigned to: {row.assigneeUserId ?? "Unassigned"}.
                        {" "}Due: {row.dueAt ?? "Not scheduled"}.</p>
                      <p>{row.auditEventsRead} audit records;
                        {" "}{row.cases} reviewed diagnostic identities.</p>
                      <p>{row.errors} errors; {row.warnings} warnings;
                        {" "}{row.unknowns} unknown links.</p>
                      <p><strong>Suggested next step:</strong> {row.action}</p>
                      <p className="action-link">
                        <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-chain?${new URLSearchParams({
                          workItemId: row.workItemId,
                          limit: String(report.filters.historyLimit),
                        }).toString()}`}>
                          Inspect this item's stored decision chain
                        </Link>
                      </p>
                    </article>
                  ))}
                </div>
              )}
            </section>
            {report.nextCursor ? (
              <p className="action-link">
                <Link href={`${base}?${makeQuery({ cursor: report.nextCursor })}`}>
                  Next bounded work-item page
                </Link>
              </p>
            ) : (
              <p>No additional cursor page was returned for this selection.</p>
            )}
            <details>
              <summary>Portfolio coverage and interpretation limits</summary>
              <ul>{report.limitations.map((text, index) =>
                <li key={index}>{text}</li>)}</ul>
            </details>
          </section>
        ) : null}
      </section>
    </main>
  );
}
