import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { loadIntegrityCases, CASE_STATES } from "../../../../../../../lib/work-integrity-cases";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{
    state?: string; severity?: string; search?: string;
    limit?: string; cursor?: string; includeInfo?: string;
    includeHistorical?: string;
  }>;
};
export default async function IntegrityCasesPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { session, membership } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/cases`;
  let report: Awaited<ReturnType<typeof loadIntegrityCases>> | null = null;
  let error: string | null = null;
  try {
    report = await loadIntegrityCases({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, query);
  } catch (caught) {
    if (caught instanceof WorkInputError) error = caught.message;
    else throw caught;
  }
  const next = new URLSearchParams();
  for (const [key, value] of Object.entries(query))
    if (value !== undefined && key !== "cursor") next.set(key, value);
  if (report?.nextCursor) next.set("cursor", report.nextCursor);
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Operational integrity</p>
        <h1 className="dashboard-title">Integrity investigation cases</h1>
        <p className="lede">
          Connect current data-quality findings with recorded human investigation decisions,
          including stale reviews that require a new assessment.
        </p>
        <p className="permission-warning">
          These cases are not security incidents or proof of compliance. They never
          alter the underlying remediation or verification state.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${slug}/actions/work/integrity`}>Return to integrity review</Link>
        </p>
        <p className="action-link">
          <Link href={`/organizations/${slug}/actions/work/integrity/triage`}>
            Record or inspect an auditable review decision
          </Link>
        </p>
        <form method="get" action={base} className="remediation-actions">
          <label htmlFor="case-state">Review state</label>
          <select id="case-state" name="state" defaultValue={query.state ?? "ALL"}>
            <option value="ALL">All states</option>
            {CASE_STATES.map(state => <option key={state} value={state}>{state}</option>)}
          </select>
          <label htmlFor="case-severity">Diagnostic severity</label>
          <select id="case-severity" name="severity" defaultValue={query.severity ?? "ALL"}>
            <option value="ALL">All severities</option>
            <option value="critical">Data integrity</option>
            <option value="attention">Attention</option>
            <option value="info">Informational</option>
          </select>
          <label htmlFor="case-search">Find a diagnostic or resource</label>
          <input id="case-search" name="search" maxLength={120}
            defaultValue={query.search ?? ""} />
          <label htmlFor="case-limit">Work items per page</label>
          <select id="case-limit" name="limit" defaultValue={query.limit ?? "25"}>
            <option value="10">10</option><option value="25">25</option>
            <option value="50">50</option><option value="100">100</option>
          </select>
          <label htmlFor="case-info">Informational diagnostics</label>
          <select id="case-info" name="includeInfo" defaultValue={query.includeInfo ?? "false"}>
            <option value="false">Hide</option><option value="true">Show</option>
          </select>
          <label htmlFor="case-history">Previously reviewed but no longer detected</label>
          <select id="case-history" name="includeHistorical"
            defaultValue={query.includeHistorical ?? "false"}>
            <option value="false">Exclude</option><option value="true">Include when covered</option>
          </select>
          <button type="submit" className="secondary-button">Apply case filters</button>
          <Link href={base}>Clear all filters</Link>
        </form>
        {error ? (
          <p role="alert" className="auth-error">{error}</p>
        ) : null}
        {report ? (
          <>
            <div className="panel" aria-label="Current case page summary">
              <div><p className="panel-label">Work items examined</p>
                <p className="panel-value">{report.totalWorkItemsExamined}</p></div>
              <div><p className="panel-label">Cases on this page</p>
                <p className="panel-value">{report.summary.totalOnPage}</p></div>
              <div><p className="panel-label">Not reviewed</p>
                <p className="panel-value">{report.summary.unreviewed}</p></div>
              <div><p className="panel-label">Stale decisions</p>
                <p className="panel-value">{report.summary.stale}</p></div>
              <div><p className="panel-label">Incomplete linked data</p>
                <p className="panel-value">{report.summary.partialCoverage}</p></div>
            </div>
            <p className="score-caption">
              Generated {report.generatedAt} ·
              {report.reviewEventsFetched} relevant audit events were retrieved.
              {report.historyComplete ? " Audit event limit not reached." :
                " Audit history truncated; previous decisions were withheld."}
            </p>
            {report.cases.length === 0 ? (
              <p>No cases match these filters on this work-item page.
                Try a different filter or review the next page if available.</p>
            ) : (
              <div className="remediation-list">
                {report.cases.map(item => (
                  <article className="remediation-card" key={item.key}>
                    <div className="remediation-heading">
                      <div>
                        <h2>{item.code}</h2>
                        <p>{item.workItemId} · {item.resourceId}</p>
                      </div>
                      <span className="role-badge">{item.state}</span>
                    </div>
                    <p>Task: {item.taskStatus} · Revision {item.taskRevision}</p>
                    {item.severity ? <p>Diagnostic severity: {item.severity}</p> : null}
                    {item.diagnostic ? <p>{item.diagnostic}</p> : (
                      <p>Historical review only. The diagnostic is not currently present
                        in the retrieved fully covered linked records.</p>
                    )}
                    {item.recommendation ? <p>Suggested follow-up: {item.recommendation}</p> : null}
                    {item.reviewEventId ? (
                      <details>
                        <summary>Most recent recorded human review</summary>
                        <p>Decision event: {item.reviewEventId}</p>
                        <p>Reviewed: {item.reviewedAt}</p>
                        <p>Recorded revision: {item.reviewedRevision}</p>
                        <p>Actor: {item.reviewerUserId ?? "Unavailable"}</p>
                        <p>Rationale: {item.reviewRationale}</p>
                        {item.reviewReference ? <p>Reference: {item.reviewReference}</p> : null}
                      </details>
                    ) : <p>No human triage decision is currently linked to this diagnostic.</p>}
                    {!item.completeCoverage ? (
                      <p className="permission-warning">
                        Linked data reached a safety limit. A complete assessment cannot be inferred.
                      </p>
                    ) : null}
                    {item.state === "STALE" ? (
                      <p className="permission-warning">
                        The recorded decision refers to a different work item revision.
                        A new review is required.
                      </p>
                    ) : null}
                    <p className="action-link">
                      <Link href={`/organizations/${slug}/actions/work/integrity/triage?workItemId=${encodeURIComponent(item.workItemId)}`}>
                        Open human review history
                      </Link>
                    </p>
                  </article>
                ))}
              </div>
            )}
            {report.nextCursor ? (
              <p className="action-link"><Link href={`${base}?${next.toString()}`}>
                Review next page of work items
              </Link></p>
            ) : <p className="score-caption">No more work-item pages returned.</p>}
            <details>
              <summary>Coverage and interpretation</summary>
              <ul>{report.limitations.map(line => <li key={line}>{line}</li>)}</ul>
            </details>
          </>
        ) : null}
      </section>
    </main>
  );
}
