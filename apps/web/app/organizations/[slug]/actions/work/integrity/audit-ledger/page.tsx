import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { loadAuditLedger, type LedgerPage } from "../../../../../../../lib/work-integrity-audit-ledger";
import { inspectLedgerInsights } from "../../../../../../../lib/work-integrity-ledger-insights";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{
    limit?: string; cursor?: string; workItemId?: string;
    actorUserId?: string; decision?: string; includeMalformed?: string;
  }>;
};
export default async function AuditLedgerPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { session, membership } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-ledger`;
  const api = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-ledger`;
  let page: LedgerPage | null = null;
  let error: string | null = null;
  try {
    page = await loadAuditLedger({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, query);
  } catch (caught) {
    if (caught instanceof WorkInputError) error = caught.message;
    else {
      console.error("Audit ledger view failed",
        caught instanceof Error ? caught.message : "unknown");
      error = "Unable to read recorded decisions.";
    }
  }
  const createSearch = (extra: Record<string, string | null>) => {
    const parts = new URLSearchParams();
    for (const [key, value] of Object.entries(query))
      if (value !== undefined) parts.set(key, value);
    for (const [key, value] of Object.entries(extra)) {
      if (value === null) parts.delete(key);
      else parts.set(key, value);
    }
    return parts.toString();
  };
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Operational audit history</p>
        <h1 className="dashboard-title">Recorded integrity review ledger</h1>
        <p className="lede">
          Explore real organization-scoped audit decisions, review timestamps,
          documented rationales, work revisions and predecessor references.
          This view is read-only and does not alter a case or remediation.
        </p>
        <p className="permission-warning">
          Only the selected raw audit page is inspected. Filters on actor and
          decision operate after that bounded page is read. Missing predecessor
          events may exist on earlier pages and do not establish deletion.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-portfolio`}>
            Return to stored audit portfolio
          </Link>
        </p>
        <form action={base} method="get" className="remediation-actions">
          <label htmlFor="ledger-work">Work ID (optional)</label>
          <input id="ledger-work" name="workItemId" type="text"
            defaultValue={query.workItemId ?? ""} placeholder="All work" />
          <label htmlFor="ledger-actor">Actor user ID (optional)</label>
          <input id="ledger-actor" name="actorUserId" type="text"
            defaultValue={query.actorUserId ?? ""} placeholder="All actors" />
          <label htmlFor="ledger-decision">Decision</label>
          <select id="ledger-decision" name="decision" defaultValue={query.decision ?? ""}>
            <option value="">All decisions</option>
            <option value="INVESTIGATE">Investigate</option>
            <option value="ACKNOWLEDGE">Acknowledge</option>
            <option value="DISMISS">Dismiss</option>
            <option value="REOPEN">Reopen</option>
          </select>
          <label htmlFor="ledger-limit">Events per raw page</label>
          <select id="ledger-limit" name="limit" defaultValue={query.limit ?? "25"}>
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
          <label htmlFor="ledger-malformed">Malformed audit metadata</label>
          <select id="ledger-malformed" name="includeMalformed"
            defaultValue={query.includeMalformed ?? "false"}>
            <option value="false">Hide malformed details</option>
            <option value="true">Show malformed details</option>
          </select>
          <button type="submit" className="secondary-button">Read stored events</button>
          <Link href={base}>Reset</Link>
        </form>
        {error ? <p role="alert" className="auth-error">{error}</p> : null}
        {page ? (
          <section aria-label="Recorded audit decision results">
            <h2>Recorded decisions</h2>
            <p>Generated at {page.generatedAt}. {page.fetched} raw audit
              records, {page.matched} matching decoded decisions.</p>
            <p className="action-link">
              <a href={`${api}?${createSearch({ format: "csv" })}`}>
                Download selected raw-page review decisions (CSV)
              </a>
            </p>
            <section aria-label="Audit event sequence observations">
              <h3>Review continuity observations</h3>
              {(() => {
                const insights = inspectLedgerInsights(page);
                return (
                  <>
                    <p>{insights.scanned} decisions across {insights.caseIdentities}
                      {" "}diagnostic identities and {insights.workIdentities} work items.</p>
                    <p>{insights.counts.ERROR} errors,
                      {" "}{insights.counts.REVIEW} requiring review,
                      {" "}{insights.counts.UNKNOWN} unknowns and
                      {" "}{insights.counts.INFO} informational observations.</p>
                    <p className="action-link">
                      <a href={`${api}?${createSearch({ format: "insights-csv" })}`}>
                        Download event sequence observations (CSV)
                      </a>
                    </p>
                    {insights.alerts.length ? (
                      <details>
                        <summary>Inspect {insights.alerts.length} ledger observations</summary>
                        <ul>{insights.alerts.slice(0, 100).map((issue, index) =>
                          <li key={`${issue.eventId}-${issue.kind}-${index}`}>
                            <strong>{issue.severity}: {issue.kind.replaceAll("_", " ")}</strong>
                            <p>Audit event: {issue.eventId}</p>
                            <p>{issue.explanation}</p>
                            <p>Next step: {issue.followup}</p>
                          </li>)}</ul>
                        {insights.alerts.length > 100 ?
                          <p>Only 100 observations are shown. Use the CSV for the remainder.</p> : null}
                      </details>
                    ) : <p>No additional sequence issues detected on this raw page.</p>}
                  </>
                );
              })()}
            </section>
            {page.entries.length ? (
              <div className="remediation-list">
                {page.entries.map(item => (
                  <article className="remediation-card" key={item.eventId}>
                    <div className="remediation-heading">
                      <h3>{item.decision} · {item.code}</h3>
                      <span className="role-badge">
                        {item.reviewedRevisionIsCurrent === null ? "Work unavailable" :
                          item.reviewedRevisionIsCurrent ? "Revision matches" :
                            "Historical work revision"}
                      </span>
                    </div>
                    <p>Review: {item.occurredAt}; actor: {item.actorUserId ?? "Not retained"}</p>
                    <p>Work: {item.workTitle ?? item.workItemId};
                      {" "}revision {item.revision} (current: {item.currentWorkRevision ?? "unknown"})</p>
                    <p>Event: <code>{item.eventId}</code></p>
                    <p>Predecessor: <code>{item.predecessorEventId ?? "First recorded decision"}</code></p>
                    {item.predecessorEventId ? (
                      <p>Earlier event on this page: {item.predecessorInPage ? "Yes" : "Unknown"}.
                        {" "}Chronology: {item.predecessorChronologicallyPrior === null ?
                          "Not available" :
                          item.predecessorChronologicallyPrior ? "Consistent" : "Reversed"}.</p>
                    ) : null}
                    <p>Recorded rationale: {item.rationale}</p>
                    {item.reference ? <p>Review reference: {item.reference}</p> : null}
                    <p className="action-link">
                      <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-chain?${new URLSearchParams({
                        workItemId: item.workItemId,
                      }).toString()}`}>Inspect linked review history</Link>
                    </p>
                  </article>
                ))}
              </div>
            ) : <p>No matching decoded review decisions on this raw page.</p>}
            {page.malformed.length ? (
              <section aria-label="Uninterpretable audit records">
                <h3>Audit records requiring source investigation</h3>
                <ul>{page.malformed.map(record => (
                  <li key={record.eventId}>
                    <strong>{record.reason}</strong>: event {record.eventId}
                    {" "}from {record.occurredAt}, work {record.workItemId ?? "unknown"}
                  </li>
                ))}</ul>
              </section>
            ) : null}
            {page.nextCursor ? (
              <p className="action-link">
                <Link href={`${base}?${createSearch({ cursor: page.nextCursor })}`}>
                  Next raw audit page
                </Link>
              </p>
            ) : <p>No additional raw audit page was returned.</p>}
            <details>
              <summary>Audit provenance and completeness limits</summary>
              <ul>{page.limitations.map((line, index) =>
                <li key={index}>{line}</li>)}</ul>
            </details>
          </section>
        ) : null}
      </section>
    </main>
  );
}
