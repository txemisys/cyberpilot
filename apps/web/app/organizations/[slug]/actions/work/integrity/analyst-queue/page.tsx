import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { loadIntegrityCases } from "../../../../../../../lib/work-integrity-cases";
import { buildLiveIntegrityPage } from "../../../../../../../lib/work-integrity-live-queue";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{
    priority?: string; reviewed?: string; offset?: string; pageSize?: string;
    cursor?: string; limit?: string; state?: string; severity?: string;
    search?: string; includeInfo?: string; includeHistorical?: string;
  }>;
};
export default async function AnalystQueuePage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { session, membership } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/analyst-queue`;
  const api = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/analyst-queue`;
  let report: ReturnType<typeof buildLiveIntegrityPage> | null = null;
  let error: string | null = null;
  try {
    const page = await loadIntegrityCases({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, query);
    report = buildLiveIntegrityPage(membership.organization.id, page, query);
  } catch (caught) {
    if (caught instanceof WorkInputError || caught instanceof Error)
      error = caught.message;
    else throw caught;
  }
  const buildQuery = (changes: Record<string, string | null>) => {
    const values = new URLSearchParams();
    for (const [key, value] of Object.entries(query))
      if (value !== undefined) values.set(key, value);
    for (const [key, value] of Object.entries(changes)) {
      if (value === null) values.delete(key);
      else values.set(key, value);
    }
    return values.toString();
  };
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Operational integrity</p>
        <h1 className="dashboard-title">Analyst investigation queue</h1>
        <p className="lede">
          Live operational case records, deterministic review priorities and
          evidence-readiness checks. Every result is scoped to your organization
          and the selected bounded work-item page.
        </p>
        <p className="permission-warning">
          This queue does not execute remediation, assign an analyst, authenticate
          evidence or certify control effectiveness. Counts are not organization-wide.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/cases`}>
            Return to investigation cases
          </Link>
        </p>
        <form method="get" action={base} className="remediation-actions">
          <label htmlFor="analyst-priority">Review priority</label>
          <select id="analyst-priority" name="priority" defaultValue={query.priority ?? "ALL"}>
            <option value="ALL">All priorities</option>
            {(["P0", "P1", "P2", "P3", "P4"] as const).map(value =>
              <option value={value} key={value}>{value}</option>)}
          </select>
          <label htmlFor="analyst-reviewed">Recorded human review</label>
          <select id="analyst-reviewed" name="reviewed" defaultValue={query.reviewed ?? "ALL"}>
            <option value="ALL">All cases</option>
            <option value="NO">Awaiting review</option>
            <option value="YES">Review recorded</option>
          </select>
          <label htmlFor="analyst-size">Cases per page</label>
          <select id="analyst-size" name="pageSize" defaultValue={query.pageSize ?? "25"}>
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
          <input type="hidden" name="includeInfo" value="true" />
          <input type="hidden" name="includeHistorical" value="true" />
          <button type="submit" className="secondary-button">Apply filters</button>
          <Link href={base}>Reset queue</Link>
        </form>
        {error ? <p role="alert" className="auth-error">{error}</p> : null}
        {report ? (
          <>
            <div className="panel" aria-label="Analyst queue metrics">
              <div><p className="panel-label">Cases on selected work page</p>
                <p className="panel-value">{report.totalCasesOnWorkPage}</p></div>
              <div><p className="panel-label">Highest priority (P0)</p>
                <p className="panel-value">{report.priorities.P0}</p></div>
              <div><p className="panel-label">Evidence blocked</p>
                <p className="panel-value">{report.evidence.blocked}</p></div>
              <div><p className="panel-label">Stale reviews</p>
                <p className="panel-value">{report.metrics.stale}</p></div>
              <div><p className="panel-label">Incomplete linked coverage</p>
                <p className="panel-value">{report.metrics.incompleteCoverage}</p></div>
            </div>
            <p className="score-caption">
              Captured {report.capturedAt}. Examined {report.workItemsExamined}
              work items on this cursor page.
              {report.snapshotComplete
                ? " The selected capture page has complete linked coverage."
                : " This page is partial or is one segment of a larger capture."}
            </p>
            <section aria-label="Download analyst queue">
              <h2>Download this analyst queue page</h2>
              <p>Exports include only the currently filtered cases and
                their evidence gaps. They do not contain verified remediation outcomes.</p>
              <p className="action-link">
                <a href={`${api}?${buildQuery({ format: "csv" })}`}>Download CSV</a>
              </p>
              <p className="action-link">
                <a href={`${api}?${buildQuery({ format: "json" })}`}>Download JSON</a>
              </p>
            </section>
            <section aria-label="Diagnostic groups">
              <h2>Diagnostic distribution on this page</h2>
              {report.groups.length ? (
                <ul>
                  {report.groups.map(group => (
                    <li key={group.code}>
                      <strong>{group.code}</strong>: {group.count} cases,
                      {" "}{group.critical} critical,
                      {" "}{group.stale} stale,
                      {" "}{group.incompleteCoverage} incomplete
                    </li>
                  ))}
                </ul>
              ) : <p>No diagnostic groups were found.</p>}
            </section>
            <section aria-label="Evidence readiness summary">
              <h2>Evidence preparation</h2>
              <p>
                {report.evidence.ready} cases have the configured review metadata
                present, and {report.evidence.blocked} need further evidence work.
                These are metadata checks, not independent authenticity checks.
              </p>
              <ul>
                <li>{report.evidence.missingReview} cases have no linked human review.</li>
                <li>{report.evidence.staleReview} cases refer to an outdated reviewed revision.</li>
                <li>{report.evidence.incompleteCoverage} cases have incomplete linked data.</li>
              </ul>
              <p className="action-link">
                <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/triage`}>
                  Open human decision history and audit trail
                </Link>
              </p>
            </section>
            <section aria-label="Review workload batches">
              <h2>Suggested review batches</h2>
              <p>
                Batches are computed from the current bounded case page, grouped
                by deterministic operational priority. They are not assigned to
                any analyst and do not create remediation work.
              </p>
              {report.batches.length === 0 ? (
                <p>No review batches are present on this page.</p>
              ) : (
                <ul>
                  {report.batches.map(batch => (
                    <li key={batch.id}>
                      <strong>{batch.priority}</strong> · {batch.count} cases
                      {" · "}{batch.completeCoverage
                        ? "Linked coverage available"
                        : "Partial coverage"}
                      {batch.requiresReassessment
                        ? " · Contains stale reviews requiring reassessment"
                        : ""}
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section aria-label="Review reason breakdown">
              <h2>Why cases appear in the review queue</h2>
              <p>
                A case can have multiple reasons. The following figures overlap
                and must not be added together as distinct case counts.
              </p>
              <ul>
                {Object.entries(report.reviewReasons)
                  .filter(([, count]) => count > 0)
                  .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
                  .map(([reason, count]) => (
                    <li key={reason}>
                      <strong>{reason.replaceAll("_", " ")}</strong>: {count} cases
                    </li>
                  ))}
              </ul>
            </section>
            <section aria-label="Priority navigation">
              <h2>Jump to a review priority</h2>
              <p>
                These filters operate within the selected work-item cursor page.
                Select a priority to see the corresponding cases and their
                evidence gaps.
              </p>
              <ul>
                {(["P0", "P1", "P2", "P3", "P4"] as const).map(priority => (
                  <li key={priority}>
                    <Link href={`${base}?${buildQuery({
                      priority, offset: null,
                    })}`}>
                      {priority}: {report.priorities[priority]} cases
                    </Link>
                  </li>
                ))}
              </ul>
              <p className="action-link">
                <Link href={`${base}?${buildQuery({
                  priority: "ALL", reviewed: "NO", offset: null,
                })}`}>
                  Show cases without recorded human review
                </Link>
              </p>
              <p className="action-link">
                <Link href={`${base}?${buildQuery({
                  priority: "ALL", reviewed: "YES", offset: null,
                })}`}>
                  Show cases with recorded human review
                </Link>
              </p>
            </section>
            <section aria-label="Prioritized investigation cases">
              <h2>Cases requiring analyst attention</h2>
              <p>{report.totalMatching} cases match the selected filters on this work page.</p>
              {report.entries.length === 0 ? (
                <p>No matching cases on this page. Other cursor pages may contain cases.</p>
              ) : (
                <div className="remediation-list">
                  {report.entries.map(item => (
                    <article key={item.caseKey} className="remediation-card">
                      <div className="remediation-heading">
                        <div>
                          <h3>{item.code}</h3>
                          <p>{item.workItemId} · {item.resourceId}</p>
                        </div>
                        <span className="role-badge">{item.priority} · {item.state}</span>
                      </div>
                      <p>Review reasons: {item.reasons.join(", ") || "None recorded"}</p>
                      <p>Suggested next step: {item.suggestedAction}</p>
                      <p>Evidence metadata: {item.evidenceReady
                        ? "Required fields present"
                        : "Missing or outdated evidence metadata"}</p>
                      {!item.evidenceReady ? (
                        <p className="permission-warning">
                          Evidence gaps: {item.missingEvidence.join(", ")}
                        </p>
                      ) : null}
                      {!item.completeCoverage ? (
                        <p className="permission-warning">
                          Linked-record collection is incomplete. Do not infer resolution.
                        </p>
                      ) : null}
                      <p className="action-link">
                        <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/triage?workItemId=${encodeURIComponent(item.workItemId)}`}>
                          Inspect or record authorized human review
                        </Link>
                      </p>
                    </article>
                  ))}
                </div>
              )}
              {report.nextOffset !== null ? (
                <p className="action-link">
                  <Link href={`${base}?${buildQuery({ offset: String(report.nextOffset) })}`}>
                    Next cases on this work page
                  </Link>
                </p>
              ) : null}
              {report.nextWorkCursor ? (
                <p className="action-link">
                  <Link href={`${base}?${buildQuery({
                    cursor: report.nextWorkCursor, offset: null,
                  })}`}>Next work-item cursor page</Link>
                </p>
              ) : null}
            </section>
            <details>
              <summary>Coverage and interpretation limitations</summary>
              <ul>{report.limitations.map((line, index) =>
                <li key={index}>{line}</li>)}</ul>
            </details>
          </>
        ) : null}
      </section>
    </main>
  );
}
