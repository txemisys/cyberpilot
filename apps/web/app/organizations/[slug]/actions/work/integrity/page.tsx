import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { loadWorkIntegrity } from "../../../../../../lib/work-integrity";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";
import { buildIntegrityTriage, selectIntegrityRows, summarizeIntegrityReview } from "../../../../../../lib/work-integrity-export";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{ cursor?: string; limit?: string; includeInfo?: string }>;
};
function severityLabel(value: "critical" | "attention" | "info") {
  switch (value) {
    case "critical": return "Data integrity problem";
    case "attention": return "Review recommended";
    case "info": return "Context for review";
  }
}
export default async function WorkIntegrityPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { session, membership } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity`;
  let result: Awaited<ReturnType<typeof loadWorkIntegrity>> | null = null;
  let error: string | null = null;
  try {
    result = await loadWorkIntegrity({
      organizationId: membership.organization.id,
      userId: session.user.id,
      role: membership.role,
    }, query);
  } catch (caught) {
    if (caught instanceof WorkInputError) error = caught.message;
    else throw caught;
  }
  const next = new URLSearchParams();
  next.set("limit", query.limit ?? "25");
  if (query.includeInfo === "true") next.set("includeInfo", "true");
  if (result?.nextCursor) next.set("cursor", result.nextCursor);
  const counts = { critical: 0, attention: 0, info: 0 };
  for (const item of result?.findings ?? []) counts[item.severity]++;
  const incomplete = result?.items.filter(item => !item.complete).length ?? 0;
  const selectedRows = result ? selectIntegrityRows(result) : [];
  const triage = buildIntegrityTriage(selectedRows);
  const statistics = result ? summarizeIntegrityReview(result) : null;
  const exportQuery = new URLSearchParams();
  exportQuery.set("limit", query.limit ?? "25");
  if (query.cursor) exportQuery.set("cursor", query.cursor);
  exportQuery.set("includeInfo", "true");

  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Operational remediation</p>
        <h1 className="dashboard-title">Work record integrity</h1>
        <p className="lede">
          Review consistency of stored tasks, handoffs, evidence links and activity.
          This is a data-quality diagnostic, not a security verification.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${slug}/actions/work`}>Return to work coordination</Link>
        </p>
        <p className="action-link">
          <Link href={`/organizations/${slug}/actions/work/integrity/triage`}>
            Review recorded diagnostic decisions and investigation history
          </Link>
        </p>
        <p className="permission-warning">
          An inconsistency does not prove a control is unsafe. An absence of listed
          inconsistencies does not establish compliance, evidence freshness or remediation closure.
        </p>
        <form action={base} method="get" className="remediation-actions">
          <label htmlFor="integrity-limit">Tasks per page</label>
          <select id="integrity-limit" name="limit" defaultValue={query.limit ?? "25"}>
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
          <label htmlFor="integrity-info">Informational signals</label>
          <select id="integrity-info" name="includeInfo" defaultValue={query.includeInfo ?? "false"}>
            <option value="false">Hide informational signals</option>
            <option value="true">Show informational signals</option>
          </select>
          <button type="submit" className="secondary-button">Run review from first page</button>
        </form>
        {error ? (
          <div className="empty-state" role="alert">
            <p>Unable to apply review filters: {error}</p>
            <Link href={base}>Reset review</Link>
          </div>
        ) : null}
        {result ? (
          <>
            <div className="panel" aria-label="Integrity review page summary">
              <div>
                <p className="panel-label">Tasks examined on this page</p>
                <p className="panel-value">{result.checked}</p>
              </div>
              <div>
                <p className="panel-label">Integrity problems</p>
                <p className="panel-value">{counts.critical}</p>
              </div>
              <div>
                <p className="panel-label">Attention signals</p>
                <p className="panel-value">{counts.attention}</p>
              </div>
              <div>
                <p className="panel-label">Incomplete linked-record coverage</p>
                <p className="panel-value">{incomplete}</p>
              </div>
            </div>
            <p className="score-caption">
              Review generated {result.generatedAt}. Counts describe only this page.
              {counts.info ? ` ${counts.info} additional informational signals.` : ""}
            </p>
            <section aria-label="Download operational integrity review">
              <h2>Portable diagnostic package</h2>
              <p>Both exports are limited to the current cursor page. CSV is escaped for
                spreadsheet safety; JSON includes follow-up groups and coverage statistics.
                Neither format is a certification or evidence of a resolved finding.</p>
              <p className="action-link">
                <a href={`/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/export?${exportQuery.toString()}&format=csv`}>
                  Download integrity findings as CSV
                </a>
              </p>
              <p className="action-link">
                <a href={`/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/export?${exportQuery.toString()}&format=json`}>
                  Download integrity review with triage as JSON
                </a>
              </p>
              <p className="score-caption">
                This page contains {statistics?.withFindings ?? 0} tasks with at least one
                diagnostic signal and {statistics?.withoutFindings ?? 0} without a returned
                signal. There are {statistics?.partialCoverage ?? 0} tasks with truncated
                linked records.
              </p>
            </section>
            <section aria-label="Suggested diagnostic follow-up">
              <h2>Suggested review sequence</h2>
              {triage.length === 0 ? (
                <p>No priority groups were produced from this page of diagnostic results.
                  This does not establish security verification.</p>
              ) : (
                <ol>
                  {triage.map(group => (
                    <li key={group.title}>
                      <h3>{group.title}</h3>
                      <p>{group.findingCount} signals across {group.affectedWorkItems.length}
                        distinct work records.</p>
                      <p>{group.nextAction}</p>
                      <details>
                        <summary>Related work records and diagnostic codes</summary>
                        <ul>{group.affectedWorkItems.map(id => (
                          <li key={id}>{id}</li>
                        ))}</ul>
                        <p>Codes: {group.codes.join(", ")}</p>
                        <p>{group.verificationCaveat}</p>
                      </details>
                    </li>
                  ))}
                </ol>
              )}
            </section>
            {result.items.length === 0 ? (
              <p>No work items were found for this page.</p>
            ) : (
              <div className="remediation-list">
                {result.items.map(item => (
                  <article key={item.workItemId} className="remediation-card">
                    <div className="remediation-heading">
                      <div>
                        <h2>Work record {item.workItemId}</h2>
                        <p className="score-caption">
                          {item.status} · Revision {item.revision}
                          · Updated {new Date(item.updatedAt).toISOString()}
                        </p>
                      </div>
                      <span className="role-badge">
                        {item.complete ? "Bounded checks complete" : "Partial coverage"}
                      </span>
                    </div>
                    <p className="action-link">
                      <Link href={`/organizations/${slug}/actions/work/${item.workItemId}`}>
                        Inspect operational work record
                      </Link>
                    </p>
                    {!item.complete ? (
                      <p className="permission-warning">
                        One or more linked-record collections reached the safety limit.
                        Checks depending on those collections were withheld.
                      </p>
                    ) : null}
                    {item.findings.length === 0 ? (
                      <p>No inconsistencies detected by the checks applied to this record.</p>
                    ) : (
                      <ul>
                        {item.findings.map((finding, index) => (
                          <li key={`${finding.code}-${finding.resourceId}-${index}`}>
                            <strong>{severityLabel(finding.severity)}: {finding.code}</strong>
                            <p>{finding.message}</p>
                            <p>Suggested follow-up: {finding.recommendation}</p>
                            <p className="score-caption">
                              Related record: {finding.resourceId}
                            </p>
                          </li>
                        ))}
                      </ul>
                    )}
                  </article>
                ))}
              </div>
            )}
            {result.nextCursor ? (
              <p className="action-link">
                <Link href={`${base}?${next.toString()}`}>Review next page</Link>
              </p>
            ) : (
              <p className="score-caption">
                End of the currently reachable cursor sequence.
              </p>
            )}
            <details>
              <summary>Coverage and interpretation limitations</summary>
              <ul>
                {result.limitations.map(line => <li key={line}>{line}</li>)}
              </ul>
              <p>
                This page never writes to the remediation workflow or changes security scores.
                Review any findings with organization administrators before taking action.
              </p>
            </details>
          </>
        ) : null}
      </section>
    </main>
  );
}
