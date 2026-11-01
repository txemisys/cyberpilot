import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { loadAuditBranches, type BranchReport } from "../../../../../../../lib/work-integrity-audit-branch-explorer";
import { planBranchActions } from "../../../../../../../lib/work-integrity-audit-branch-actions";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{ workItemId?: string; limit?: string; includeRationale?: string }>;
};
export default async function AuditBranchesPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { membership, session } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-branches`;
  const api = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-branches`;
  let report: BranchReport | null = null;
  let error: string | null = null;
  if (query.workItemId) {
    try {
      report = await loadAuditBranches({
        organizationId: membership.organization.id,
        userId: session.user.id, role: membership.role,
      }, query);
    } catch (caught) {
      if (caught instanceof WorkInputError) error = caught.message;
      else {
        console.error("Audit branch inspection failed",
          caught instanceof Error ? caught.message : "unknown");
        error = "Unable to inspect the recorded review graph.";
      }
    }
  }
  const downloadParams = new URLSearchParams();
  if (query.workItemId) downloadParams.set("workItemId", query.workItemId);
  if (query.limit) downloadParams.set("limit", query.limit);
  if (query.includeRationale) downloadParams.set("includeRationale", query.includeRationale);
  downloadParams.set("format", "csv");
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Review concurrency</p>
        <h1 className="dashboard-title">Stored audit branch explorer</h1>
        <p className="lede">
          Examine all review-event branches visible in a bounded tenant-scoped
          work-item audit history. This complements a single predecessor chain
          by checking competing successors and disconnected roots.
        </p>
        <p className="permission-warning">
          The graph is derived from recorded human triage events, not an
          external cryptographic attestation. It never confirms a control's
          security effectiveness or closes an investigation automatically.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-portfolio`}>
            Return to work audit portfolio
          </Link>
        </p>
        <form action={base} method="get" className="remediation-actions">
          <label htmlFor="branch-work">Work item identifier</label>
          <input id="branch-work" name="workItemId" required
            minLength={5} maxLength={120} type="text"
            defaultValue={query.workItemId ?? ""} />
          <label htmlFor="branch-cap">Audit event source cap</label>
          <select id="branch-cap" name="limit" defaultValue={query.limit ?? "500"}>
            <option value="100">100</option>
            <option value="250">250</option>
            <option value="500">500</option>
            <option value="1000">1,000</option>
            <option value="2000">2,000</option>
          </select>
          <label htmlFor="branch-rationale">Display recorded rationale</label>
          <select id="branch-rationale" name="includeRationale"
            defaultValue={query.includeRationale ?? "false"}>
            <option value="false">Hide human rationale</option>
            <option value="true">Include rationale</option>
          </select>
          <button type="submit" className="secondary-button">Inspect stored review graph</button>
          <Link href={base}>Reset</Link>
        </form>
        {error ? <p className="auth-error" role="alert">{error}</p> : null}
        {report ? (
          <section aria-label="Stored audit branch graph">
            <h2>{report.workTitle}</h2>
            <p>Work revision {report.workRevision}. Source query at {report.generatedAt}.</p>
            <div className="panel">
              <div><p className="panel-label">Reviewed diagnostics</p>
                <p className="panel-value">{report.totals.cases}</p></div>
              <div><p className="panel-label">Decoded audit events</p>
                <p className="panel-value">{report.totals.nodes}</p></div>
              <div><p className="panel-label">Competing branches</p>
                <p className="panel-value">{report.totals.forks}</p></div>
              <div><p className="panel-label">Audit inconsistencies</p>
                <p className="panel-value">{report.totals.errors}</p></div>
            </div>
            <p>{report.sourceRows} stored audit rows inspected;
              {" "}{report.malformedRows} had unreadable triage metadata.</p>
            {report.sourceTruncated ? (
              <p className="permission-warning">
                Source history exceeded the configured cap. Missing predecessors
                and graph coverage are inconclusive.
              </p>
            ) : null}
            <p className="action-link">
              <a href={`${api}?${downloadParams.toString()}`}>
                Download recorded event graph (CSV)
              </a>
            </p>
            <section aria-label="Human audit branch followups">
              <h3>Prioritized source investigations</h3>
              {(() => {
                const plan = planBranchActions(report);
                const params = new URLSearchParams(downloadParams);
                params.set("format", "actions-csv");
                return (
                  <>
                    <p>{plan.total} proposed human follow-ups;
                      {" "}{plan.priorities.P0} urgent P0,
                      {" "}{plan.priorities.P1} P1,
                      {" "}{plan.uniqueAffectedCases} distinct affected cases.</p>
                    <p className="action-link">
                      <a href={`${api}?${params.toString()}`}>
                        Download source investigation handoff (CSV)
                      </a>
                    </p>
                    <div className="remediation-list">
                      {plan.actions.slice(0, 25).map(item => (
                        <article key={item.id} className="remediation-card">
                          <h4>{item.priority}: {item.type.replaceAll("_", " ")}</h4>
                          <p>{item.explanation}</p>
                          <p>Related events: {item.eventIds.join(", ") || "Not determined"}.</p>
                          <p>Next step: {item.nextStep}</p>
                          <p>Requires source access: {item.sourceAccessRequired ? "Yes" : "No"}.
                            {" "}Requires human decision: {item.humanDecisionRequired ? "Yes" : "No"}.</p>
                        </article>
                      ))}
                    </div>
                    {plan.omitted > 0 ? <p>{plan.omitted} follow-ups excluded
                      by the response cap; totals include them.</p> : null}
                  </>
                );
              })()}
            </section>
            <section aria-label="Review graph diagnostic cases">
              <h3>Decision graph by diagnostic case</h3>
              {report.cases.length ? (
                <div className="remediation-list">
                  {report.cases.map(item => (
                    <article className="remediation-card" key={item.caseKey}>
                      <div className="remediation-heading">
                        <h4>{item.code}</h4>
                        <span className="role-badge">
                          {item.forks ? "Concurrent branches found" :
                            item.hasUnknownHistory ? "Coverage uncertain" : "No fork detected"}
                        </span>
                      </div>
                      <p>Resource: <code>{item.resourceId}</code></p>
                      <p>{item.events} review events; {item.roots} recorded roots;
                        {" "}{item.terminals} terminal events; {item.forks} competing predecessors.</p>
                      <p>Maximum observed depth: {item.maxDepth ?? "unknown"}.
                        {" "}Latest recorded decision: {item.latestDecision}.</p>
                      <p>Cycle detected: {item.hasCycle ? "Yes" : "No"}.</p>
                      <ul>
                        {report.nodes.filter(node => node.caseKey === item.caseKey)
                          .slice(0, 50).map(node => (
                            <li key={node.id}>
                              <p><strong>{node.decision}</strong> (revision {node.revision})
                                {" "}at {node.occurredAt}</p>
                              <p>Event: <code>{node.id}</code></p>
                              <p>Predecessor: <code>{node.previousEventId ?? "Recorded root"}</code></p>
                              <p>Successors:
                                {" "}{node.successorIds.length ? node.successorIds.join(", ") : "None recorded"}</p>
                              {node.rationale !== null ? <p>Rationale: {node.rationale}</p> : null}
                              <p className="action-link">
                                <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-lineage?${new URLSearchParams({
                                  eventId: node.id,
                                }).toString()}`}>
                                  Traverse this event's source predecessor chain
                                </Link>
                              </p>
                            </li>
                          ))}
                      </ul>
                    </article>
                  ))}
                </div>
              ) : <p>No decoded human integrity review events found for this work.</p>}
            </section>
            {report.issues.length ? (
              <section aria-label="Audit graph inconsistencies">
                <h3>Observed source anomalies</h3>
                <ul>{report.issues.slice(0, 100).map((issue, index) => (
                  <li key={`${issue.code}-${issue.eventId}-${index}`}>
                    <strong>{issue.severity}: {issue.code.replaceAll("_", " ")}</strong>
                    <p>{issue.message}</p>
                    <p>Follow-up: {issue.suggestedAction}</p>
                  </li>
                ))}</ul>
              </section>
            ) : <p>No graph anomalies found within the bounded source rows.</p>}
            <details>
              <summary>Source coverage and interpretation limitations</summary>
              <ul>{report.limitations.map((line, index) =>
                <li key={index}>{line}</li>)}</ul>
            </details>
          </section>
        ) : null}
      </section>
    </main>
  );
}
