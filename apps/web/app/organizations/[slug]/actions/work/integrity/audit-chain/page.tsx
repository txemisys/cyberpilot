import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import {
  loadAuditChain, type AuditChainReport,
} from "../../../../../../../lib/work-integrity-audit-chain";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{
    workItemId?: string; limit?: string; includeEvents?: string;
  }>;
};
function problemTitle(code: string): string {
  return code.toLowerCase().replaceAll("_", " ");
}
function renderCase(report: AuditChainReport, record: AuditChainReport["cases"][number]) {
  const issues = report.problems.filter(problem => problem.caseKey === record.caseKey);
  return (
    <article className="remediation-card" key={record.caseKey}>
      <div className="remediation-heading">
        <div>
          <h3>{record.code}</h3>
          <p>{record.workItemId} · {record.resourceId}</p>
        </div>
        <span className="role-badge">
          {record.errors ? "Requires investigation" :
            record.unknowns ? "Coverage uncertain" : "No chain errors detected"}
        </span>
      </div>
      <div className="panel">
        <div><p className="panel-label">Recorded reviews</p>
          <p className="panel-value">{record.eventCount}</p></div>
        <div><p className="panel-label">Roots</p>
          <p className="panel-value">{record.rootCount}</p></div>
        <div><p className="panel-label">Heads</p>
          <p className="panel-value">{record.headCount}</p></div>
        <div><p className="panel-label">Latest chain length</p>
          <p className="panel-value">{record.chainLength}</p></div>
      </div>
      <p>Latest recorded decision: {record.latestDecision ?? "None"}.
        {" "}Latest reviewed revision: {record.latestRevision ?? "Not recorded"}.</p>
      <p>Current work-item revision reviewed:
        {" "}{record.isCurrentRevision ? "Yes, according to recorded metadata" :
          "No current review established"}.</p>
      {!record.completeHistory ? (
        <p className="permission-warning">
          The available event history is incomplete, inconsistent or bounded;
          this is not a verified complete review chain.
        </p>
      ) : (
        <p className="score-caption">
          The returned audit links form one continuous chain. This is not
          proof that the underlying control or remediation is effective.
        </p>
      )}
      {record.eventIds.length ? (
        <details>
          <summary>Event identifiers ({record.eventIds.length})</summary>
          <ol>{record.eventIds.map(id => <li key={id}><code>{id}</code></li>)}</ol>
        </details>
      ) : null}
      {issues.length ? (
        <section aria-label="Case audit-chain investigations">
          <h4>Recorded chain anomalies ({issues.length})</h4>
          <ul>
            {issues.map((issue, index) => (
              <li key={`${issue.code}-${issue.eventId}-${index}`}>
                <strong>{issue.severity}: {problemTitle(issue.code)}</strong>
                <p>{issue.message}</p>
                <p>Recommended action: {issue.recommendedAction}</p>
                {issue.eventId ? <p>Audit event: <code>{issue.eventId}</code></p> : null}
                {issue.predecessorId ?
                  <p>Predecessor: <code>{issue.predecessorId}</code></p> : null}
              </li>
            ))}
          </ul>
        </section>
      ) : <p>No anomalies identified for this case in the available audit window.</p>}
    </article>
  );
}
export default async function AuditChainPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { session, membership } = await requireOrganizationAccess(slug);
  const organization = membership.organization.id;
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-chain`;
  const api = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-chain`;
  let report: AuditChainReport | null = null;
  let error: string | null = null;
  if (query.workItemId) {
    try {
      report = await loadAuditChain({
        organizationId: organization, userId: session.user.id, role: membership.role,
      }, query);
    } catch (caught) {
      if (caught instanceof WorkInputError) error = caught.message;
      else {
        console.error("Audit chain page failed",
          caught instanceof Error ? caught.message : "unknown");
        error = "Unable to inspect the audit chain.";
      }
    }
  }
  const downloadParams = new URLSearchParams();
  if (query.workItemId) downloadParams.set("workItemId", query.workItemId);
  if (query.limit) downloadParams.set("limit", query.limit);
  if (query.includeEvents) downloadParams.set("includeEvents", query.includeEvents);
  const download = (format: "json" | "csv") => {
    const params = new URLSearchParams(downloadParams);
    params.set("format", format);
    return `${api}?${params.toString()}`;
  };
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Audit traceability</p>
        <h1 className="dashboard-title">Inspect a work item's audit chain</h1>
        <p className="lede">
          Read directly from your organization's recorded triage decisions
          and inspect event predecessor links, review revisions, historical
          coverage and concurrency anomalies.
        </p>
        <p className="permission-warning">
          This view is read-only. It never changes an approval, a work item,
          a finding or a control. Even an internally consistent audit chain
          is not a security verification or a certification.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/analyst-queue`}>
            Return to the operational integrity analyst queue
          </Link>
        </p>
        <form action={base} method="get" className="remediation-actions">
          <label htmlFor="audit-work">Work-item identifier</label>
          <input id="audit-work" type="text" name="workItemId"
            required minLength={5} maxLength={100}
            defaultValue={query.workItemId ?? ""}
            placeholder="Enter a work-item ID" />
          <label htmlFor="audit-limit">Maximum audit events</label>
          <select id="audit-limit" name="limit" defaultValue={query.limit ?? "500"}>
            <option value="100">100</option>
            <option value="500">500</option>
            <option value="1000">1,000</option>
            <option value="2000">2,000</option>
          </select>
          <label htmlFor="audit-ids">Show event identities</label>
          <select id="audit-ids" name="includeEvents"
            defaultValue={query.includeEvents ?? "false"}>
            <option value="false">Hide IDs</option>
            <option value="true">Show IDs</option>
          </select>
          <button type="submit" className="secondary-button">Inspect stored history</button>
          <Link href={base}>Clear</Link>
        </form>
        {error ? <p className="auth-error" role="alert">{error}</p> : null}
        {report ? (
          <section aria-label="Authenticated audit chain report">
            <h2>{report.workTitle}</h2>
            <p>Work revision {report.currentRevision} · read at {report.generatedAt}</p>
            <div className="panel" aria-label="Audit chain summary">
              <div><p className="panel-label">Diagnostic cases</p>
                <p className="panel-value">{report.totals.cases}</p></div>
              <div><p className="panel-label">Chain errors</p>
                <p className="panel-value">{report.totals.errors}</p></div>
              <div><p className="panel-label">Warnings</p>
                <p className="panel-value">{report.totals.warnings}</p></div>
              <div><p className="panel-label">Unknown links</p>
                <p className="panel-value">{report.totals.unknowns}</p></div>
            </div>
            <p>{report.recordsRead} audit rows inspected.
              {" "}{report.malformedRecords} rows lacked interpretable review metadata.</p>
            <p className={report.historyComplete ? "score-caption" : "permission-warning"}>
              {report.historyComplete
                ? "The selected stored event chains are internally complete under these checks."
                : "Complete audit-chain coverage cannot be established from this selection."}
            </p>
            {report.bounded ? (
              <p className="permission-warning">
                More source audit events exist than the configured limit.
                Increase the limit before judging missing predecessor links.
              </p>
            ) : null}
            <div className="remediation-actions">
              <a href={download("json")}>Download authenticated report (JSON)</a>
              <a href={download("csv")}>Download case summary (CSV)</a>
            </div>
            <section aria-label="Audit chain cases">
              <h2>Review chains by diagnostic case</h2>
              {report.cases.length ? (
                <div className="remediation-list">
                  {report.cases.map(row => renderCase(report, row))}
                </div>
              ) : <p>No recorded triage events were found for this work item.</p>}
            </section>
            {report.problems.filter(problem => problem.caseKey === null).length ? (
              <section aria-label="Audit source coverage warnings">
                <h2>Audit source limitations</h2>
                <ul>{report.problems.filter(problem => problem.caseKey === null)
                  .map((issue, index) => (
                    <li key={index}>
                      <strong>{issue.code}</strong>: {issue.message}
                      <p>{issue.recommendedAction}</p>
                    </li>
                  ))}</ul>
              </section>
            ) : null}
            <details>
              <summary>Interpretation and source limitations</summary>
              <ul>{report.limitations.map((line, index) =>
                <li key={index}>{line}</li>)}</ul>
            </details>
          </section>
        ) : !error ? (
          <p>Select a work item to inspect the actual organization-scoped audit history.</p>
        ) : null}
      </section>
    </main>
  );
}
