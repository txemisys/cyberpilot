import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import {
  loadAuditLineage, type LineageReport,
} from "../../../../../../../lib/work-integrity-audit-lineage";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{
    eventId?: string; maxDepth?: string; includeRationale?: string;
  }>;
};
export default async function AuditLineagePage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { session, membership } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-lineage`;
  const api = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-lineage`;
  let report: LineageReport | null = null;
  let error: string | null = null;
  if (query.eventId) {
    try {
      report = await loadAuditLineage({
        organizationId: membership.organization.id,
        userId: session.user.id, role: membership.role,
      }, query);
    } catch (caught) {
      if (caught instanceof WorkInputError) error = caught.message;
      else {
        console.error("Audit lineage page failed",
          caught instanceof Error ? caught.message : "unknown");
        error = "Unable to reconstruct this audit chain.";
      }
    }
  }
  const csv = new URLSearchParams();
  if (query.eventId) csv.set("eventId", query.eventId);
  if (query.maxDepth) csv.set("maxDepth", query.maxDepth);
  if (query.includeRationale) csv.set("includeRationale", query.includeRationale);
  csv.set("format", "csv");
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Authoritative review event lineage</p>
        <h1 className="dashboard-title">Follow recorded audit predecessors</h1>
        <p className="lede">
          Traverse the real, tenant-scoped audit-event predecessor chain
          from a selected human integrity review. Each link is fetched
          from the stored event source with bounded depth.
        </p>
        <p className="permission-warning">
          This investigation is read-only. Missing or inconsistent links
          require human investigation. Even a chain reaching its recorded root
          does not independently prove audit immutability or effective remediation.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-ledger`}>
            Return to recorded integrity review ledger
          </Link>
        </p>
        <form method="get" action={base} className="remediation-actions">
          <label htmlFor="lineage-event">Recorded audit event identifier</label>
          <input id="lineage-event" name="eventId" type="text" required
            minLength={5} maxLength={120} defaultValue={query.eventId ?? ""}
            placeholder="An existing audit review event" />
          <label htmlFor="lineage-depth">Maximum source predecessor depth</label>
          <select id="lineage-depth" name="maxDepth" defaultValue={query.maxDepth ?? "100"}>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="250">250</option>
            <option value="500">500</option>
          </select>
          <label htmlFor="lineage-rationale">Recorded rationale in report</label>
          <select id="lineage-rationale" name="includeRationale"
            defaultValue={query.includeRationale ?? "false"}>
            <option value="false">Hide rationale</option>
            <option value="true">Include rationale</option>
          </select>
          <button type="submit" className="secondary-button">Traverse source chain</button>
          <Link href={base}>Reset</Link>
        </form>
        {error ? <p role="alert" className="auth-error">{error}</p> : null}
        {report ? (
          <section aria-label="Audited source chain result">
            <h2>{report.workTitle ?? report.workItemId}</h2>
            <p>Source event: <code>{report.requestedEventId}</code></p>
            <p>Generated at {report.generatedAt}.</p>
            <div className="panel">
              <div><p className="panel-label">Stored events inspected</p>
                <p className="panel-value">{report.inspectedEvents}</p></div>
              <div><p className="panel-label">Source link observations</p>
                <p className="panel-value">{report.issues.length}</p></div>
              <div><p className="panel-label">Traversal terminal</p>
                <p className="panel-value">{report.terminal}</p></div>
            </div>
            <p>Selected decision: {report.newestRecordedDecision}.
              {" "}Reviewed revision {report.latestReviewedRevision};
              current work revision {report.currentRevision ?? "unavailable"}.</p>
            <p className={report.sourceChainComplete ? "score-caption" : "permission-warning"}>
              {report.sourceChainComplete ?
                "The selected predecessor links reached their recorded root without errors or unknowns."
                : "The selected predecessor walk is incomplete or requires investigation."}
            </p>
            <p className="action-link">
              <a href={`${api}?${csv.toString()}`}>Download source lineage (CSV)</a>
            </p>
            <section aria-label="Stored review predecessor sequence">
              <h3>Review events, newest to oldest</h3>
              <div className="remediation-list">
                {report.nodes.map(node => (
                  <article className="remediation-card" key={node.eventId}>
                    <div className="remediation-heading">
                      <h3>Depth {node.depth}: {node.decision}</h3>
                      <span className="role-badge">Revision {node.reviewedRevision}</span>
                    </div>
                    <p>Event: <code>{node.eventId}</code></p>
                    <p>Occurred: {node.occurredAt}</p>
                    <p>Actor: {node.actorUserId ?? "Not retained"}</p>
                    <p>Diagnostic: {node.code}; resource: {node.resourceId}</p>
                    <p>Predecessor: <code>{node.previousEventId ?? "Recorded root"}</code></p>
                    {node.rationale !== null ? <p>Rationale: {node.rationale}</p> : null}
                    {node.reference ? <p>Source reference: {node.reference}</p> : null}
                    <p className="action-link">
                      <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-event?${new URLSearchParams({
                        eventId: node.eventId,
                      }).toString()}`}>
                        Inspect direct source-event relationships
                      </Link>
                    </p>
                  </article>
                ))}
              </div>
            </section>
            {report.issues.length ? (
              <section aria-label="Recorded source lineage anomalies">
                <h3>Source lineage issues</h3>
                <ul>{report.issues.map((issue, index) => (
                  <li key={`${issue.kind}-${issue.eventId}-${index}`}>
                    <strong>{issue.severity}: {issue.kind.replaceAll("_", " ")}</strong>
                    <p>{issue.message}</p>
                    <p>Recommended action: {issue.nextAction}</p>
                    {issue.referencedEventId ?
                      <p>Referenced event: <code>{issue.referencedEventId}</code></p> : null}
                  </li>
                ))}</ul>
              </section>
            ) : <p>No issues found within this bounded predecessor walk.</p>}
            <details>
              <summary>Source limitations</summary>
              <ul>{report.limitations.map((line, index) =>
                <li key={index}>{line}</li>)}</ul>
            </details>
          </section>
        ) : null}
      </section>
    </main>
  );
}
