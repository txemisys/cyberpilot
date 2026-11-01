import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import {
  loadAuditEventDetail, type AuditEventDetail,
  type AuditEventLink,
} from "../../../../../../../lib/work-integrity-audit-event-detail";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{ eventId?: string }>;
};
function EventCard({ row }: { row: AuditEventLink }) {
  return (
    <article className="remediation-card">
      <div className="remediation-heading">
        <h3>{row.relation}: {row.decision}</h3>
        <span className="role-badge">
          {row.isCurrentWorkRevision === null ? "Work unavailable" :
            row.isCurrentWorkRevision ? "Current work revision" : "Historical review"}
        </span>
      </div>
      <p>Event ID: <code>{row.id}</code></p>
      <p>Occurred: {row.occurredAt}; actor: {row.actorUserId ?? "Not retained"}</p>
      <p>Reviewed work revision: {row.reviewedRevision}</p>
      <p>Diagnostic identity: <code>{row.caseKey}</code></p>
      <p>Predecessor: <code>{row.previousEventId ?? "No predecessor recorded"}</code></p>
      <p>Recorded rationale: {row.rationale}</p>
      {row.reference ? <p>Reference: {row.reference}</p> : null}
    </article>
  );
}
export default async function AuditEventPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const { eventId } = await searchParams;
  const { membership, session } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-event`;
  let detail: AuditEventDetail | null = null;
  let error: string | null = null;
  if (eventId) {
    try {
      detail = await loadAuditEventDetail({
        organizationId: membership.organization.id,
        userId: session.user.id, role: membership.role,
      }, eventId);
    } catch (caught) {
      if (caught instanceof WorkInputError) error = caught.message;
      else {
        console.error("Source audit detail page failed",
          caught instanceof Error ? caught.message : "unknown");
        error = "Unable to inspect the selected audit event.";
      }
    }
  }
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Direct source audit investigation</p>
        <h1 className="dashboard-title">Inspect a stored human-review event</h1>
        <p className="lede">
          Read an authoritative tenant-scoped audit event and investigate
          its predecessor, immediately linked successors, timestamps and
          current work revision.
        </p>
        <p className="permission-warning">
          This investigation is read-only. An internally consistent review
          event records a human decision, not successful remediation or proof
          of security-control effectiveness.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-ledger`}>
            Return to the recorded audit ledger
          </Link>
        </p>
        <form action={base} method="get" className="remediation-actions">
          <label htmlFor="audit-selected-event">Recorded audit event ID</label>
          <input id="audit-selected-event" type="text" name="eventId"
            required minLength={5} maxLength={120}
            defaultValue={eventId ?? ""} placeholder="Stored event identifier" />
          <button type="submit" className="secondary-button">
            Inspect source event
          </button>
          <Link href={base}>Clear</Link>
        </form>
        {error ? <p role="alert" className="auth-error">{error}</p> : null}
        {detail ? (
          <section aria-label="Source audit event detail">
            <h2>{detail.workTitle ?? detail.workItemId ?? "Audit event"}</h2>
            <p>Checked at {detail.generatedAt}. Current work status:
              {" "}{detail.workStatus ?? "Not available"};
              revision {detail.currentWorkRevision ?? "unknown"}.</p>
            <div className="panel">
              <div>
                <p className="panel-label">Linked source events</p>
                <p className="panel-value">{detail.linkedEventCount}</p>
              </div>
              <div>
                <p className="panel-label">Successors found</p>
                <p className="panel-value">{detail.successors.length}</p>
              </div>
              <div>
                <p className="panel-label">Investigation issues</p>
                <p className="panel-value">{detail.problems.length}</p>
              </div>
            </div>
            {detail.successorQueryTruncated ? (
              <p className="permission-warning">
                The successor search exceeded its source cap.
                Not every related event may be included.
              </p>
            ) : null}
            <h3>Selected source event</h3>
            {detail.selected ? <EventCard row={detail.selected} /> :
              <p className="auth-error">Audit metadata could not be decoded.</p>}
            <h3>Direct predecessor</h3>
            {detail.predecessor ? <EventCard row={detail.predecessor} /> :
              <p>No decoded predecessor event was returned.</p>}
            <h3>Direct successor reviews</h3>
            {detail.successors.length ? (
              <div className="remediation-list">
                {detail.successors.map(row => <EventCard key={row.id} row={row} />)}
              </div>
            ) : <p>No direct successor events were returned by the bounded source query.</p>}
            {detail.problems.length ? (
              <section aria-label="Event source investigations">
                <h3>Observations requiring investigation</h3>
                <ul>{detail.problems.map((problem, index) => (
                  <li key={`${problem.code}-${problem.relatedEventId}-${index}`}>
                    <strong>{problem.severity}: {problem.code.replaceAll("_", " ")}</strong>
                    <p>{problem.message}</p>
                    <p>Next action: {problem.nextAction}</p>
                    {problem.relatedEventId ? <p>Related event: {problem.relatedEventId}</p> : null}
                  </li>
                ))}</ul>
              </section>
            ) : <p>No immediate source link anomaly was found in this bounded inspection.</p>}
            {detail.workItemId ? (
              <p className="action-link">
                <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-chain?${new URLSearchParams({
                  workItemId: detail.workItemId,
                }).toString()}`}>
                  Inspect wider work-item review chain
                </Link>
              </p>
            ) : null}
            <details>
              <summary>Direct source investigation limitations</summary>
              <ul>{detail.limitations.map((line, index) =>
                <li key={index}>{line}</li>)}</ul>
            </details>
          </section>
        ) : null}
      </section>
    </main>
  );
}
