import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { canManageWork } from "../../../../../../../lib/remediation-work-input";
import { listIntegrityTriage } from "../../../../../../../lib/work-integrity-triage";
import TriageEditor from "./triage-editor";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{ page?: string; limit?: string; workItemId?: string; code?: string }>;
};
export default async function IntegrityTriagePage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { membership, session } = await requireOrganizationAccess(slug);
  const scope = {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/triage`;
  const response = await listIntegrityTriage(scope, query);
  const previous = new URLSearchParams({
    ...query, page: String(Math.max(1, response.page - 1)),
  });
  const next = new URLSearchParams({
    ...query, page: String(response.page + 1),
  });
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Operational integrity</p>
        <h1 className="dashboard-title">Diagnostic review decisions</h1>
        <p className="lede">
          Record a human investigation decision with immutable attribution,
          rationale and revision. This workflow does not close or verify any finding.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${slug}/actions/work/integrity`}>
            Return to integrity checks
          </Link>
        </p>
        <p className="permission-warning">{response.disclaimer}</p>
        <form action={base} method="get" className="remediation-actions">
          <label htmlFor="triage-work-id">Work item ID (optional)</label>
          <input id="triage-work-id" name="workItemId" defaultValue={query.workItemId ?? ""}
            maxLength={100} />
          <label htmlFor="triage-limit">Events per page</label>
          <select id="triage-limit" name="limit" defaultValue={query.limit ?? "25"}>
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
          <button className="secondary-button" type="submit">Filter history</button>
        </form>
        {canManageWork(membership.role) ? (
          <TriageEditor slug={slug} />
        ) : (
          <p>Audit access is read-only. Only owners and administrators can record decisions.</p>
        )}
        <div className="panel">
          <div>
            <p className="panel-label">Events matching query</p>
            <p className="panel-value">{response.total}</p>
          </div>
          <div>
            <p className="panel-label">Page</p>
            <p className="panel-value">{response.page} / {response.pages}</p>
          </div>
          <div>
            <p className="panel-label">Events returned</p>
            <p className="panel-value">{response.events.length}</p>
          </div>
        </div>
        {response.events.length === 0 ? (
          <p>No audit decisions are stored for this page and filter.</p>
        ) : (
          <ol>
            {response.events.map(event => (
              <li key={event.id}>
                <article className="remediation-card">
                  <h2>{event.decision} · {event.code}</h2>
                  <p>Work item: {event.workItemId} · Linked record: {event.resourceId}</p>
                  <p>Revision reviewed: {event.revision}</p>
                  <p>Review recorded: {event.occurredAt.toISOString()}</p>
                  <p>Reviewer user ID: {event.actorUserId ?? "Unavailable"}</p>
                  <p>Rationale: {event.rationale}</p>
                  {event.reference ? <p>External reference: {event.reference}</p> : null}
                  <p className="score-caption">Audit event: {event.id}</p>
                  {event.previousEventId ? (
                    <p className="score-caption">Previous decision: {event.previousEventId}</p>
                  ) : null}
                </article>
              </li>
            ))}
          </ol>
        )}
        <nav aria-label="Diagnostic audit pagination" className="workspace-links">
          {response.page > 1 ? (
            <Link href={`${base}?${previous.toString()}`}>Previous page</Link>
          ) : null}
          {response.page < response.pages ? (
            <Link href={`${base}?${next.toString()}`}>Next page</Link>
          ) : null}
        </nav>
        <details>
          <summary>Coverage and workflow limits</summary>
          <p>{response.coverage}</p>
          <p>Decisions are append-only audit events. An acknowledged or dismissed
            diagnostic is not a completed remediation, a verified control,
            or proof that linked evidence is sufficient.</p>
          <p>Changes to the work item revision make prior review decisions stale
            and require a fresh investigation.</p>
        </details>
      </section>
    </main>
  );
}
