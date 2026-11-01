import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { loadAuditDigest, type AuditDigest } from "../../../../../../../lib/work-integrity-audit-digest";
import { analyzeAuditDigestTrends } from "../../../../../../../lib/work-integrity-audit-digest-trends";
import { planAuditReviewWorkload } from "../../../../../../../lib/work-integrity-audit-digest-review";
import { WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{
    from?: string; to?: string; limit?: string;
    actorUserId?: string; workItemId?: string;
  }>;
};
export default async function AuditDigestPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { session, membership } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-digest`;
  const api = `/api/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-digest`;
  let digest: AuditDigest | null = null;
  let error: string | null = null;
  try {
    digest = await loadAuditDigest({
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    }, query);
  } catch (caught) {
    if (caught instanceof WorkInputError) error = caught.message;
    else {
      console.error("Audit digest view failed", caught instanceof Error ? caught.message : "unknown");
      error = "Unable to load recorded audit activity.";
    }
  }
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query))
    if (value !== undefined) search.set(key, value);
  search.set("format", "csv");
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Recorded review activity</p>
        <h1 className="dashboard-title">Human decision audit digest</h1>
        <p className="lede">
          Aggregate actual tenant-scoped integrity review events by day,
          actor and diagnostic case within a bounded time window.
        </p>
        <p className="permission-warning">
          These figures are recorded decisions, not the number of completed
          remediations or verified security controls. Source history caps
          and missing user accounts are identified rather than guessed.
        </p>
        <p className="action-link">
          <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-ledger`}>
            Browse individual stored audit events
          </Link>
        </p>
        <form action={base} method="get" className="remediation-actions">
          <label htmlFor="digest-from">Window begins (ISO timestamp)</label>
          <input id="digest-from" name="from" type="text"
            defaultValue={query.from ?? ""} placeholder="2026-10-01T00:00:00Z" />
          <label htmlFor="digest-to">Window ends (ISO timestamp)</label>
          <input id="digest-to" name="to" type="text"
            defaultValue={query.to ?? ""} placeholder="Defaults to now" />
          <label htmlFor="digest-work">Work item (optional)</label>
          <input id="digest-work" name="workItemId" type="text"
            defaultValue={query.workItemId ?? ""} placeholder="All work" />
          <label htmlFor="digest-actor">Actor (optional)</label>
          <input id="digest-actor" name="actorUserId" type="text"
            defaultValue={query.actorUserId ?? ""} placeholder="All recorded actors" />
          <label htmlFor="digest-limit">Maximum source events</label>
          <select id="digest-limit" name="limit" defaultValue={query.limit ?? "2000"}>
            <option value="100">100</option>
            <option value="500">500</option>
            <option value="2000">2,000</option>
            <option value="5000">5,000</option>
          </select>
          <button type="submit" className="secondary-button">Inspect recorded activity</button>
          <Link href={base}>Reset</Link>
        </form>
        {error ? <p role="alert" className="auth-error">{error}</p> : null}
        {digest ? (
          <section aria-label="Stored human review digest">
            <p>Source interval {digest.from} through {digest.to}.</p>
            <p>{digest.rawRecordsRead} stored audit rows read.
              {" "}{digest.malformed} lacked interpretable triage metadata.</p>
            {digest.historyTruncated ? (
              <p className="permission-warning">
                The source event cap was reached. All counts are lower bounds.
              </p>
            ) : null}
            <div className="panel">
              <div><p className="panel-label">Recorded decisions</p>
                <p className="panel-value">{digest.recorded}</p></div>
              <div><p className="panel-label">Work items with reviews</p>
                <p className="panel-value">{digest.uniqueWorkItems}</p></div>
              <div><p className="panel-label">Diagnostic cases reviewed</p>
                <p className="panel-value">{digest.uniqueCases}</p></div>
              <div><p className="panel-label">Actor references</p>
                <p className="panel-value">{digest.reviewedByActors}</p></div>
            </div>
            <p>Investigations: {digest.decisions.INVESTIGATE};
              {" "}acknowledgements: {digest.decisions.ACKNOWLEDGE};
              {" "}dismissals: {digest.decisions.DISMISS};
              {" "}reopenings: {digest.decisions.REOPEN}.</p>
            <p className="action-link">
              <a href={`${api}?${search.toString()}`}>
                Download daily recorded review counts (CSV)
              </a>
            </p>
            <section aria-label="Recorded review workload trends">
              <h2>Bounded recorded-review trend</h2>
              {(() => {
                const trends = analyzeAuditDigestTrends(digest);
                const params = new URLSearchParams(search);
                params.set("format", "trends-csv");
                return (
                  <>
                    <p>First half: {trends.prior.recorded} decisions across
                      {" "}{trends.prior.days} days; second half:
                      {" "}{trends.current.recorded} decisions across
                      {" "}{trends.current.days} days.</p>
                    <p>Change in recorded decisions: {trends.recordedDelta}.
                      These counts do not measure remediation success.</p>
                    <p className="action-link">
                      <a href={`${api}?${params.toString()}`}>
                        Download recorded activity trend observations (CSV)
                      </a>
                    </p>
                    {trends.findings.length ? (
                      <ul>{trends.findings.map(issue => (
                        <li key={issue.signal}>
                          <strong>{issue.priority}: {issue.signal.replaceAll("_", " ")}</strong>
                          <p>{issue.explanation}</p>
                          <p>Next step: {issue.nextStep}</p>
                        </li>
                      ))}</ul>
                    ) : <p>Insufficient bounded activity to infer a direction.</p>}
                  </>
                );
              })()}
            </section>
            <section aria-label="Suggested audit investigation workload">
              <h2>Human investigation follow-ups</h2>
              {(() => {
                const workload = planAuditReviewWorkload(digest);
                const params = new URLSearchParams(search);
                params.set("format", "workload-csv");
                return (
                  <>
                    <p>{workload.itemCount} investigation suggestions,
                      {" "}{workload.casesNeedingReview} distinct cases
                      and {workload.sourceQualityItems} source-coverage actions.
                      These recommendations are not persisted assignments.</p>
                    <p className="action-link">
                      <a href={`${api}?${params.toString()}`}>
                        Download proposed audit follow-ups (CSV)
                      </a>
                    </p>
                    {workload.items.length ? (
                      <div className="remediation-list">
                        {workload.items.slice(0, 50).map(item => (
                          <article className="remediation-card" key={item.id}>
                            <div className="remediation-heading">
                              <h3>{item.kind.replaceAll("_", " ")}</h3>
                              <span className="role-badge">{item.priority}</span>
                            </div>
                            {item.workItemId ? <p>Work: {item.workItemId}</p> : null}
                            {item.day ? <p>Source day: {item.day}</p> : null}
                            <p>{item.occurrences} related recorded occurrences.</p>
                            <p>{item.explanation}</p>
                            <p><strong>Next step:</strong> {item.recommendedAction}</p>
                          </article>
                        ))}
                      </div>
                    ) : <p>No follow-ups were identified within the selected bounds.</p>}
                    {workload.omittedItems > 0 ? (
                      <p>{workload.omittedItems} suggestions were omitted
                        by the bounded workload limit.</p>
                    ) : null}
                  </>
                );
              })()}
            </section>
            <section aria-label="Daily review counts">
              <h2>Daily review activity</h2>
              <div className="remediation-list">
                {digest.daily.map(bucket => (
                  <article key={bucket.day} className="remediation-card">
                    <h3>{bucket.day}</h3>
                    <p>{bucket.recorded} decisions, {bucket.uniqueCases} cases,
                      {" "}{bucket.uniqueWorkItems} work items,
                      {" "}{bucket.actors} known actors.</p>
                    <p>{bucket.investigations} investigations,
                      {" "}{bucket.acknowledgements} acknowledgements,
                      {" "}{bucket.dismissals} dismissals,
                      {" "}{bucket.reopenings} reopenings.</p>
                    <p>{bucket.staleReviews} historical revision reviews;
                      {" "}{bucket.unknownActors} decisions without current actor;
                      {" "}{bucket.malformed} malformed source records.</p>
                  </article>
                ))}
              </div>
            </section>
            <section aria-label="Audit activity by reviewer">
              <h2>Recorded actors</h2>
              {digest.actors.length ? (
                <ul>{digest.actors.map((actor, index) => (
                  <li key={actor.actorUserId ?? `missing-${index}`}>
                    <strong>{actor.actorUserId ?? "Actor unavailable"}</strong>:
                    {" "}{actor.recorded} decisions across
                    {" "}{actor.workItems} work items
                  </li>
                ))}</ul>
              ) : <p>No recorded reviewer actors in this bounded window.</p>}
            </section>
            <section aria-label="Most recent reviewed cases">
              <h2>Case review history</h2>
              <div className="remediation-list">
                {digest.cases.slice(0, 100).map(item => (
                  <article key={item.caseKey} className="remediation-card">
                    <h3>{item.code}</h3>
                    <p>Work: {item.workItemId}; resource: {item.resourceId}</p>
                    <p>{item.events} recorded decisions; latest: {item.lastDecision}
                      {" "}at {item.lastAt}.</p>
                    <p>Reviewed revision: {item.latestReviewedRevision};
                      {" "}current work revision: {item.currentWorkRevision ?? "unavailable"}.</p>
                    <p className="action-link">
                      <Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity/audit-chain?${new URLSearchParams({
                        workItemId: item.workItemId,
                      }).toString()}`}>
                        Inspect authoritative linked events
                      </Link>
                    </p>
                  </article>
                ))}
              </div>
              {digest.cases.length > 100 ? (
                <p>Only the first 100 case summaries are shown.</p>
              ) : null}
            </section>
            <details>
              <summary>Limits of review activity interpretation</summary>
              <ul>{digest.limitations.map((line, index) =>
                <li key={index}>{line}</li>)}</ul>
            </details>
          </section>
        ) : null}
      </section>
    </main>
  );
}
