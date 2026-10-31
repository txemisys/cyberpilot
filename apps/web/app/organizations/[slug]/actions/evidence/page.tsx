import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import {
  buildFindingEvidenceReview, rankEvidenceReviews, summarizeEvidenceReviews,
} from "../../../../lib/finding-evidence-review";
import {
  loadReviewData, parseReviewListOptions, reviewListUrl,
} from "../../../../lib/finding-review-data";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<Record<string, string | undefined>>;
};

function stateLabel(state: string): string {
  switch (state) {
    case "ready-for-check": return "Needs fresh verification";
    case "needs-observation": return "Needs observed evidence";
    case "in-progress": return "Action in progress";
    case "unaddressed": return "No action recorded";
    case "finding-resolved": return "Finding resolved";
    case "verified": return "Action verified";
    default: return "Review needed";
  }
}

export default async function EvidenceReviewPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const filters = await searchParams;
  const { membership } = await requireOrganizationAccess(slug);
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (typeof value === "string") search.set(key, value);
  }
  const options = parseReviewListOptions(search);
  const page = await loadReviewData(membership.organization.id, options);
  const reviews = rankEvidenceReviews(page.findings.map(buildFindingEvidenceReview));
  const summary = summarizeEvidenceReviews(reviews);
  const currentPage = Math.floor(page.offset / page.limit) + 1;
  const lastPage = Math.max(1, Math.ceil(page.total / page.limit));
  const base = `/organizations/${slug}/actions/evidence`;
  const exportParams = new URLSearchParams();
  if (options.includeResolved) exportParams.set("resolved", "yes");
  if (options.severity) exportParams.set("severity", options.severity);
  if (options.search) exportParams.set("search", options.search);
  const exportHref = `/api/organizations/${slug}/actions/evidence/export?${exportParams}`;

  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Evidence verification</p>
        <h1 className="dashboard-title">Review security evidence</h1>
        <p className="lede">
          Understand which findings have recorded work, which need new observations,
          and which actions actually have verification records.
        </p>
        <div className="workspace-links no-print">
          <p className="action-link">
            <Link href={`/organizations/${slug}/actions`}>Return to security actions</Link>
          </p>
          <p className="action-link">
            <Link href={`/organizations/${slug}/actions/queue`}>Next actions queue</Link>
          </p>
          <p className="action-link">
            <Link href={`/organizations/${slug}`}>Organization workspace</Link>
          </p>
        </div>
        <section aria-label="Evidence review coverage">
          <div className="panel">
            <div>
              <p className="panel-label">Findings on page</p>
              <strong>{summary.total}</strong>
            </div>
            <div>
              <p className="panel-label">Need fresh observations</p>
              <strong>{summary.pendingEvidence}</strong>
            </div>
            <div>
              <p className="panel-label">No action recorded</p>
              <strong>{summary.unaddressed}</strong>
            </div>
            <div>
              <p className="panel-label">Verified action records</p>
              <strong>{summary.verified}</strong>
            </div>
            <div>
              <p className="panel-label">Observed signals</p>
              <strong>{summary.observedSignals}</strong>
            </div>
            <div>
              <p className="panel-label">Declared signals</p>
              <strong>{summary.declaredSignals}</strong>
            </div>
          </div>
          <p className="score-caption">
            These are counts for the selected page, not all findings in the organization.
            Declared steps and observations do not automatically resolve a finding.
          </p>
        </section>

        <form className="remediation-actions" action={base} method="get">
          <label htmlFor="review-search">Search findings</label>
          <input
            name="search"
            id="review-search"
            type="search"
            maxLength={100}
            defaultValue={options.search ?? ""}
            placeholder="Title, rule or description"
          />
          <label htmlFor="review-severity">Severity</label>
          <select
            id="review-severity"
            name="severity"
            defaultValue={options.severity ?? ""}
          >
            <option value="">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
          <label htmlFor="review-resolved">Finding scope</label>
          <select
            name="resolved"
            id="review-resolved"
            defaultValue={options.includeResolved ? "yes" : "no"}
          >
            <option value="no">Open findings only</option>
            <option value="yes">Include other states</option>
          </select>
          <label htmlFor="review-size">Findings per page</label>
          <select name="limit" id="review-size" defaultValue={options.limit}>
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
          </select>
          <button type="submit" className="secondary-button">Apply filters</button>
          <Link href={base}>Clear</Link>
        </form>

        <div className="workspace-links no-print">
          <p className="action-link">
            <a href={exportHref}>Export matching evidence review (CSV)</a>
          </p>
        </div>
        <p className="score-caption">
          {page.total === 0
            ? "No findings match these filters."
            : `Findings ${page.offset + 1}–${page.offset + reviews.length} of ${page.total} matching records.`}
        </p>

        {reviews.length === 0 ? (
          <div className="empty-state">
            <p>There are no findings to review under these filters.</p>
          </div>
        ) : (
          <div className="remediation-list">
            {reviews.map(review => (
              <article className="remediation-card" key={review.findingId}>
                <div className="remediation-heading">
                  <div>
                    <p className="priority-score">
                      {review.severity} · {review.findingStatus}
                    </p>
                    <h2>{review.findingTitle}</h2>
                  </div>
                  <span className="role-badge">{stateLabel(review.status)}</span>
                </div>
                <p>{review.explanation}</p>
                <p>
                  <strong>Next step:</strong> {review.nextAction}
                </p>
                <dl>
                  <dt>Observed evidence</dt>
                  <dd>{review.observedCount}</dd>
                  <dt>Declared evidence</dt>
                  <dd>{review.declaredCount}</dd>
                  <dt>Unknown or errored evidence</dt>
                  <dd>{review.unknownCount + review.errorCount}</dd>
                  <dt>Remediation actions</dt>
                  <dd>{review.actionCount}</dd>
                  <dt>Work acknowledged</dt>
                  <dd>{review.acknowledgedStepCount} / {review.totalStepCount}</dd>
                  <dt>Latest observation</dt>
                  <dd>{review.mostRecentObservationAt?.toISOString() ?? "Not recorded"}</dd>
                </dl>
                <p className="action-link">
                  <Link href={`${base}/${review.findingId}`}>
                    Review evidence and related actions
                  </Link>
                </p>
              </article>
            ))}
          </div>
        )}

        <nav className="workspace-links no-print" aria-label="Evidence review pages">
          {currentPage > 1 ? (
            <p className="action-link">
              <Link href={reviewListUrl(base, options, currentPage - 1)}>
                Previous findings
              </Link>
            </p>
          ) : null}
          <p>Page {currentPage} of {lastPage}</p>
          {currentPage < lastPage ? (
            <p className="action-link">
              <Link href={reviewListUrl(base, options, currentPage + 1)}>
                Next findings
              </Link>
            </p>
          ) : null}
        </nav>
        <p className="score-caption">
          Evidence is matched by exact control or rule identifier. An absence of matched
          evidence is not evidence that a control is absent. This view never scans
          providers or recalculates CyberScore.
        </p>
      </section>
    </main>
  );
}
