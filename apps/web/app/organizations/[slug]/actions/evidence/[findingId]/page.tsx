import Link from "next/link";
import { notFound } from "next/navigation";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { loadSingleFindingReview } from "../../../../../../lib/finding-review-data";
import { buildFindingEvidenceReview } from "../../../../../../lib/finding-evidence-review";

type Props = { params: Promise<{ slug: string; findingId: string }> };

function formatDate(value: Date | null): string {
  return value?.toISOString() ?? "Not recorded";
}

export default async function FindingEvidenceDetailPage({ params }: Props) {
  const { slug, findingId } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const finding = await loadSingleFindingReview(membership.organization.id, findingId);
  if (!finding) notFound();
  const review = buildFindingEvidenceReview(finding);
  const base = `/organizations/${slug}`;

  const sources = {
    OBSERVED: finding.evidence.filter(item => item.source === "OBSERVED"),
    DECLARED: finding.evidence.filter(item => item.source === "DECLARED"),
    UNKNOWN: finding.evidence.filter(item => item.source === "UNKNOWN"),
    ERROR: finding.evidence.filter(item => item.source === "ERROR"),
  };

  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Finding evidence</p>
        <h1 className="dashboard-title">{finding.title}</h1>
        <p className="lede">
          {membership.organization.name} · {finding.severity} · {finding.status}
        </p>
        <div className="workspace-links no-print">
          <p className="action-link">
            <Link href={base + "/actions/evidence"}>All evidence reviews</Link>
          </p>
          <p className="action-link">
            <Link href={base + "/actions"}>Security actions</Link>
          </p>
          <p className="action-link">
            <Link href={base}>Workspace</Link>
          </p>
        </div>

        <section className="remediation-section">
          <h2>What was found</h2>
          <p>{finding.description}</p>
          <dl>
            <dt>First observed finding</dt>
            <dd>{formatDate(finding.firstSeenAt)}</dd>
            <dt>Most recent finding observation</dt>
            <dd>{formatDate(finding.lastSeenAt)}</dd>
            <dt>Finding resolution recorded</dt>
            <dd>{formatDate(finding.resolvedAt)}</dd>
            <dt>Current finding status</dt>
            <dd>{finding.status}</dd>
          </dl>
          <p className="score-caption">
            These timestamps describe the stored finding lifecycle. They do not
            independently certify the configuration or operation of a security control.
          </p>
        </section>

        <section className="remediation-section">
          <h2>Evidence assessment</h2>
          <div className="panel">
            <div>
              <p className="panel-label">Observed signals</p>
              <strong>{review.observedCount}</strong>
            </div>
            <div>
              <p className="panel-label">Declared signals</p>
              <strong>{review.declaredCount}</strong>
            </div>
            <div>
              <p className="panel-label">Unknown signals</p>
              <strong>{review.unknownCount}</strong>
            </div>
            <div>
              <p className="panel-label">Error signals</p>
              <strong>{review.errorCount}</strong>
            </div>
            <div>
              <p className="panel-label">Verified action records</p>
              <strong>{review.verifiedActionCount}</strong>
            </div>
          </div>
          <h3>What these records mean</h3>
          <p>{review.explanation}</p>
          <h3>Recommended next action</h3>
          <p>{review.nextAction}</p>
          <p>
            <strong>Most recent matched observation:</strong>{" "}
            {formatDate(review.mostRecentObservationAt)}
          </p>
          <p>
            <strong>Most recent action verification:</strong>{" "}
            {formatDate(review.verificationAt)}
          </p>
        </section>

        <section className="remediation-section">
          <h2>Linked evidence by provenance</h2>
          {finding.evidence.length === 0 ? (
            <div className="empty-state">
              <p>No exact control-identifier evidence was matched to this finding.</p>
              <p>
                This is a matching limitation; it is not proof that no evidence exists.
              </p>
            </div>
          ) : (
            <>
              {(
                ["OBSERVED", "DECLARED", "UNKNOWN", "ERROR"] as const
              ).map(source => (
                <section key={source} aria-label={source + " evidence"}>
                  <h3>{source} ({sources[source].length})</h3>
                  {sources[source].length === 0 ? (
                    <p>No matching records in this category.</p>
                  ) : (
                    <ol className="remediation-list">
                      {sources[source].map(item => (
                        <li className="remediation-card" key={item.id}>
                          <p><strong>{item.category}</strong></p>
                          <p>{item.summary}</p>
                          <p>
                            <strong>Observation:</strong>{" "}
                            {formatDate(item.lastObservedAt)}
                          </p>
                          <p>
                            <strong>Record created:</strong>{" "}
                            {formatDate(item.capturedAt)}
                          </p>
                          {source === "DECLARED" ? (
                            <p className="permission-warning">
                              A declaration is not independent verification.
                            </p>
                          ) : null}
                          {source === "ERROR" || source === "UNKNOWN" ? (
                            <p className="permission-warning">
                              Evidence is unavailable or inconclusive.
                            </p>
                          ) : null}
                        </li>
                      ))}
                    </ol>
                  )}
                </section>
              ))}
            </>
          )}
        </section>

        <section className="remediation-section">
          <h2>Remediation and verification history</h2>
          {finding.actions.length === 0 ? (
            <p>No remediation was recorded against this finding.</p>
          ) : (
            <ol className="remediation-list">
              {finding.actions.map(action => {
                const complete = action.steps.filter(
                  (_step, index) => action.acknowledgedSteps.has(index),
                ).length;
                const verified = action.status === "VERIFIED" &&
                  action.verifiedAt !== null;
                return (
                  <li className="remediation-card" key={action.id}>
                    <h3>{action.title}</h3>
                    <p>{action.mode} · {action.status}</p>
                    <p>
                      <strong>Acknowledged guided steps:</strong>{" "}
                      {complete} / {action.steps.length}
                    </p>
                    <p>
                      <strong>Approved:</strong> {formatDate(action.approvedAt)}
                    </p>
                    <p>
                      <strong>Work completed:</strong> {formatDate(action.completedAt)}
                    </p>
                    <p>
                      <strong>Verified:</strong>{" "}
                      {verified ? formatDate(action.verifiedAt) : "Not verified"}
                    </p>
                    <h4>Recorded verification criteria</h4>
                    {action.verification.length ? (
                      <ol>
                        {action.verification.map((criterion, index) => (
                          <li key={index}>{criterion}</li>
                        ))}
                      </ol>
                    ) : (
                      <p>No checklist is recorded.</p>
                    )}
                    <p className="action-link">
                      <Link href={base + "/actions/" + action.id}>
                        Open remediation workflow
                      </Link>
                    </p>
                  </li>
                );
              })}
            </ol>
          )}
        </section>

        <section className="remediation-section">
          <h2>Before communicating closure</h2>
          <p>
            Confirm the finding status, review the verification checklist,
            and obtain evidence from an authorized source where available.
            Acknowledgments, execution success, and declarations are not
            interchangeable with a verified security improvement.
          </p>
          <p className="action-link no-print">
            <Link href={base + "/actions/queue"}>
              Return to prioritized remediation work
            </Link>
          </p>
        </section>
        <p className="score-caption">
          All information comes from stored, tenant-scoped records.
          This page does not fetch LIVE provider data, execute fixes,
          modify stored evidence or recalculate CyberScore.
        </p>
      </section>
    </main>
  );
}
