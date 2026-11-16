import { createHash } from "node:crypto";

/**
 * Canonical, read-only reconciliation of Baseline's persisted source,
 * review and action history. Technical traceability is explicitly not
 * customer acceptance or independent control verification.
 */
export type BaselineDossierDraft = {
  id: string;
  organizationId: string;
  revision: number;
  status: string;
  responsesDigest: string;
  submittedAt: string | null;
  updatedAt: string;
};
export type BaselineDossierRevision = {
  id: string;
  organizationId: string;
  draftId: string;
  revision: number;
  eventKind: string;
  responsesDigest: string;
  reportDigest: string | null;
  storedReportValid: boolean;
  reportOrganizationId: string | null;
  actorUserId: string;
  createdAt: string;
};
export type BaselineDossierReview = {
  id: string;
  organizationId: string;
  draftId: string;
  sourceRevision: number;
  reportDigest: string;
  revision: number;
  state: string;
  scope: string;
  issueCount: number;
  blockingIssueCount: number;
  findingsDigest: string;
  reviewerUserId: string | null;
  completedAt: string | null;
  updatedAt: string;
};
export type BaselineDossierReviewEvent = {
  id: string;
  organizationId: string;
  reviewId: string;
  revision: number;
  action: string;
  previousState: string;
  newState: string;
  findingsDigest: string;
  actorUserId: string;
  createdAt: string;
};
export type BaselineDossierAction = {
  id: string;
  organizationId: string;
  questionId: string;
  sourceDraftRevision: number;
  revision: number;
  status: string;
  ownerUserId: string | null;
  evidenceReference: string | null;
  dueAt: string | null;
  completedAt: string | null;
  updatedAt: string;
};
export type BaselineDossierActionEvent = {
  id: string;
  organizationId: string;
  followUpId: string;
  revision: number;
  action: string;
  previousStatus: string;
  nextStatus: string;
  actorUserId: string;
  createdAt: string;
};
export type BaselineDossierInput = {
  organizationId: string;
  generatedAt: string;
  draft: BaselineDossierDraft | null;
  revisions: BaselineDossierRevision[];
  reviews: BaselineDossierReview[];
  reviewEvents: BaselineDossierReviewEvent[];
  actions: BaselineDossierAction[];
  actionEvents: BaselineDossierActionEvent[];
  sourceCounts: {
    drafts: number;
    revisions: number;
    reviews: number;
    reviewEvents: number;
    actions: number;
    actionEvents: number;
  };
  queryCaps: {
    drafts: number;
    revisions: number;
    reviews: number;
    reviewEvents: number;
    actions: number;
    actionEvents: number;
  };
};
export type BaselineDossierGate = {
  id: string;
  state: "PASS" | "BLOCK" | "ADVISORY";
  expected: number;
  observed: number;
  reason: string;
  linkedSourceIds: string[];
};
export type BaselineDossierTimelineEntry = {
  at: string;
  kind: "DRAFT_REVISION" | "TECHNICAL_REVIEW" |
    "REVIEW_EVENT" | "ACTION" | "ACTION_EVENT";
  sourceId: string;
  sourceRevision: number;
  state: string;
  relationship: string;
  organizationId: string;
};
export type BaselineDossierSubmission = {
  revision: number;
  reportDigest: string | null;
  sourceValid: boolean;
  internalReviewId: string | null;
  internalReviewState: string | null;
  reviewEventCount: number;
  blockingIssueCount: number;
  customerApproved: false;
  technicalControlsVerified: false;
};
export type BaselineDossierActionSummary = {
  total: number;
  open: number;
  inProgress: number;
  blocked: number;
  completedReported: number;
  reopened: number;
  unknownStatus: number;
  overdue: number;
  missingOwners: number;
  sourceRevisionWithoutSubmission: number;
  independentRemediationsVerified: 0;
};
export type BaselineDossierReport = {
  schema: "cyberpilot.baseline.development.dossier.v1";
  organizationId: string;
  generatedAt: string;
  verdict: "BLOCKED" | "TECHNICALLY_TRACEABLE" | "REVIEW_REQUIRED";
  latestDraftState: string | null;
  latestDraftRevision: number | null;
  sourceCompleteness: {
    bounded: boolean;
    allTenantScoped: boolean;
    revisionsContiguous: boolean;
    reviewEventsContiguous: boolean;
    actionEventsContiguous: boolean;
    digestReferencesCoherent: boolean;
  };
  gates: BaselineDossierGate[];
  submissions: BaselineDossierSubmission[];
  actions: BaselineDossierActionSummary;
  timeline: BaselineDossierTimelineEntry[];
  sampleCounts: BaselineDossierInput["sourceCounts"];
  limits: string[];
  digest: string;
  customerApprovalRecorded: false;
  independentlyValidatedSecurityControls: 0;
  actualRemediationVerified: false;
  existingCyberScoreModified: false;
};
function assertValidString(s: string): boolean {
  return typeof s === "string" && s.length > 0 &&
    s.length < 256 && !/[\u0000-\u001f\u007f]/.test(s);
}
function isIso(s: string): boolean {
  return typeof s === "string" &&
    Number.isFinite(Date.parse(s)) &&
    new Date(s).toISOString() === s;
}
function isDigest(s: string | null): boolean {
  return typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
}
function unique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object")
    return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.entries(value)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => JSON.stringify(k) + ":" + canonical(v))
    .join(",") + "}";
}
function digest(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}
function contiguous(revisions: readonly number[], last: number): boolean {
  if (!Number.isSafeInteger(last) || last < 1)
    return false;
  if (revisions.length !== last) return false;
  const sorted = [...revisions].sort((a, b) => a - b);
  return sorted.every((r, i) => r === i + 1);
}
function bounded(input: BaselineDossierInput): boolean {
  return Object.entries(input.sourceCounts).every(([k, count]) => {
    const cap = input.queryCaps[k as keyof typeof input.queryCaps];
    return Number.isSafeInteger(count) &&
      count >= 0 && count <= cap;
  });
}
function countMap<T>(items: readonly T[], key: (row: T) => string) {
  const result = new Map<string, T[]>();
  for (const row of items) {
    const id = key(row);
    const previous = result.get(id) ?? [];
    previous.push(row);
    result.set(id, previous);
  }
  return result;
}
function stableTimeline(a: BaselineDossierTimelineEntry,
  b: BaselineDossierTimelineEntry): number {
  return a.at.localeCompare(b.at) ||
    a.kind.localeCompare(b.kind) ||
    a.sourceId.localeCompare(b.sourceId) ||
    a.sourceRevision - b.sourceRevision;
}
function gate(id: string, state: BaselineDossierGate["state"],
  reason: string, expected: number, observed: number,
  sourceIds: string[] = []): BaselineDossierGate {
  return {
    id, state, reason, expected, observed,
    linkedSourceIds: unique(sourceIds).slice(0, 100),
  };
}
export function buildBaselineDevelopmentDossier(
  input: BaselineDossierInput,
): BaselineDossierReport {
  if (!assertValidString(input.organizationId) ||
      !isIso(input.generatedAt))
    throw Error("Invalid dossier scope or timestamp.");
  const gates: BaselineDossierGate[] = [];
  const scope: string[] = [];
  const checkScope = (rows: Array<{
    id: string; organizationId: string;
  }>, collection: string) => {
    for (const row of rows)
      if (row.organizationId !== input.organizationId ||
          !assertValidString(row.id))
        scope.push(collection + ":" + String(row.id).slice(0, 80));
  };
  if (input.draft &&
      input.draft.organizationId !== input.organizationId)
    scope.push("draft:" + input.draft.id);
  checkScope(input.revisions, "revision");
  checkScope(input.reviews, "review");
  checkScope(input.reviewEvents, "review-event");
  checkScope(input.actions, "action");
  checkScope(input.actionEvents, "action-event");
  const allScoped = scope.length === 0;
  gates.push(gate("TENANT_BOUNDARY",
    allScoped ? "PASS" : "BLOCK",
    "All sources must belong to the authenticated organization.",
    0, scope.length, scope));
  const complete = bounded(input);
  gates.push(gate("BOUNDED_SOURCE_COMPLETENESS",
    complete ? "PASS" : "BLOCK",
    "Source count may not exceed the bounded read window.",
    0, complete ? 0 : 1));
  const draft = input.draft;
  gates.push(gate("DRAFT_EXISTS",
    draft ? "PASS" : "BLOCK",
    "An actual PostgreSQL Baseline draft is required.",
    1, draft ? 1 : 0, draft ? [draft.id] : []));
  const revisions = [...input.revisions].sort((a, b) =>
    a.revision - b.revision);
  const uniqueRevisionNumbers = unique(revisions.map(r =>
    String(r.revision)));
  const revisionSequence = draft !== null &&
    input.sourceCounts.revisions === revisions.length &&
    uniqueRevisionNumbers.length === revisions.length &&
    contiguous(revisions.map(r => r.revision), draft.revision);
  gates.push(gate("REVISION_SEQUENCE",
    revisionSequence ? "PASS" : "BLOCK",
    "All revisions must be present and sequential.",
    draft?.revision ?? 0, revisions.length,
    revisions.filter(r => r.revision < 1).map(r => r.id)));
  const latest = revisions.at(-1);
  const stateCoherent = draft !== null && latest !== undefined &&
    (draft.status === "SUBMITTED" && latest.eventKind === "SUBMIT" ||
     draft.status === "DRAFT" &&
     ["SAVE","REOPEN","CREATE"].includes(latest.eventKind)) &&
    draft.responsesDigest === latest.responsesDigest;
  gates.push(gate("LATEST_DRAFT_STATE",
    stateCoherent ? "PASS" : "BLOCK",
    "Current draft digest, state and most recent event must agree.",
    1, stateCoherent ? 1 : 0,
    [draft?.id, latest?.id].filter((x): x is string => Boolean(x))));
  const sourceIds = new Set(revisions.map(r => r.id));
  const revisionIdentity = revisions.every(r =>
    r.draftId === draft?.id &&
    r.organizationId === input.organizationId &&
    isDigest(r.responsesDigest) &&
    isIso(r.createdAt) &&
    assertValidString(r.actorUserId) &&
    ["CREATE","SAVE","SUBMIT","REOPEN"].includes(r.eventKind));
  gates.push(gate("SOURCE_REVISION_IDENTITY",
    revisionIdentity ? "PASS" : "BLOCK",
    "Stored revision identity, actor, timestamps and hashes are required.",
    revisions.length, revisionIdentity ? revisions.length : 0,
    revisions.filter(r => !isDigest(r.responsesDigest)).map(r => r.id)));
  const submissions = revisions.filter(r => r.eventKind === "SUBMIT");
  const submissionDigestValid = submissions.every(r =>
    r.storedReportValid &&
    isDigest(r.reportDigest) &&
    r.reportOrganizationId === input.organizationId);
  gates.push(gate("SUBMITTED_REPORT_INTEGRITY",
    submissionDigestValid ? "PASS" : "BLOCK",
    "The immutable submitted report must pass independent digest checks.",
    submissions.length,
    submissions.filter(r => r.storedReportValid &&
      isDigest(r.reportDigest) &&
      r.reportOrganizationId === input.organizationId).length,
    submissions.filter(r => !r.storedReportValid).map(r => r.id)));
  gates.push(gate("SUBMISSION_EXISTS",
    submissions.length ? "PASS" : "ADVISORY",
    "A draft without submission has no completed technical review source.",
    1, submissions.length));
  const submittedByRevision = new Map(submissions.map(r =>
    [r.revision, r]));
  const reviewsBySource = countMap(input.reviews,
    r => String(r.sourceRevision));
  const reviewForeignSources = input.reviews.filter(r => {
    const source = submittedByRevision.get(r.sourceRevision);
    return !source || r.draftId !== draft?.id ||
      r.reportDigest !== source.reportDigest ||
      r.scope !== "DEVELOPMENT_REVIEW" ||
      !isDigest(r.reportDigest);
  });
  gates.push(gate("REVIEW_SOURCE_BINDING",
    !reviewForeignSources.length ? "PASS" : "BLOCK",
    "Each internal review must bind to a submitted version and digest.",
    input.reviews.length,
    input.reviews.length - reviewForeignSources.length,
    reviewForeignSources.map(r => r.id)));
  const duplicateReviews = [...reviewsBySource.values()]
    .filter(rows => rows.length !== 1)
    .flat();
  gates.push(gate("ONE_REVIEW_PER_SUBMISSION",
    duplicateReviews.length ? "BLOCK" : "PASS",
    "There may be only one review per submitted source revision.",
    submissions.length, input.reviews.length,
    duplicateReviews.map(x => x.id)));
  const reviewEventsById = countMap(input.reviewEvents, x => x.reviewId);
  const reviewIds = new Set(input.reviews.map(x => x.id));
  const strayReviewEvents = input.reviewEvents.filter(e =>
    !reviewIds.has(e.reviewId));
  gates.push(gate("REVIEW_EVENT_PARENT",
    strayReviewEvents.length ? "BLOCK" : "PASS",
    "No review event may reference an absent or foreign review.",
    input.reviewEvents.length,
    input.reviewEvents.length - strayReviewEvents.length,
    strayReviewEvents.map(e => e.id)));
  const brokenReviewEvents = input.reviews.filter(review => {
    const events = reviewEventsById.get(review.id) ?? [];
    if (!contiguous(events.map(x => x.revision), review.revision))
      return true;
    const latestEvent = [...events].sort((a, b) =>
      b.revision - a.revision)[0];
    return !latestEvent ||
      latestEvent.newState !== review.state ||
      latestEvent.findingsDigest !== review.findingsDigest ||
      !events.every(e => isDigest(e.findingsDigest) &&
        isIso(e.createdAt) && assertValidString(e.actorUserId));
  });
  gates.push(gate("REVIEW_CAS_AUDIT_SEQUENCE",
    brokenReviewEvents.length ? "BLOCK" : "PASS",
    "All CAS revisions must have contiguous persisted review events.",
    input.reviews.length,
    input.reviews.length - brokenReviewEvents.length,
    brokenReviewEvents.map(x => x.id)));
  const invalidReviewState = input.reviews.filter(r =>
    !["OPEN","IN_REVIEW","CHANGES_REQUESTED",
      "TECHNICALLY_REVIEWED","REOPENED"].includes(r.state) ||
    r.revision < 1 ||
    r.issueCount < 0 ||
    r.blockingIssueCount < 0 ||
    r.blockingIssueCount > r.issueCount ||
    r.state === "TECHNICALLY_REVIEWED" &&
      (r.blockingIssueCount !== 0 || !r.completedAt) ||
    r.state !== "TECHNICALLY_REVIEWED" && r.completedAt !== null);
  gates.push(gate("REVIEW_STATE_CONSERVATIVE",
    invalidReviewState.length ? "BLOCK" : "PASS",
    "Completed review cannot contain unresolved blockers or fake signoff.",
    input.reviews.length,
    input.reviews.length - invalidReviewState.length,
    invalidReviewState.map(x => x.id)));
  const actionIds = new Set(input.actions.map(x => x.id));
  const strayActionEvents = input.actionEvents.filter(e =>
    !actionIds.has(e.followUpId));
  gates.push(gate("FOLLOW_UP_EVENT_PARENT",
    strayActionEvents.length ? "BLOCK" : "PASS",
    "Follow-up events cannot refer to unscoped or missing actions.",
    input.actionEvents.length,
    input.actionEvents.length - strayActionEvents.length,
    strayActionEvents.map(x => x.id)));
  const followUpEventsById = countMap(input.actionEvents,
    e => e.followUpId);
  const brokenActionEvents = input.actions.filter(action => {
    const events = followUpEventsById.get(action.id) ?? [];
    if (!contiguous(events.map(e => e.revision), action.revision))
      return true;
    const latestEvent = [...events].sort((a, b) =>
      b.revision - a.revision)[0];
    return !latestEvent ||
      latestEvent.nextStatus !== action.status ||
      !events.every(e => isIso(e.createdAt) &&
        assertValidString(e.actorUserId));
  });
  gates.push(gate("ACTION_CAS_AUDIT_SEQUENCE",
    brokenActionEvents.length ? "BLOCK" : "PASS",
    "Every action revision must have one immutable event.",
    input.actions.length,
    input.actions.length - brokenActionEvents.length,
    brokenActionEvents.map(x => x.id)));
  const actionWithoutSubmission = input.actions.filter(x =>
    !submittedByRevision.has(x.sourceDraftRevision));
  gates.push(gate("ACTION_SUBMISSION_PROVENANCE",
    actionWithoutSubmission.length ? "BLOCK" : "PASS",
    "Every action needs a real submitted source version.",
    input.actions.length,
    input.actions.length - actionWithoutSubmission.length,
    actionWithoutSubmission.map(x => x.id)));
  const unknownStatuses = input.actions.filter(x =>
    !["OPEN","IN_PROGRESS","BLOCKED",
      "COMPLETED_REPORTED","REOPENED"].includes(x.status));
  gates.push(gate("ACTION_STATE_RECOGNIZED",
    unknownStatuses.length ? "BLOCK" : "PASS",
    "Unknown action states cannot count as remediation.",
    input.actions.length,
    input.actions.length - unknownStatuses.length,
    unknownStatuses.map(x => x.id)));
  const overdue = input.actions.filter(x =>
    x.dueAt !== null && isIso(x.dueAt) &&
    x.dueAt < input.generatedAt &&
    !["COMPLETED_REPORTED"].includes(x.status));
  const withoutOwner = input.actions.filter(x =>
    !x.ownerUserId &&
    ["IN_PROGRESS","BLOCKED","COMPLETED_REPORTED"].includes(x.status));
  gates.push(gate("FOLLOW_UP_OVERDUE",
    overdue.length ? "ADVISORY" : "PASS",
    "Overdue declared tasks need human attention, not automatic findings.",
    0, overdue.length, overdue.map(x => x.id)));
  gates.push(gate("FOLLOW_UP_ACCOUNTABILITY",
    withoutOwner.length ? "ADVISORY" : "PASS",
    "Reported progress without a responsible member needs review.",
    0, withoutOwner.length, withoutOwner.map(x => x.id)));
  const incomplete = input.reviews.filter(r =>
    r.state !== "TECHNICALLY_REVIEWED");
  gates.push(gate("INTERNAL_TECHNICAL_REVIEW",
    incomplete.length || submissions.length !== input.reviews.length ?
      "ADVISORY" : "PASS",
    "Internal completion does not imply customer acceptance or certification.",
    submissions.length, input.reviews.length - incomplete.length,
    incomplete.map(x => x.id)));
  const summary: BaselineDossierActionSummary = {
    total: input.actions.length,
    open: input.actions.filter(x => x.status === "OPEN").length,
    inProgress: input.actions.filter(x => x.status === "IN_PROGRESS").length,
    blocked: input.actions.filter(x => x.status === "BLOCKED").length,
    completedReported: input.actions.filter(x =>
      x.status === "COMPLETED_REPORTED").length,
    reopened: input.actions.filter(x => x.status === "REOPENED").length,
    unknownStatus: unknownStatuses.length,
    overdue: overdue.length,
    missingOwners: withoutOwner.length,
    sourceRevisionWithoutSubmission: actionWithoutSubmission.length,
    independentRemediationsVerified: 0,
  };
  const timeline: BaselineDossierTimelineEntry[] = [
    ...revisions.map(x => ({
      at: x.createdAt, kind: "DRAFT_REVISION" as const,
      sourceId: x.id, sourceRevision: x.revision,
      state: x.eventKind, relationship: x.draftId,
      organizationId: x.organizationId,
    })),
    ...input.reviews.map(x => ({
      at: x.updatedAt, kind: "TECHNICAL_REVIEW" as const,
      sourceId: x.id, sourceRevision: x.sourceRevision,
      state: x.state, relationship: x.draftId,
      organizationId: x.organizationId,
    })),
    ...input.reviewEvents.map(x => ({
      at: x.createdAt, kind: "REVIEW_EVENT" as const,
      sourceId: x.id, sourceRevision: x.revision,
      state: x.action, relationship: x.reviewId,
      organizationId: x.organizationId,
    })),
    ...input.actions.map(x => ({
      at: x.updatedAt, kind: "ACTION" as const,
      sourceId: x.id, sourceRevision: x.revision,
      state: x.status, relationship: x.questionId,
      organizationId: x.organizationId,
    })),
    ...input.actionEvents.map(x => ({
      at: x.createdAt, kind: "ACTION_EVENT" as const,
      sourceId: x.id, sourceRevision: x.revision,
      state: x.action, relationship: x.followUpId,
      organizationId: x.organizationId,
    })),
  ].sort(stableTimeline);
  const resultWithoutDigest = {
    schema: "cyberpilot.baseline.development.dossier.v1" as const,
    organizationId: input.organizationId,
    generatedAt: input.generatedAt,
    verdict: (gates.some(g => g.state === "BLOCK") ?
      "BLOCKED" : gates.some(g => g.state === "ADVISORY") ?
      "REVIEW_REQUIRED" : "TECHNICALLY_TRACEABLE") as
        BaselineDossierReport["verdict"],
    latestDraftState: draft?.status ?? null,
    latestDraftRevision: draft?.revision ?? null,
    sourceCompleteness: {
      bounded: complete, allTenantScoped: allScoped,
      revisionsContiguous: revisionSequence,
      reviewEventsContiguous: brokenReviewEvents.length === 0,
      actionEventsContiguous: brokenActionEvents.length === 0,
      digestReferencesCoherent: submissionDigestValid &&
        !reviewForeignSources.length,
    },
    gates,
    submissions: submissions.map(source => {
      const review = reviewsBySource.get(String(source.revision))?.[0];
      return {
        revision: source.revision,
        reportDigest: source.reportDigest,
        sourceValid: source.storedReportValid,
        internalReviewId: review?.id ?? null,
        internalReviewState: review?.state ?? null,
        reviewEventCount: review ?
          reviewEventsById.get(review.id)?.length ?? 0 : 0,
        blockingIssueCount: review?.blockingIssueCount ?? 0,
        customerApproved: false as const,
        technicalControlsVerified: false as const,
      };
    }),
    actions: summary,
    timeline,
    sampleCounts: input.sourceCounts,
    limits: [
      "Development A+B traceability does not constitute legal signoff.",
      "A presented questionnaire is a declaration, not an observed control.",
      "TECHNICALLY_REVIEWED means internal process completion only.",
      "COMPLETED_REPORTED is not an independently verified remediation.",
      "No LIVE provider, customer tenant, external scan, or certification is implied.",
      "The SHA-256 digest is local integrity, not an external digital signature.",
      "Only bounded tenant-scoped PostgreSQL records are considered.",
    ],
    customerApprovalRecorded: false as const,
    independentlyValidatedSecurityControls: 0 as const,
    actualRemediationVerified: false as const,
    existingCyberScoreModified: false as const,
  };
  return {
    ...resultWithoutDigest,
    digest: digest(resultWithoutDigest),
  };
}
export function verifyBaselineDevelopmentDossier(
  report: BaselineDossierReport,
  expectedOrganizationId?: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const { digest: saved, ...canonical } = report;
  if (digest(canonical) !== saved)
    errors.push("DOSSIER_INTEGRITY_INVALID");
  if (expectedOrganizationId &&
      report.organizationId !== expectedOrganizationId)
    errors.push("TENANT_MISMATCH");
  if (report.customerApprovalRecorded !== false ||
      report.independentlyValidatedSecurityControls !== 0 ||
      report.actualRemediationVerified !== false ||
      report.existingCyberScoreModified !== false)
    errors.push("FORBIDDEN_CERTIFICATION_CLAIM");
  if (report.gates.length !==
      new Set(report.gates.map(x => x.id)).size)
    errors.push("DUPLICATE_GATE_ID");
  if (report.verdict === "TECHNICALLY_TRACEABLE" &&
      report.gates.some(x => x.state !== "PASS"))
    errors.push("OVERSTATED_DEVELOPMENT_READINESS");
  return { valid: errors.length === 0, errors };
}
export function compareBaselineDevelopmentDossiers(
  before: BaselineDossierReport,
  after: BaselineDossierReport,
) {
  if (!verifyBaselineDevelopmentDossier(before).valid ||
      !verifyBaselineDevelopmentDossier(after).valid ||
      before.organizationId !== after.organizationId ||
      before.generatedAt >= after.generatedAt)
    throw Error("Invalid or cross-tenant Baseline dossier comparison.");
  const prev = new Map(before.gates.map(x => [x.id, x.state]));
  const next = new Map(after.gates.map(x => [x.id, x.state]));
  return {
    organizationId: after.organizationId,
    previousDigest: before.digest,
    currentDigest: after.digest,
    newlyBlocked: [...next].filter(([id, s]) =>
      s === "BLOCK" && prev.get(id) !== "BLOCK").map(([id]) => id),
    resolvedBlocks: [...prev].filter(([id, s]) =>
      s === "BLOCK" && next.get(id) !== "BLOCK").map(([id]) => id),
    newlyAdvisory: [...next].filter(([id, s]) =>
      s === "ADVISORY" && prev.get(id) !== "ADVISORY").map(([id]) => id),
    sourcesAdded: after.timeline.length - before.timeline.length,
    customerImprovementProven: false as const,
    technicalRemediationProven: false as const,
  };
}
export function exportBaselineDevelopmentDossier(
  report: BaselineDossierReport,
  format: "JSON" | "CSV" | "MARKDOWN",
): { filename: string; mime: string; text: string } {
  if (!verifyBaselineDevelopmentDossier(report).valid)
    throw Error("Cannot export a tampered Baseline dossier.");
  const stamp = report.generatedAt.slice(0, 10);
  const stem = "baseline-development-" + stamp;
  if (format === "JSON") return {
    filename: stem + ".json", mime: "application/json",
    text: JSON.stringify(report, null, 2),
  };
  if (format === "CSV") {
    const quote = (s: unknown) =>
      '"' + String(s ?? "").replaceAll('"', '""') + '"';
    const rows = [
      ["Gate","State","Expected","Observed","Reason"],
      ...report.gates.map(x =>
        [x.id, x.state, x.expected, x.observed, x.reason]),
    ];
    return {
      filename: stem + ".csv", mime: "text/csv",
      text: rows.map(row => row.map(quote).join(",")).join("\n"),
    };
  }
  if (format !== "MARKDOWN") throw Error("Unsupported dossier format.");
  return {
    filename: stem + ".md", mime: "text/markdown",
    text: [
      "# Baseline development evidence dossier",
      "",
      "Organization: " + report.organizationId,
      "Generated: " + report.generatedAt,
      "Verdict: " + report.verdict,
      "Digest: " + report.digest,
      "",
      "| Gate | State | Expected | Observed |",
      "| --- | --- | ---: | ---: |",
      ...report.gates.map(g => "| " + g.id + " | " + g.state +
        " | " + g.expected + " | " + g.observed + " |"),
      "",
      "## Limitations",
      ...report.limits.map(x => "- " + x),
    ].join("\n"),
  };
}
