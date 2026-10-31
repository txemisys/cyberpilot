export type ReviewEvidenceSource = "OBSERVED" | "DECLARED" | "UNKNOWN" | "ERROR";
export type ReviewFindingStatus = "OPEN" | "RESOLVED" | "SUPPRESSED" | string;
export type ReviewActionStatus = "PROPOSED" | "APPROVED" | "EXECUTING" | "SUCCEEDED" | "VERIFIED" | "FAILED" | string;
export type ReviewPriority = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | string;

export type ReviewEvidence = {
  id: string;
  source: ReviewEvidenceSource;
  category: string;
  capturedAt: Date | null;
  lastObservedAt: Date | null;
  summary: string;
};

export type ReviewAction = {
  id: string;
  title: string;
  status: ReviewActionStatus;
  mode: "GUIDED" | "AUTOMATED";
  createdAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
  verifiedAt: Date | null;
  approvedAt: Date | null;
  steps: readonly string[];
  verification: readonly string[];
  acknowledgedSteps: ReadonlySet<number>;
};

export type ReviewFinding = {
  id: string;
  title: string;
  description: string;
  severity: ReviewPriority;
  status: ReviewFindingStatus;
  firstSeenAt: Date;
  lastSeenAt: Date;
  resolvedAt: Date | null;
  evidence: readonly ReviewEvidence[];
  actions: readonly ReviewAction[];
};

export type EvidenceReviewStatus =
  | "verified"
  | "needs-observation"
  | "ready-for-check"
  | "in-progress"
  | "unaddressed"
  | "finding-resolved"
  | "review-needed";

export type EvidenceReview = {
  findingId: string;
  findingTitle: string;
  severity: ReviewPriority;
  findingStatus: ReviewFindingStatus;
  status: EvidenceReviewStatus;
  explanation: string;
  nextAction: string;
  observedCount: number;
  declaredCount: number;
  unknownCount: number;
  errorCount: number;
  actionCount: number;
  verifiedActionCount: number;
  acknowledgedStepCount: number;
  totalStepCount: number;
  mostRecentObservationAt: Date | null;
  latestActionAt: Date | null;
  verificationAt: Date | null;
  evidenceFreshness: "not-observed" | "dated" | "unknown";
  requiresFreshEvidence: boolean;
};

const PRIORITY: Readonly<Record<string, number>> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function mostRecent(dates: readonly (Date | null)[]): Date | null {
  let selected: Date | null = null;
  for (const date of dates) {
    if (!date || !Number.isFinite(date.getTime())) continue;
    if (!selected || date.getTime() > selected.getTime()) selected = date;
  }
  return selected;
}

function countAcknowledged(action: ReviewAction): number {
  return action.steps.reduce(
    (total, _step, index) => total + (action.acknowledgedSteps.has(index) ? 1 : 0),
    0,
  );
}

function isVerified(action: ReviewAction): boolean {
  return action.status === "VERIFIED" && action.verifiedAt !== null;
}

function requiresEvidence(action: ReviewAction): boolean {
  if (isVerified(action)) return false;
  if (action.status === "SUCCEEDED") return true;
  return action.mode === "GUIDED" &&
    action.status === "APPROVED" &&
    action.steps.length > 0 &&
    countAcknowledged(action) === action.steps.length;
}

function hasUnfinishedWork(action: ReviewAction): boolean {
  return action.status === "APPROVED" ||
    action.status === "EXECUTING" ||
    action.status === "FAILED";
}

export function buildFindingEvidenceReview(finding: ReviewFinding): EvidenceReview {
  const observed = finding.evidence.filter(item => item.source === "OBSERVED");
  const declared = finding.evidence.filter(item => item.source === "DECLARED");
  const unknown = finding.evidence.filter(item => item.source === "UNKNOWN");
  const errors = finding.evidence.filter(item => item.source === "ERROR");
  const observedAt = mostRecent(observed.flatMap(item => [
    item.lastObservedAt,
    item.capturedAt,
  ]));
  const latestActionAt = mostRecent(
    finding.actions.map(item => item.verifiedAt ??
      item.completedAt ?? item.startedAt ?? item.approvedAt ?? item.createdAt),
  );
  const verifiedActions = finding.actions.filter(isVerified);
  const verifiedAt = mostRecent(verifiedActions.map(item => item.verifiedAt));
  const pendingEvidence = finding.actions.some(requiresEvidence);
  const unfinished = finding.actions.some(hasUnfinishedWork);
  const completedSteps = finding.actions.reduce(
    (total, item) => total + countAcknowledged(item),
    0,
  );
  const allSteps = finding.actions.reduce(
    (total, item) => total + item.steps.length,
    0,
  );

  let status: EvidenceReviewStatus;
  let explanation: string;
  let nextAction: string;
  if (finding.status === "RESOLVED") {
    status = "finding-resolved";
    explanation = "The stored finding is resolved. Review its provenance and history before communicating closure.";
    nextAction = "Review recorded resolution and the evidence that supports it.";
  } else if (verifiedAt) {
    status = "verified";
    explanation = "At least one action has a recorded verification timestamp. The finding status is shown separately.";
    nextAction = "Confirm whether the associated finding remains open and whether further work is required.";
  } else if (pendingEvidence) {
    status = "ready-for-check";
    explanation = "Work has been acknowledged or execution completed; it is not yet verified by fresh evidence.";
    nextAction = "Request fresh evidence and compare the result against the verification checklist.";
  } else if (unfinished) {
    status = "in-progress";
    explanation = "A remediation has been approved, is executing or requires attention after failure.";
    nextAction = "Continue the recorded remediation steps or investigate the failed execution.";
  } else if (finding.actions.length === 0) {
    status = "unaddressed";
    explanation = "No remediation action is recorded for this finding.";
    nextAction = "Review the finding and plan a suitable remediation.";
  } else if (observed.length === 0) {
    status = "needs-observation";
    explanation = "The existing evidence does not include an observed result.";
    nextAction = "Collect an observed signal before claiming an effective security control.";
  } else {
    status = "review-needed";
    explanation = "The recorded actions have not established verified resolution.";
    nextAction = "Review action state and collect further evidence where needed.";
  }

  return {
    findingId: finding.id,
    findingTitle: finding.title,
    severity: finding.severity,
    findingStatus: finding.status,
    status,
    explanation,
    nextAction,
    observedCount: observed.length,
    declaredCount: declared.length,
    unknownCount: unknown.length,
    errorCount: errors.length,
    actionCount: finding.actions.length,
    verifiedActionCount: verifiedActions.length,
    acknowledgedStepCount: completedSteps,
    totalStepCount: allSteps,
    mostRecentObservationAt: observedAt,
    latestActionAt,
    verificationAt: verifiedAt,
    evidenceFreshness: observedAt ? "dated" :
      observed.length ? "unknown" : "not-observed",
    requiresFreshEvidence: status === "ready-for-check" ||
      status === "needs-observation",
  };
}

export function rankEvidenceReviews(reviews: readonly EvidenceReview[]): EvidenceReview[] {
  const stateRanks: Record<EvidenceReviewStatus, number> = {
    "ready-for-check": 0,
    "needs-observation": 1,
    "in-progress": 2,
    "unaddressed": 3,
    "review-needed": 4,
    "verified": 5,
    "finding-resolved": 6,
  };
  return [...reviews].sort((left, right) => {
    const state = stateRanks[left.status] - stateRanks[right.status];
    if (state) return state;
    const severity = (PRIORITY[left.severity] ?? 5) -
      (PRIORITY[right.severity] ?? 5);
    if (severity) return severity;
    return left.findingId.localeCompare(right.findingId);
  });
}

export type ReviewPortfolio = {
  total: number;
  unaddressed: number;
  inProgress: number;
  pendingEvidence: number;
  verified: number;
  resolved: number;
  observedSignals: number;
  declaredSignals: number;
  unknownSignals: number;
  errorSignals: number;
};

export function summarizeEvidenceReviews(
  reviews: readonly EvidenceReview[],
): ReviewPortfolio {
  return {
    total: reviews.length,
    unaddressed: reviews.filter(item => item.status === "unaddressed").length,
    inProgress: reviews.filter(item => item.status === "in-progress").length,
    pendingEvidence: reviews.filter(item => item.requiresFreshEvidence).length,
    verified: reviews.filter(item => item.status === "verified").length,
    resolved: reviews.filter(item => item.status === "finding-resolved").length,
    observedSignals: reviews.reduce((sum, item) => sum + item.observedCount, 0),
    declaredSignals: reviews.reduce((sum, item) => sum + item.declaredCount, 0),
    unknownSignals: reviews.reduce((sum, item) => sum + item.unknownCount, 0),
    errorSignals: reviews.reduce((sum, item) => sum + item.errorCount, 0),
  };
}

export function evidenceReviewCsv(reviews: readonly EvidenceReview[]): string {
  const fields = [
    "Finding ID", "Title", "Severity", "Finding status", "Review state",
    "Observed signals", "Declared signals", "Unknown signals", "Error signals",
    "Actions", "Verified actions", "Steps acknowledged", "Total steps",
    "Last observed UTC", "Last verified UTC", "Next action",
  ];
  const cell = (value: string) => {
    const safe = /^[\s]*[=+@\-]/.test(value) ? "'" + value : value;
    return '"' + safe.replaceAll('"', '""') + '"';
  };
  const lines = reviews.map(item => [
    item.findingId, item.findingTitle, item.severity, item.findingStatus,
    item.status, item.observedCount.toString(), item.declaredCount.toString(),
    item.unknownCount.toString(), item.errorCount.toString(),
    item.actionCount.toString(), item.verifiedActionCount.toString(),
    item.acknowledgedStepCount.toString(), item.totalStepCount.toString(),
    item.mostRecentObservationAt?.toISOString() ?? "",
    item.verificationAt?.toISOString() ?? "", item.nextAction,
  ].map(cell).join(","));
  return "\uFEFF" + [fields.map(cell).join(","), ...lines].join("\r\n") + "\r\n";
}
