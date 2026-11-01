import type {
  ContinuityFinding, ContinuityFindingKind, ContinuityReport,
} from "./work-integrity-review-continuity";

/**
 * Convert audit continuity diagnostics into a bounded handoff plan for humans.
 * This is an in-memory recommendation, not a persisted assignment or approval.
 */
export type ContinuityActionType =
  | "RECONCILE_AUDIT_SOURCE"
  | "REVIEW_WORK_REVISION"
  | "REASSESS_TRIAGE"
  | "RECAPTURE_SCOPE"
  | "CHECK_EVENT_ATTRIBUTION"
  | "DOCUMENT_RATIONALE"
  | "VERIFY_CLOCKS";
export type ContinuityAction = {
  id: string;
  caseKey: string | null;
  type: ContinuityActionType;
  priority: "P0" | "P1" | "P2" | "P3";
  explanation: string;
  nextStep: string;
  firstDetectedAt: string;
  lastDetectedAt: string;
  occurrences: number;
  relatedFindingKinds: ContinuityFindingKind[];
  relatedEventIds: string[];
  requiresSourceAccess: boolean;
  requiresHumanDecision: boolean;
  cannotCloseAutomatically: true;
};
export type ContinuityActionPlan = {
  organizationId: string;
  capturedThrough: string;
  actions: ContinuityAction[];
  totals: Record<ContinuityAction["priority"], number>;
  byType: Partial<Record<ContinuityActionType, number>>;
  affectedCaseCount: number;
  totalActionCandidates: number;
  truncated: boolean;
  limitations: string[];
};
type ActionRule = {
  kind: ContinuityFindingKind;
  type: ContinuityActionType;
  priority: ContinuityAction["priority"];
  explanation: string;
  nextStep: string;
  requiresSourceAccess: boolean;
  requiresHumanDecision: boolean;
};
const rules: readonly ActionRule[] = [
  {
    kind: "REVIEW_EVENT_REUSED_FOR_DIFFERENT_CASE",
    type: "RECONCILE_AUDIT_SOURCE", priority: "P0",
    explanation: "An audit event identity appears under different cases.",
    nextStep: "Compare the original immutable event resource ID and audit source before trusting either capture.",
    requiresSourceAccess: true, requiresHumanDecision: true,
  },
  {
    kind: "REVIEW_EVENT_CONTENT_CHANGED",
    type: "RECONCILE_AUDIT_SOURCE", priority: "P0",
    explanation: "Review event metadata changed while its identity remained constant.",
    nextStep: "Retrieve source audit records and investigate changes to actor, timestamp, revision and rationale.",
    requiresSourceAccess: true, requiresHumanDecision: true,
  },
  {
    kind: "DECISION_CHANGED_WITHOUT_EVENT",
    type: "RECONCILE_AUDIT_SOURCE", priority: "P0",
    explanation: "A decision state changed without a new linked review event.",
    nextStep: "Reconstruct the decision sequence from the authoritative audit ledger.",
    requiresSourceAccess: true, requiresHumanDecision: true,
  },
  {
    kind: "WORK_REVISION_REWOUND",
    type: "REVIEW_WORK_REVISION", priority: "P0",
    explanation: "A work item appears to have moved backward in revision history.",
    nextStep: "Check optimistic-concurrency history and reload the latest tenant-scoped task revision.",
    requiresSourceAccess: true, requiresHumanDecision: false,
  },
  {
    kind: "REVIEW_REVISION_REWOUND",
    type: "REVIEW_WORK_REVISION", priority: "P1",
    explanation: "The recorded review revision moved backward.",
    nextStep: "Inspect whether a historical review was incorrectly presented as the latest decision.",
    requiresSourceAccess: true, requiresHumanDecision: true,
  },
  {
    kind: "REVIEW_REVISION_AHEAD",
    type: "REVIEW_WORK_REVISION", priority: "P0",
    explanation: "Review metadata references an unavailable future task revision.",
    nextStep: "Correlate the audit event with the work revision history and investigate synchronization.",
    requiresSourceAccess: true, requiresHumanDecision: true,
  },
  {
    kind: "REVIEW_STALE",
    type: "REASSESS_TRIAGE", priority: "P1",
    explanation: "A review no longer corresponds to the captured task revision.",
    nextStep: "Request an authorized human decision using the current task state and linked evidence.",
    requiresSourceAccess: false, requiresHumanDecision: true,
  },
  {
    kind: "REVIEW_ABSENT_ON_NEW_REVISION",
    type: "REASSESS_TRIAGE", priority: "P1",
    explanation: "The task was revised without retaining a current review link.",
    nextStep: "Inspect prior reviews and determine whether a new decision is required.",
    requiresSourceAccess: true, requiresHumanDecision: true,
  },
  {
    kind: "REVIEW_EVENT_DISAPPEARED",
    type: "RECONCILE_AUDIT_SOURCE", priority: "P1",
    explanation: "An existing review event is absent despite the case remaining present.",
    nextStep: "Check event retention and verify the current case audit history.",
    requiresSourceAccess: true, requiresHumanDecision: false,
  },
  {
    kind: "REVIEW_EVENT_CHANGED_WITHOUT_REVISION",
    type: "REASSESS_TRIAGE", priority: "P2",
    explanation: "A new audit event was recorded without an accompanying task revision.",
    nextStep: "Check whether the event is a legitimate supplementary review.",
    requiresSourceAccess: true, requiresHumanDecision: true,
  },
  {
    kind: "REVIEW_UNATTRIBUTED",
    type: "CHECK_EVENT_ATTRIBUTION", priority: "P2",
    explanation: "A review event is missing its current user attribution.",
    nextStep: "Identify the original actor or document that the account was removed.",
    requiresSourceAccess: true, requiresHumanDecision: false,
  },
  {
    kind: "REVIEW_WITHOUT_RATIONALE",
    type: "DOCUMENT_RATIONALE", priority: "P2",
    explanation: "A review lacks a sufficient explanation in recorded metadata.",
    nextStep: "Ask the reviewer to provide a new auditable explanation; do not rewrite prior events.",
    requiresSourceAccess: false, requiresHumanDecision: true,
  },
  {
    kind: "REVIEW_TIME_REWOUND",
    type: "VERIFY_CLOCKS", priority: "P1",
    explanation: "The latest review time appears earlier than the preceding snapshot.",
    nextStep: "Compare source event order, clock synchronization and event ingestion times.",
    requiresSourceAccess: true, requiresHumanDecision: false,
  },
  {
    kind: "REVIEW_TIME_AFTER_CAPTURE",
    type: "VERIFY_CLOCKS", priority: "P1",
    explanation: "A review appears to occur after its enclosing capture.",
    nextStep: "Verify trusted time sources and regenerate the capture if clocks are inconsistent.",
    requiresSourceAccess: true, requiresHumanDecision: false,
  },
  {
    kind: "SOURCE_SCOPE_INCOMPLETE",
    type: "RECAPTURE_SCOPE", priority: "P1",
    explanation: "At least one source capture does not claim complete coverage.",
    nextStep: "Recollect the same query scope, including audit history and linked operational records.",
    requiresSourceAccess: true, requiresHumanDecision: false,
  },
];
const lookup = new Map(rules.map(rule => [rule.kind, rule]));
const priorityRank = { P0: 0, P1: 1, P2: 2, P3: 3 };
type Candidate = {
  rule: ActionRule;
  issue: ContinuityFinding;
};
function candidateKey(type: ContinuityActionType, key: string | null): string {
  // A JSON tuple avoids ambiguous delimiter collisions in source case IDs.
  return JSON.stringify([type, key]);
}
function canonicalActionId(type: ContinuityActionType, key: string | null): string {
  return candidateKey(type, key);
}
function choosePriority(candidates: readonly Candidate[]): ContinuityAction["priority"] {
  return candidates.map(item => item.rule.priority)
    .sort((a, b) => priorityRank[a] - priorityRank[b])[0] ?? "P3";
}
function mergeCandidates(candidates: readonly Candidate[]): ContinuityAction {
  if (!candidates.length) throw new Error("Cannot create an empty continuity action.");
  const first = candidates[0]!;
  const priority = choosePriority(candidates);
  const ordered = [...candidates].sort((a, b) =>
    priorityRank[a.rule.priority] - priorityRank[b.rule.priority] ||
    a.issue.afterTime.localeCompare(b.issue.afterTime));
  const primary = ordered[0]!;
  const times = candidates.map(candidate => candidate.issue.afterTime).sort();
  const kinds = [...new Set(candidates.map(candidate => candidate.issue.kind))].sort();
  const events = [...new Set(candidates
    .map(candidate => candidate.issue.eventId)
    .filter((id): id is string => id !== null))].sort();
  return {
    id: canonicalActionId(first.rule.type, first.issue.caseKey),
    caseKey: first.issue.caseKey,
    type: first.rule.type,
    priority,
    explanation: primary.rule.explanation,
    nextStep: primary.rule.nextStep,
    firstDetectedAt: times[0]!,
    lastDetectedAt: times[times.length - 1]!,
    occurrences: candidates.length,
    relatedFindingKinds: kinds,
    relatedEventIds: events,
    requiresSourceAccess: candidates.some(item => item.rule.requiresSourceAccess),
    requiresHumanDecision: candidates.some(item => item.rule.requiresHumanDecision),
    cannotCloseAutomatically: true,
  };
}
export function planContinuityActions(
  report: ContinuityReport,
  options: { limit?: number; includeInformation?: boolean } = {},
): ContinuityActionPlan {
  const limit = options.limit ?? 250;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    throw new Error("Continuity action limit must be between 1 and 1000.");
  if (options.includeInformation !== undefined &&
      typeof options.includeInformation !== "boolean")
    throw new Error("Invalid information option.");
  const grouped = new Map<string, Candidate[]>();
  for (const transition of report.transitions) {
    for (const issue of transition.findings) {
      if (!options.includeInformation && issue.severity === "INFO") continue;
      const rule = lookup.get(issue.kind);
      if (!rule) throw new Error("Unknown continuity diagnostic mapping.");
      const key = candidateKey(rule.type, issue.caseKey);
      const existing = grouped.get(key);
      if (existing) existing.push({ rule, issue });
      else grouped.set(key, [{ rule, issue }]);
    }
  }
  const candidates = [...grouped.values()].map(mergeCandidates);
  candidates.sort((a, b) =>
    priorityRank[a.priority] - priorityRank[b.priority] ||
    b.occurrences - a.occurrences ||
    a.id.localeCompare(b.id));
  const actions = candidates.slice(0, limit);
  const totals: ContinuityActionPlan["totals"] = {
    P0: 0, P1: 0, P2: 0, P3: 0,
  };
  const byType: ContinuityActionPlan["byType"] = {};
  for (const action of candidates) {
    totals[action.priority]++;
    byType[action.type] = (byType[action.type] ?? 0) + 1;
  }
  return {
    organizationId: report.organizationId,
    capturedThrough: report.to,
    actions, totals, byType,
    affectedCaseCount: new Set(candidates.map(action => action.caseKey)
      .filter((key): key is string => key !== null)).size,
    totalActionCandidates: candidates.length,
    truncated: candidates.length > limit,
    limitations: [
      "Actions are suggestions derived from uploaded captures and are not persisted.",
      "Any recommended review must be performed through the authorized audited workflow.",
      "No suggestion asserts verified remediation, compliance or control effectiveness.",
      ...(candidates.length > limit ?
        ["Some suggested actions were omitted by the bounded response limit."] : []),
    ],
  };
}
export function continuityActionsCsv(plan: ContinuityActionPlan): string {
  const quote = (value: unknown): string => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const columns = [
    "caseKey", "priority", "type", "explanation", "nextStep",
    "occurrences", "firstDetectedAt", "lastDetectedAt",
    "relatedFindingKinds", "relatedEventIds",
    "requiresSourceAccess", "requiresHumanDecision", "cannotCloseAutomatically",
  ];
  const lines = [columns.map(quote).join(",")];
  for (const action of plan.actions) {
    lines.push([
      action.caseKey, action.priority, action.type,
      action.explanation, action.nextStep, action.occurrences,
      action.firstDetectedAt, action.lastDetectedAt,
      action.relatedFindingKinds.join(";"), action.relatedEventIds.join(";"),
      action.requiresSourceAccess, action.requiresHumanDecision,
      action.cannotCloseAutomatically,
    ].map(quote).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
