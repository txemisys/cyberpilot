import { WorkInputError } from "./remediation-work-input";
import type { IntegrityRemediationPlan } from "./work-integrity-remediation-plan";
import type { IntegrityRemediationDecisionRecord } from "./work-integrity-remediation-workspace";
import type {
  IntegrityRemediationExecutionEvent,
  IntegrityRemediationExecutionLedger,
  IntegrityRemediationExecutionState,
} from "./work-integrity-remediation-execution";
import type { IntegrityExecutionReviewAudit } from "./work-integrity-remediation-execution-review";

export type IntegrityExecutionControlIssue =
  | "MISSING_APPROVAL" | "LATE_APPROVAL" | "REJECTED_APPROVAL"
  | "DEFERRED_APPROVAL" | "UNKNOWN_CANDIDATE" | "DUPLICATE_EVENT_ID"
  | "DUPLICATE_ATTEMPT_ID" | "CONCURRENT_ATTEMPT"
  | "STARTED_AFTER_TERMINAL" | "TERMINAL_WITHOUT_START"
  | "EVENT_AFTER_EVALUATION" | "ACTOR_NOT_ATTESTED"
  | "MISSING_TERMINAL_REASON" | "MISSING_COMPLETION_REFERENCE"
  | "APPROVAL_AFTER_COMPLETION" | "UNEXPECTED_EXECUTION"
  | "UNVERIFIED_COMPLETION" | "UNAPPROVED_RETRY";
export type IntegrityExecutionControlFinding = {
  code: IntegrityExecutionControlIssue;
  severity: "ERROR" | "WARNING";
  candidateId: string;
  eventId: string | null;
  attemptId: string | null;
  occurredAt: string | null;
  explanation: string;
};
export type IntegrityExecutionControlPolicy = {
  requireApprovalBeforeStart: boolean;
  requireApprovalBeforeEveryRetry: boolean;
  requireCompletionEvidenceReference: boolean;
  rejectFutureEvents: boolean;
  warnOnUnverifiedCompletion: boolean;
  requireTerminalReason: boolean;
  maximumAttemptsPerCandidate: number;
  maximumOpenAttemptsPerCandidate: number;
};
export type IntegrityExecutionControlCandidate = {
  candidateId: string;
  priority: string;
  action: string;
  decision: string | null;
  reviewedAt: string | null;
  eventCount: number;
  acceptedEventCount: number;
  rejectedEventCount: number;
  attemptCount: number;
  openAttempts: number;
  completedAttempts: number;
  failedAttempts: number;
  cancelledAttempts: number;
  firstStartedAt: string | null;
  lastActivityAt: string | null;
  hasApprovalBeforeFirstStart: boolean;
  hasTerminalEvidenceReference: boolean;
  hasVerifiedCompletion: boolean;
  findings: IntegrityExecutionControlFinding[];
  eligibleToStart: boolean;
  needsAttention: boolean;
};
export type IntegrityExecutionControlReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  policy: IntegrityExecutionControlPolicy;
  limitation: string;
  candidates: IntegrityExecutionControlCandidate[];
  findings: IntegrityExecutionControlFinding[];
  totals: {
    candidates: number;
    started: number;
    approved: number;
    lateApprovals: number;
    missingApprovals: number;
    concurrentAttempts: number;
    unverifiedCompletions: number;
    eligibleToStart: number;
    needsAttention: number;
    errors: number;
    warnings: number;
    acceptedEvents: number;
    rejectedEvents: number;
  };
};
export type IntegrityExecutionControlQuery = {
  candidateIds?: string[];
  issueCodes?: IntegrityExecutionControlIssue[];
  priorities?: string[];
  onlyErrors?: boolean;
  onlyNeedsAttention?: boolean;
  onlyEligibleToStart?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityExecutionControlPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  candidates: IntegrityExecutionControlCandidate[];
};
export type IntegrityExecutionControlTransition = {
  candidateId: string;
  attemptId: string;
  eventId: string;
  from: IntegrityRemediationExecutionState | null;
  to: IntegrityRemediationExecutionState;
  occurredAt: string;
  actorUserId: string;
  approvedAt: string | null;
  approvedBeforeEvent: boolean;
  accepted: boolean;
  findingCodes: IntegrityExecutionControlIssue[];
};
export type IntegrityExecutionControlTimeline = {
  captureId: string;
  transitions: IntegrityExecutionControlTransition[];
  totals: {
    accepted: number;
    rejected: number;
    approvedBeforeEvent: number;
    unapprovedAtEvent: number;
    terminalTransitions: number;
    retriedCandidates: number;
  };
};
const codes: IntegrityExecutionControlIssue[] = [
  "MISSING_APPROVAL", "LATE_APPROVAL", "REJECTED_APPROVAL",
  "DEFERRED_APPROVAL", "UNKNOWN_CANDIDATE", "DUPLICATE_EVENT_ID",
  "DUPLICATE_ATTEMPT_ID", "CONCURRENT_ATTEMPT",
  "STARTED_AFTER_TERMINAL", "TERMINAL_WITHOUT_START",
  "EVENT_AFTER_EVALUATION", "ACTOR_NOT_ATTESTED",
  "MISSING_TERMINAL_REASON", "MISSING_COMPLETION_REFERENCE",
  "APPROVAL_AFTER_COMPLETION", "UNEXPECTED_EXECUTION",
  "UNVERIFIED_COMPLETION", "UNAPPROVED_RETRY",
];
const defaults: IntegrityExecutionControlPolicy = {
  requireApprovalBeforeStart: true,
  requireApprovalBeforeEveryRetry: true,
  requireCompletionEvidenceReference: true,
  rejectFutureEvents: true,
  warnOnUnverifiedCompletion: true,
  requireTerminalReason: true,
  maximumAttemptsPerCandidate: 10,
  maximumOpenAttemptsPerCandidate: 1,
};
function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function timestamp(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid execution control timestamp.");
  return value;
}
function strings(value: unknown, label: string, max = 1000) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || !x ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
function issue(
  code: IntegrityExecutionControlIssue,
  severity: IntegrityExecutionControlFinding["severity"],
  explanation: string,
  candidateId: string,
  eventId: string | null = null,
  attemptId: string | null = null,
  occurredAt: string | null = null,
): IntegrityExecutionControlFinding {
  return { code, severity, explanation, candidateId,
    eventId, attemptId, occurredAt };
}
function terminal(state: IntegrityRemediationExecutionState) {
  return state === "COMPLETED" || state === "FAILED" ||
    state === "CANCELLED";
}
export function parseIntegrityExecutionControlPolicy(
  value: unknown,
): IntegrityExecutionControlPolicy {
  if (value === undefined) return { ...defaults };
  const raw = object(value, "execution control policy");
  if (Object.keys(raw).some(x => !Object.keys(defaults).includes(x)))
    throw new WorkInputError("INVALID", "Unknown execution control field.");
  const policy = { ...defaults };
  for (const key of [
    "requireApprovalBeforeStart", "requireApprovalBeforeEveryRetry",
    "requireCompletionEvidenceReference", "rejectFutureEvents",
    "warnOnUnverifiedCompletion", "requireTerminalReason",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid control policy boolean.");
      policy[key] = raw[key] as boolean;
    }
  }
  for (const key of [
    "maximumAttemptsPerCandidate", "maximumOpenAttemptsPerCandidate",
  ] as const) {
    if (raw[key] !== undefined) {
      if (!Number.isSafeInteger(raw[key]) || (raw[key] as number) < 1 ||
          (raw[key] as number) > 100)
        throw new WorkInputError("INVALID", "Invalid control policy limit.");
      policy[key] = raw[key] as number;
    }
  }
  return policy;
}
export function evaluateIntegrityExecutionControls(
  plan: IntegrityRemediationPlan,
  decisions: readonly IntegrityRemediationDecisionRecord[],
  events: readonly IntegrityRemediationExecutionEvent[],
  ledger: IntegrityRemediationExecutionLedger,
  audit: IntegrityExecutionReviewAudit,
  evaluatedAt: string,
  policy: IntegrityExecutionControlPolicy = defaults,
): IntegrityExecutionControlReport {
  timestamp(evaluatedAt);
  if (plan.captureId !== ledger.captureId ||
      plan.captureId !== audit.captureId)
    throw new WorkInputError("INVALID", "Execution control capture mismatch.");
  const approved = new Map(decisions.map(x => [x.candidateId, x]));
  const planned = new Map(plan.candidates.map(x => [x.id, x]));
  const acceptedIds = new Set(audit.timeline.filter(x => x.accepted)
    .map(x => x.eventId));
  const allFindings: IntegrityExecutionControlFinding[] = [];
  const sorted = [...events].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) ||
    a.eventId.localeCompare(b.eventId));
  const byCandidate = new Map<string, IntegrityRemediationExecutionEvent[]>();
  const eventIds = new Set<string>();
  for (const event of sorted) {
    if (eventIds.has(event.eventId)) {
      allFindings.push(issue("DUPLICATE_EVENT_ID", "ERROR",
        "Event identifier is repeated in the submitted execution history.",
        event.candidateId, event.eventId, event.attemptId, event.occurredAt));
      continue;
    }
    eventIds.add(event.eventId);
    if (!planned.has(event.candidateId)) {
      allFindings.push(issue("UNKNOWN_CANDIDATE", "ERROR",
        "Execution event does not match the remediation plan.",
        event.candidateId, event.eventId, event.attemptId, event.occurredAt));
      continue;
    }
    const group = byCandidate.get(event.candidateId) ?? [];
    group.push(event);
    byCandidate.set(event.candidateId, group);
    if (policy.rejectFutureEvents && event.occurredAt > evaluatedAt)
      allFindings.push(issue("EVENT_AFTER_EVALUATION", "ERROR",
        "Execution event occurs after the evaluation timestamp.",
        event.candidateId, event.eventId, event.attemptId, event.occurredAt));
  }
  const candidates: IntegrityExecutionControlCandidate[] =
    ledger.candidates.map(candidate => {
      const row = planned.get(candidate.candidateId);
      const decision = approved.get(candidate.candidateId);
      const eventsForCandidate = byCandidate.get(candidate.candidateId) ?? [];
      const relevant: IntegrityExecutionControlFinding[] = [];
      const attempts = new Map<string, IntegrityRemediationExecutionEvent[]>();
      for (const event of eventsForCandidate) {
        const group = attempts.get(event.attemptId) ?? [];
        group.push(event);
        attempts.set(event.attemptId, group);
        if (!acceptedIds.has(event.eventId)) continue;
        if (event.state === "REQUESTED") {
          if (!decision) relevant.push(issue("MISSING_APPROVAL", "ERROR",
            "Execution was requested without an approval.",
            candidate.candidateId, event.eventId, event.attemptId,
            event.occurredAt));
          else if (decision.decision === "DEFER")
            relevant.push(issue("DEFERRED_APPROVAL", "ERROR",
              "Execution was requested for a deferred candidate.",
              candidate.candidateId, event.eventId, event.attemptId,
              event.occurredAt));
          else if (decision.decision === "REJECT")
            relevant.push(issue("REJECTED_APPROVAL", "ERROR",
              "Execution was requested for a rejected candidate.",
              candidate.candidateId, event.eventId, event.attemptId,
              event.occurredAt));
          else if (policy.requireApprovalBeforeStart &&
              decision.reviewedAt > event.occurredAt)
            relevant.push(issue("LATE_APPROVAL", "ERROR",
              "Execution began before the approval was recorded.",
              candidate.candidateId, event.eventId, event.attemptId,
              event.occurredAt));
        }
        if (event.state === "COMPLETED" &&
            policy.requireCompletionEvidenceReference &&
            event.evidenceRefs.length === 0 &&
            !(attempts.get(event.attemptId) ?? []).some(x =>
              x.evidenceRefs.length > 0))
          relevant.push(issue("MISSING_COMPLETION_REFERENCE", "ERROR",
            "Completion has no submitted evidence reference.",
            candidate.candidateId, event.eventId, event.attemptId,
            event.occurredAt));
        if (terminal(event.state) && event.state !== "COMPLETED" &&
            policy.requireTerminalReason && !event.reason.trim())
          relevant.push(issue("MISSING_TERMINAL_REASON", "ERROR",
            "Terminal failure or cancellation requires a reason.",
            candidate.candidateId, event.eventId, event.attemptId,
            event.occurredAt));
      }
      const started = [...attempts.values()].filter(rows =>
        rows.some(x => x.state === "REQUESTED"));
      if (started.length > policy.maximumAttemptsPerCandidate)
        relevant.push(issue("UNAPPROVED_RETRY", "ERROR",
          "Execution exceeds maximum permitted attempts.",
          candidate.candidateId));
      const open = [...attempts.values()].filter(rows => {
        const last = rows.at(-1);
        return last && !terminal(last.state);
      });
      if (open.length > policy.maximumOpenAttemptsPerCandidate)
        relevant.push(issue("CONCURRENT_ATTEMPT", "ERROR",
          "Multiple execution attempts remain open.",
          candidate.candidateId));
      const earliest = eventsForCandidate[0];
      const acceptedEvents = eventsForCandidate.filter(x =>
        acceptedIds.has(x.eventId));
      const firstStartedAt = acceptedEvents.find(x =>
        x.state === "REQUESTED")?.occurredAt ?? null;
      const hasApprovalBeforeFirstStart = !!decision &&
        decision.decision === "ACCEPT" &&
        (firstStartedAt === null || decision.reviewedAt <= firstStartedAt);
      if (candidate.state === "COMPLETED" &&
          !candidate.hasVerifiedEvidence && policy.warnOnUnverifiedCompletion)
        relevant.push(issue("UNVERIFIED_COMPLETION", "WARNING",
          "Completed execution lacks independently verified evidence.",
          candidate.candidateId));
      if (candidate.state === "COMPLETED" &&
          decision && candidate.completedAt &&
          decision.reviewedAt > candidate.completedAt)
        relevant.push(issue("APPROVAL_AFTER_COMPLETION", "ERROR",
          "Approval occurred after the recorded completion.",
          candidate.candidateId));
      const terminalEvidence = acceptedEvents.some(x =>
        x.state === "COMPLETED" && x.evidenceRefs.length > 0);
      const eligible = !!row && !!decision &&
        decision.decision === "ACCEPT" &&
        decision.reviewedAt <= evaluatedAt &&
        candidate.state === "NOT_STARTED" &&
        relevant.every(x => x.severity !== "ERROR");
      allFindings.push(...relevant);
      return {
        candidateId: candidate.candidateId,
        priority: candidate.priority ?? "UNKNOWN",
        action: candidate.action ?? "UNKNOWN",
        decision: decision?.decision ?? null,
        reviewedAt: decision?.reviewedAt ?? null,
        eventCount: eventsForCandidate.length,
        acceptedEventCount: acceptedEvents.length,
        rejectedEventCount: eventsForCandidate.length - acceptedEvents.length,
        attemptCount: attempts.size,
        openAttempts: open.length,
        completedAttempts: [...attempts.values()].filter(rows =>
          rows.at(-1)?.state === "COMPLETED").length,
        failedAttempts: [...attempts.values()].filter(rows =>
          rows.at(-1)?.state === "FAILED").length,
        cancelledAttempts: [...attempts.values()].filter(rows =>
          rows.at(-1)?.state === "CANCELLED").length,
        firstStartedAt,
        lastActivityAt: eventsForCandidate.at(-1)?.occurredAt ?? null,
        hasApprovalBeforeFirstStart,
        hasTerminalEvidenceReference: terminalEvidence,
        hasVerifiedCompletion: candidate.hasVerifiedEvidence,
        findings: relevant,
        eligibleToStart: eligible,
        needsAttention: relevant.length > 0 ||
          candidate.state === "BLOCKED" || candidate.state === "FAILED",
      };
    });
  return {
    schemaVersion: 1, captureId: plan.captureId, evaluatedAt, policy,
    limitation: "Submitted execution events and actor identities are client-declared; this is a diagnostic review, not a persisted authorization record.",
    candidates, findings: allFindings,
    totals: {
      candidates: candidates.length,
      started: candidates.filter(x => x.firstStartedAt !== null).length,
      approved: candidates.filter(x => x.decision === "ACCEPT").length,
      lateApprovals: allFindings.filter(x =>
        x.code === "LATE_APPROVAL").length,
      missingApprovals: allFindings.filter(x =>
        x.code === "MISSING_APPROVAL").length,
      concurrentAttempts: allFindings.filter(x =>
        x.code === "CONCURRENT_ATTEMPT").length,
      unverifiedCompletions: allFindings.filter(x =>
        x.code === "UNVERIFIED_COMPLETION").length,
      eligibleToStart: candidates.filter(x => x.eligibleToStart).length,
      needsAttention: candidates.filter(x => x.needsAttention).length,
      errors: allFindings.filter(x => x.severity === "ERROR").length,
      warnings: allFindings.filter(x => x.severity === "WARNING").length,
      acceptedEvents: audit.totals.accepted,
      rejectedEvents: audit.totals.rejected,
    },
  };
}
export function buildIntegrityExecutionControlTimeline(
  report: IntegrityExecutionControlReport,
  events: readonly IntegrityRemediationExecutionEvent[],
  audit: IntegrityExecutionReviewAudit,
): IntegrityExecutionControlTimeline {
  if (report.captureId !== audit.captureId)
    throw new WorkInputError("INVALID", "Control timeline capture mismatch.");
  const byCandidate = new Map(report.candidates.map(x =>
    [x.candidateId, x]));
  const accepted = new Set(audit.timeline.filter(x => x.accepted)
    .map(x => x.eventId));
  const previous = new Map<string, IntegrityRemediationExecutionState>();
  const transitions = [...events].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) ||
    a.eventId.localeCompare(b.eventId)).map(event => {
    const key = JSON.stringify([event.candidateId, event.attemptId]);
    const old = previous.get(key) ?? null;
    const isAccepted = accepted.has(event.eventId);
    if (isAccepted) previous.set(key, event.state);
    const candidate = byCandidate.get(event.candidateId);
    const approvedAt = candidate?.decision === "ACCEPT"
      ? candidate.reviewedAt : null;
    return {
      candidateId: event.candidateId, attemptId: event.attemptId,
      eventId: event.eventId, from: old, to: event.state,
      occurredAt: event.occurredAt, actorUserId: event.actorUserId,
      approvedAt,
      approvedBeforeEvent: approvedAt !== null &&
        approvedAt <= event.occurredAt,
      accepted: isAccepted,
      findingCodes: (candidate?.findings ?? []).filter(x =>
        x.eventId === event.eventId).map(x => x.code),
    };
  });
  return {
    captureId: report.captureId, transitions,
    totals: {
      accepted: transitions.filter(x => x.accepted).length,
      rejected: transitions.filter(x => !x.accepted).length,
      approvedBeforeEvent: transitions.filter(x =>
        x.approvedBeforeEvent).length,
      unapprovedAtEvent: transitions.filter(x =>
        !x.approvedBeforeEvent).length,
      terminalTransitions: transitions.filter(x =>
        x.accepted && terminal(x.to)).length,
      retriedCandidates: report.candidates.filter(x =>
        x.attemptCount > 1).length,
    },
  };
}
export function parseIntegrityExecutionControlQuery(
  value: unknown,
): IntegrityExecutionControlQuery {
  const raw = object(value, "execution control query");
  if (Object.keys(raw).some(x => ![
    "candidateIds", "issueCodes", "priorities",
    "onlyErrors", "onlyNeedsAttention", "onlyEligibleToStart",
    "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown control query field.");
  for (const key of [
    "onlyErrors", "onlyNeedsAttention", "onlyEligibleToStart",
  ]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid control query flag.");
  }
  const issueCodes = raw.issueCodes === undefined ? undefined :
    strings(raw.issueCodes, "control issue codes", 100);
  if (issueCodes?.some(x => !codes.includes(x as IntegrityExecutionControlIssue)))
    throw new WorkInputError("INVALID", "Unknown control issue code.");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 100;
  if (!Number.isSafeInteger(offset) || (offset as number) < 0 ||
      (offset as number) > 1000000 ||
      !Number.isSafeInteger(limit) || (limit as number) < 1 ||
      (limit as number) > 1000)
    throw new WorkInputError("INVALID", "Invalid control query pagination.");
  return {
    ...(raw.candidateIds !== undefined ? {
      candidateIds: strings(raw.candidateIds, "control candidate IDs"),
    } : {}),
    ...(issueCodes !== undefined ? {
      issueCodes: issueCodes as IntegrityExecutionControlIssue[],
    } : {}),
    ...(raw.priorities !== undefined ? {
      priorities: strings(raw.priorities, "control priorities"),
    } : {}),
    onlyErrors: raw.onlyErrors === true,
    onlyNeedsAttention: raw.onlyNeedsAttention === true,
    onlyEligibleToStart: raw.onlyEligibleToStart === true,
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityExecutionControls(
  report: IntegrityExecutionControlReport,
  query: IntegrityExecutionControlQuery,
): IntegrityExecutionControlPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.candidates.filter(candidate =>
    (!query.candidateIds ||
      query.candidateIds.includes(candidate.candidateId)) &&
    (!query.priorities ||
      query.priorities.includes(candidate.priority)) &&
    (!query.issueCodes || candidate.findings.some(x =>
      query.issueCodes!.includes(x.code))) &&
    (!query.onlyErrors || candidate.findings.some(x =>
      x.severity === "ERROR")) &&
    (!query.onlyNeedsAttention || candidate.needsAttention) &&
    (!query.onlyEligibleToStart || candidate.eligibleToStart));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    candidates: selected.slice(offset, offset + limit),
  };
}
export function compareIntegrityExecutionControls(
  before: IntegrityExecutionControlReport,
  after: IntegrityExecutionControlReport,
) {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Control comparison capture mismatch.");
  const old = new Map(before.candidates.map(x => [x.candidateId, x]));
  const current = new Map(after.candidates.map(x => [x.candidateId, x]));
  return {
    captureId: before.captureId,
    from: before.evaluatedAt, to: after.evaluatedAt,
    introduced: after.candidates.filter(x => !old.has(x.candidateId))
      .map(x => x.candidateId),
    removed: before.candidates.filter(x => !current.has(x.candidateId))
      .map(x => x.candidateId),
    newlyEligible: after.candidates.filter(x =>
      x.eligibleToStart && !old.get(x.candidateId)?.eligibleToStart)
      .map(x => x.candidateId),
    eligibilityLost: before.candidates.filter(x =>
      x.eligibleToStart && !current.get(x.candidateId)?.eligibleToStart)
      .map(x => x.candidateId),
    newlyFlagged: after.candidates.filter(x =>
      x.needsAttention && !old.get(x.candidateId)?.needsAttention)
      .map(x => x.candidateId),
    attentionResolved: before.candidates.filter(x =>
      x.needsAttention && !current.get(x.candidateId)?.needsAttention)
      .map(x => x.candidateId),
    errorDelta: after.totals.errors - before.totals.errors,
    warningDelta: after.totals.warnings - before.totals.warnings,
    eligibleDelta: after.totals.eligibleToStart -
      before.totals.eligibleToStart,
    attentionDelta: after.totals.needsAttention -
      before.totals.needsAttention,
  };
}
