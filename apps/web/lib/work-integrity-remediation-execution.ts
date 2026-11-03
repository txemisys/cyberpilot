import { WorkInputError } from "./remediation-work-input";
import type { IntegrityRemediationPlan, IntegrityRemediationCandidate } from "./work-integrity-remediation-plan";
import type { IntegrityRemediationDecisionRecord } from "./work-integrity-remediation-workspace";

export type IntegrityRemediationExecutionState =
  | "REQUESTED" | "IN_PROGRESS" | "BLOCKED" | "COMPLETED" | "FAILED" | "CANCELLED";
export type IntegrityRemediationExecutionEvent = {
  eventId: string;
  candidateId: string;
  state: IntegrityRemediationExecutionState;
  occurredAt: string;
  actorUserId: string;
  evidenceRefs: string[];
  reason: string;
  attemptId: string;
};
export type IntegrityRemediationExecutionIssue =
  | "UNKNOWN_CANDIDATE" | "DUPLICATE_EVENT" | "DUPLICATE_TRANSITION"
  | "INVALID_TRANSITION" | "OUT_OF_ORDER" | "MISSING_EVIDENCE"
  | "MISSING_REASON" | "UNAPPROVED_EXECUTION" | "DUPLICATE_ATTEMPT"
  | "STALE_DECISION" | "REOPENED_COMPLETION";
export type IntegrityRemediationExecutionFinding = {
  code: IntegrityRemediationExecutionIssue;
  eventId: string;
  candidateId: string;
  attemptId: string;
  explanation: string;
  severity: "ERROR" | "WARNING";
};
export type IntegrityRemediationExecutionAttempt = {
  attemptId: string;
  candidateId: string;
  state: IntegrityRemediationExecutionState;
  startedAt: string;
  lastChangedAt: string;
  completedAt: string | null;
  startedBy: string;
  lastActor: string;
  evidenceRefs: string[];
  eventIds: string[];
  transitions: number;
  terminal: boolean;
  reason: string;
};
export type IntegrityRemediationExecutionCandidate = {
  candidateId: string;
  action: IntegrityRemediationCandidate["action"] | null;
  priority: IntegrityRemediationCandidate["priority"] | null;
  decision: IntegrityRemediationDecisionRecord["decision"] | null;
  currentAttemptId: string | null;
  state: IntegrityRemediationExecutionState | "NOT_STARTED";
  attempts: IntegrityRemediationExecutionAttempt[];
  hasVerifiedEvidence: boolean;
  completedAt: string | null;
  findings: IntegrityRemediationExecutionFinding[];
};
export type IntegrityRemediationExecutionLedger = {
  schemaVersion: 1;
  captureId: string;
  candidates: IntegrityRemediationExecutionCandidate[];
  findings: IntegrityRemediationExecutionFinding[];
  totals: {
    candidates: number;
    notStarted: number;
    requested: number;
    inProgress: number;
    blocked: number;
    completed: number;
    failed: number;
    cancelled: number;
    verifiedCompleted: number;
    unverifiedCompleted: number;
    attempts: number;
    events: number;
    errors: number;
    warnings: number;
  };
};
export type IntegrityRemediationExecutionQuery = {
  states?: Array<IntegrityRemediationExecutionCandidate["state"]>;
  candidateIds?: string[];
  actions?: IntegrityRemediationCandidate["action"][];
  onlyFindings?: boolean;
  onlyUnverified?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityRemediationExecutionPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  candidates: IntegrityRemediationExecutionCandidate[];
};
const states: IntegrityRemediationExecutionState[] = [
  "REQUESTED", "IN_PROGRESS", "BLOCKED", "COMPLETED", "FAILED", "CANCELLED",
];
const allowed: Record<IntegrityRemediationExecutionState, IntegrityRemediationExecutionState[]> = {
  REQUESTED: ["IN_PROGRESS", "BLOCKED", "CANCELLED", "FAILED"],
  IN_PROGRESS: ["BLOCKED", "COMPLETED", "FAILED", "CANCELLED"],
  BLOCKED: ["IN_PROGRESS", "FAILED", "CANCELLED"],
  COMPLETED: [],
  FAILED: [],
  CANCELLED: [],
};
function object(value: unknown, label: string) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function string(value: unknown, label: string, max = 1500) {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > max || /[\u0000-\u001f\u007f]/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function time(value: unknown, label: string) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function list(value: unknown, label: string, maximum: number) {
  if (!Array.isArray(value) || value.length > maximum)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value.map(x => string(x, label)))];
}
export function parseIntegrityRemediationExecutionEvents(
  value: unknown,
): IntegrityRemediationExecutionEvent[] {
  if (!Array.isArray(value) || value.length > 50000)
    throw new WorkInputError("INVALID", "Invalid execution event collection.");
  return value.map(entry => {
    const raw = object(entry, "execution event");
    if (Object.keys(raw).some(key => ![
      "eventId", "candidateId", "state", "occurredAt", "actorUserId",
      "evidenceRefs", "reason", "attemptId",
    ].includes(key)))
      throw new WorkInputError("INVALID", "Unknown execution event field.");
    if (!states.includes(raw.state as IntegrityRemediationExecutionState))
      throw new WorkInputError("INVALID", "Invalid execution state.");
    if (typeof raw.reason !== "string" || raw.reason.length > 4000 ||
        /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(raw.reason))
      throw new WorkInputError("INVALID", "Invalid execution reason.");
    return {
      eventId: string(raw.eventId, "execution event ID"),
      candidateId: string(raw.candidateId, "execution candidate ID"),
      state: raw.state as IntegrityRemediationExecutionState,
      occurredAt: time(raw.occurredAt, "execution timestamp"),
      actorUserId: string(raw.actorUserId, "execution actor"),
      evidenceRefs: list(raw.evidenceRefs ?? [], "evidence references", 100),
      reason: raw.reason,
      attemptId: string(raw.attemptId, "execution attempt ID"),
    };
  });
}
function finding(
  event: IntegrityRemediationExecutionEvent,
  code: IntegrityRemediationExecutionIssue,
  explanation: string,
  severity: "ERROR" | "WARNING" = "ERROR",
): IntegrityRemediationExecutionFinding {
  return {
    eventId: event.eventId, candidateId: event.candidateId,
    attemptId: event.attemptId, code, explanation, severity,
  };
}
function isTerminal(state: IntegrityRemediationExecutionState) {
  return state === "COMPLETED" || state === "FAILED" ||
    state === "CANCELLED";
}
function initialAttempt(event: IntegrityRemediationExecutionEvent):
  IntegrityRemediationExecutionAttempt {
  return {
    attemptId: event.attemptId, candidateId: event.candidateId,
    state: event.state, startedAt: event.occurredAt,
    lastChangedAt: event.occurredAt, completedAt: null,
    startedBy: event.actorUserId, lastActor: event.actorUserId,
    evidenceRefs: [...event.evidenceRefs],
    eventIds: [event.eventId], transitions: 0,
    terminal: isTerminal(event.state), reason: event.reason,
  };
}
export function buildIntegrityRemediationExecutionLedger(
  plan: IntegrityRemediationPlan,
  decisions: readonly IntegrityRemediationDecisionRecord[],
  events: readonly IntegrityRemediationExecutionEvent[],
): IntegrityRemediationExecutionLedger {
  const known = new Map(plan.candidates.map(x => [x.id, x]));
  const decisionsByCandidate = new Map(decisions.map(x =>
    [x.candidateId, x.decision]));
  const seenIds = new Set<string>();
  const attempts = new Map<string, IntegrityRemediationExecutionAttempt>();
  const findings: IntegrityRemediationExecutionFinding[] = [];
  const accepted = new Set<string>();
  const sorted = [...events].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) ||
    a.eventId.localeCompare(b.eventId));
  for (const event of sorted) {
    if (seenIds.has(event.eventId)) {
      findings.push(finding(event, "DUPLICATE_EVENT",
        "Execution event ID has already been processed."));
      continue;
    }
    seenIds.add(event.eventId);
    if (!known.has(event.candidateId)) {
      findings.push(finding(event, "UNKNOWN_CANDIDATE",
        "Execution event references an absent remediation candidate."));
      continue;
    }
    const key = JSON.stringify([event.candidateId, event.attemptId]);
    const previous = attempts.get(key);
    if (!previous) {
      if (event.state !== "REQUESTED") {
        findings.push(finding(event, "INVALID_TRANSITION",
          "Execution attempt must begin in REQUESTED state."));
        continue;
      }
      if (decisionsByCandidate.get(event.candidateId) !== "ACCEPT") {
        findings.push(finding(event, "UNAPPROVED_EXECUTION",
          "Execution cannot start without an accepted remediation decision."));
        continue;
      }
      if (accepted.has(event.candidateId)) {
        const others = [...attempts.values()].filter(x =>
          x.candidateId === event.candidateId);
        if (others.some(x => !x.terminal)) {
          findings.push(finding(event, "DUPLICATE_ATTEMPT",
            "A prior execution attempt is still open."));
          continue;
        }
      }
      accepted.add(event.candidateId);
      attempts.set(key, initialAttempt(event));
      continue;
    }
    if (event.occurredAt < previous.lastChangedAt) {
      findings.push(finding(event, "OUT_OF_ORDER",
        "Execution transition predates the previous event."));
      continue;
    }
    if (event.state === previous.state) {
      findings.push(finding(event, "DUPLICATE_TRANSITION",
        "Execution attempt already has this state.", "WARNING"));
      continue;
    }
    if (!allowed[previous.state].includes(event.state)) {
      findings.push(finding(event, "INVALID_TRANSITION",
        "Execution state transition is not permitted."));
      continue;
    }
    if (event.state === "COMPLETED" && event.evidenceRefs.length === 0 &&
        previous.evidenceRefs.length === 0) {
      findings.push(finding(event, "MISSING_EVIDENCE",
        "Completion requires at least one evidence reference."));
      continue;
    }
    if ((event.state === "FAILED" || event.state === "CANCELLED" ||
        event.state === "BLOCKED") && !event.reason.trim()) {
      findings.push(finding(event, "MISSING_REASON",
        "Failure, cancellation and blocking require a reason."));
      continue;
    }
    previous.state = event.state;
    previous.lastChangedAt = event.occurredAt;
    previous.lastActor = event.actorUserId;
    previous.eventIds.push(event.eventId);
    previous.transitions++;
    previous.reason = event.reason;
    previous.evidenceRefs = [...new Set([
      ...previous.evidenceRefs, ...event.evidenceRefs,
    ])].sort();
    previous.terminal = isTerminal(event.state);
    if (event.state === "COMPLETED")
      previous.completedAt = event.occurredAt;
  }
  const candidates: IntegrityRemediationExecutionCandidate[] =
    plan.candidates.map(candidate => {
      const rows = [...attempts.values()].filter(x =>
        x.candidateId === candidate.id).sort((a, b) =>
        a.startedAt.localeCompare(b.startedAt) ||
        a.attemptId.localeCompare(b.attemptId));
      const latest = rows.at(-1);
      const relevant = findings.filter(x => x.candidateId === candidate.id);
      return {
        candidateId: candidate.id, action: candidate.action,
        priority: candidate.priority,
        decision: decisionsByCandidate.get(candidate.id) ?? null,
        currentAttemptId: latest?.attemptId ?? null,
        state: latest?.state ?? "NOT_STARTED",
        attempts: rows,
        hasVerifiedEvidence: false,
        completedAt: latest?.completedAt ?? null,
        findings: relevant,
      };
    });
  const count = (state: IntegrityRemediationExecutionCandidate["state"]) =>
    candidates.filter(x => x.state === state).length;
  return {
    schemaVersion: 1, captureId: plan.captureId,
    candidates, findings,
    totals: {
      candidates: candidates.length,
      notStarted: count("NOT_STARTED"),
      requested: count("REQUESTED"),
      inProgress: count("IN_PROGRESS"),
      blocked: count("BLOCKED"),
      completed: count("COMPLETED"),
      failed: count("FAILED"),
      cancelled: count("CANCELLED"),
      verifiedCompleted: 0,
      unverifiedCompleted: count("COMPLETED"),
      attempts: attempts.size, events: seenIds.size,
      errors: findings.filter(x => x.severity === "ERROR").length,
      warnings: findings.filter(x => x.severity === "WARNING").length,
    },
  };
}
export function verifyIntegrityRemediationExecutionEvidence(
  ledger: IntegrityRemediationExecutionLedger,
  verifiedEvidenceRefs: readonly string[],
): IntegrityRemediationExecutionLedger {
  const trusted = new Set(verifiedEvidenceRefs);
  const candidates = ledger.candidates.map(candidate => {
    const latest = candidate.attempts.at(-1);
    return {
      ...candidate,
      hasVerifiedEvidence: candidate.state === "COMPLETED" &&
        !!latest && latest.evidenceRefs.some(ref => trusted.has(ref)),
    };
  });
  return {
    ...ledger, candidates,
    totals: {
      ...ledger.totals,
      verifiedCompleted: candidates.filter(x =>
        x.state === "COMPLETED" && x.hasVerifiedEvidence).length,
      unverifiedCompleted: candidates.filter(x =>
        x.state === "COMPLETED" && !x.hasVerifiedEvidence).length,
    },
  };
}
export function parseIntegrityRemediationExecutionQuery(
  value: unknown,
): IntegrityRemediationExecutionQuery {
  const raw = object(value, "execution query");
  if (Object.keys(raw).some(key => ![
    "states", "candidateIds", "actions", "onlyFindings",
    "onlyUnverified", "offset", "limit",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown execution query field.");
  for (const key of ["onlyFindings", "onlyUnverified"]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid execution filter.");
  }
  const selectedStates = raw.states === undefined
    ? undefined : list(raw.states, "execution states", 7);
  if (selectedStates?.some(x => x !== "NOT_STARTED" &&
      !states.includes(x as IntegrityRemediationExecutionState)))
    throw new WorkInputError("INVALID", "Unknown execution state.");
  const offset = raw.offset === undefined ? 0 : raw.offset;
  const limit = raw.limit === undefined ? 100 : raw.limit;
  if (!Number.isSafeInteger(offset) || (offset as number) < 0 ||
      !Number.isSafeInteger(limit) || (limit as number) < 1 ||
      (limit as number) > 1000)
    throw new WorkInputError("INVALID", "Invalid execution pagination.");
  return {
    ...(selectedStates !== undefined ? {
      states: selectedStates as NonNullable<IntegrityRemediationExecutionQuery["states"]>,
    } : {}),
    ...(raw.candidateIds !== undefined ? {
      candidateIds: list(raw.candidateIds, "execution candidate IDs", 1000),
    } : {}),
    ...(raw.actions !== undefined ? {
      actions: list(raw.actions, "execution actions", 100),
    } : {}),
    onlyFindings: raw.onlyFindings === true,
    onlyUnverified: raw.onlyUnverified === true,
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityRemediationExecution(
  ledger: IntegrityRemediationExecutionLedger,
  query: IntegrityRemediationExecutionQuery,
): IntegrityRemediationExecutionPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = ledger.candidates.filter(item =>
    (!query.states || query.states.includes(item.state)) &&
    (!query.candidateIds || query.candidateIds.includes(item.candidateId)) &&
    (!query.actions || (item.action !== null &&
      query.actions.includes(item.action))) &&
    (!query.onlyFindings || item.findings.length > 0) &&
    (!query.onlyUnverified || (item.state === "COMPLETED" &&
      !item.hasVerifiedEvidence)));
  return {
    captureId: ledger.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    candidates: selected.slice(offset, offset + limit),
  };
}
export function compareIntegrityRemediationExecutionLedgers(
  before: IntegrityRemediationExecutionLedger,
  after: IntegrityRemediationExecutionLedger,
) {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Execution ledger capture mismatch.");
  const previous = new Map(before.candidates.map(x => [x.candidateId, x]));
  const current = new Map(after.candidates.map(x => [x.candidateId, x]));
  const introduced = after.candidates.filter(x =>
    !previous.has(x.candidateId)).map(x => x.candidateId);
  const resolved = before.candidates.filter(x =>
    !current.has(x.candidateId)).map(x => x.candidateId);
  const transitions = after.candidates.flatMap(x => {
    const old = previous.get(x.candidateId);
    return old && old.state !== x.state
      ? [{ candidateId: x.candidateId, from: old.state, to: x.state }] : [];
  });
  const newlyVerified = after.candidates.filter(x =>
    x.hasVerifiedEvidence &&
    !previous.get(x.candidateId)?.hasVerifiedEvidence)
    .map(x => x.candidateId);
  const verificationLost = before.candidates.filter(x =>
    x.hasVerifiedEvidence &&
    !current.get(x.candidateId)?.hasVerifiedEvidence)
    .map(x => x.candidateId);
  return {
    captureId: before.captureId,
    introduced: introduced.sort(), resolved: resolved.sort(),
    transitions, newlyVerified: newlyVerified.sort(),
    verificationLost: verificationLost.sort(),
    completedDelta: after.totals.completed - before.totals.completed,
    verifiedDelta: after.totals.verifiedCompleted -
      before.totals.verifiedCompleted,
    errorsDelta: after.totals.errors - before.totals.errors,
  };
}
