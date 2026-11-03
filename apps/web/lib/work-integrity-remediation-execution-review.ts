import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityRemediationExecutionEvent,
  IntegrityRemediationExecutionLedger,
  IntegrityRemediationExecutionCandidate,
  IntegrityRemediationExecutionFinding,
  IntegrityRemediationExecutionState,
} from "./work-integrity-remediation-execution";
import type { IntegrityRemediationPlan } from "./work-integrity-remediation-plan";
import type { IntegrityRemediationDecisionRecord } from "./work-integrity-remediation-workspace";
import {
  buildIntegrityRemediationExecutionLedger,
  verifyIntegrityRemediationExecutionEvidence,
} from "./work-integrity-remediation-execution";

export type IntegrityExecutionReviewCheckpoint = {
  at: string;
  ledger: IntegrityRemediationExecutionLedger;
  changes: IntegrityExecutionReviewChange[];
  totals: IntegrityExecutionReviewTotals;
};
export type IntegrityExecutionReviewChangeKind =
  | "INTRODUCED" | "REMOVED" | "STARTED" | "STATE_CHANGED"
  | "VERIFIED" | "VERIFICATION_LOST" | "NEW_FINDING" | "FINDING_RESOLVED";
export type IntegrityExecutionReviewChange = {
  kind: IntegrityExecutionReviewChangeKind;
  candidateId: string;
  from: string | null;
  to: string | null;
  at: string;
  findingCode: string | null;
};
export type IntegrityExecutionReviewTotals = {
  candidates: number;
  started: number;
  completed: number;
  verified: number;
  pending: number;
  blocked: number;
  failed: number;
  cancelled: number;
  findings: number;
  errors: number;
  warnings: number;
  newFindings: number;
  resolvedFindings: number;
  newlyVerified: number;
  verificationLost: number;
  transitions: number;
};
export type IntegrityExecutionReviewHistory = {
  schemaVersion: 1;
  captureId: string;
  checkpoints: IntegrityExecutionReviewCheckpoint[];
  final: IntegrityRemediationExecutionLedger;
  summary: {
    checkpointCount: number;
    firstAt: string;
    lastAt: string;
    peakInProgress: number;
    peakBlocked: number;
    peakErrors: number;
    peakUnverifiedCompletions: number;
    firstVerifiedAt: string | null;
    lastVerifiedAt: string | null;
    totalTransitions: number;
    totalRegressions: number;
    totalImprovements: number;
    currentVerificationRate: number;
  };
};
export type IntegrityExecutionReviewEventLine = {
  eventId: string;
  candidateId: string;
  attemptId: string;
  state: IntegrityRemediationExecutionState;
  occurredAt: string;
  actorUserId: string;
  evidenceRefs: string[];
  accepted: boolean;
  findingCodes: string[];
  ordinal: number;
};
export type IntegrityExecutionReviewActor = {
  actorUserId: string;
  totalEvents: number;
  acceptedEvents: number;
  rejectedEvents: number;
  candidates: string[];
  attempts: string[];
  firstAt: string;
  lastAt: string;
  stateChanges: Record<IntegrityRemediationExecutionState, number>;
};
export type IntegrityExecutionReviewAttempt = {
  attemptId: string;
  candidateId: string;
  events: IntegrityExecutionReviewEventLine[];
  startedAt: string | null;
  lastAt: string | null;
  latestState: IntegrityRemediationExecutionState | null;
  acceptedEvents: number;
  rejectedEvents: number;
  actors: string[];
  evidenceRefs: string[];
  findingCodes: string[];
};
export type IntegrityExecutionReviewAudit = {
  schemaVersion: 1;
  captureId: string;
  timeline: IntegrityExecutionReviewEventLine[];
  actors: IntegrityExecutionReviewActor[];
  attempts: IntegrityExecutionReviewAttempt[];
  unmatchedFindings: IntegrityRemediationExecutionFinding[];
  totals: {
    events: number;
    accepted: number;
    rejected: number;
    actors: number;
    attempts: number;
    evidenceReferences: number;
    findings: number;
  };
};
export type IntegrityExecutionReviewQuery = {
  candidateIds?: string[];
  actorUserIds?: string[];
  attemptIds?: string[];
  states?: IntegrityRemediationExecutionState[];
  accepted?: boolean;
  from?: string;
  to?: string;
  offset?: number;
  limit?: number;
};
export type IntegrityExecutionReviewPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  events: IntegrityExecutionReviewEventLine[];
};
export type IntegrityExecutionReviewCase = {
  caseKey: string;
  candidateIds: string[];
  total: number;
  notStarted: number;
  inProgress: number;
  completed: number;
  verified: number;
  blocked: number;
  failed: number;
  errorCount: number;
  latestChangeAt: string | null;
};
export type IntegrityExecutionReviewWork = {
  workItemId: string;
  candidateIds: string[];
  total: number;
  completed: number;
  verified: number;
  blocked: number;
  failed: number;
  errorCount: number;
  latestChangeAt: string | null;
};
export type IntegrityExecutionReviewMatrix = {
  captureId: string;
  cases: IntegrityExecutionReviewCase[];
  workItems: IntegrityExecutionReviewWork[];
  unassignedCandidateIds: string[];
  totals: {
    cases: number;
    workItems: number;
    unassigned: number;
    affectedCases: number;
    affectedWorkItems: number;
  };
};
function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function timestamp(value: unknown, label: string) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value;
}
function strings(value: unknown, label: string, max = 1000) {
  if (!Array.isArray(value) || value.length > max ||
      value.some(x => typeof x !== "string" || x.length < 1 ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
function findingKey(finding: IntegrityRemediationExecutionFinding) {
  return JSON.stringify([
    finding.candidateId, finding.attemptId, finding.eventId, finding.code,
  ]);
}
function changes(
  before: IntegrityRemediationExecutionLedger | null,
  after: IntegrityRemediationExecutionLedger,
  at: string,
): IntegrityExecutionReviewChange[] {
  if (!before) return after.candidates.map(candidate => ({
    kind: "INTRODUCED", candidateId: candidate.candidateId,
    from: null, to: candidate.state, at, findingCode: null,
  }));
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Execution history capture mismatch.");
  const previous = new Map(before.candidates.map(x => [x.candidateId, x]));
  const current = new Map(after.candidates.map(x => [x.candidateId, x]));
  const output: IntegrityExecutionReviewChange[] = [];
  for (const candidate of after.candidates) {
    const old = previous.get(candidate.candidateId);
    if (!old) {
      output.push({
        kind: "INTRODUCED", candidateId: candidate.candidateId,
        from: null, to: candidate.state, at, findingCode: null,
      });
      continue;
    }
    if (old.state !== candidate.state) {
      output.push({
        kind: old.state === "NOT_STARTED" ? "STARTED" : "STATE_CHANGED",
        candidateId: candidate.candidateId,
        from: old.state, to: candidate.state, at, findingCode: null,
      });
    }
    if (old.hasVerifiedEvidence !== candidate.hasVerifiedEvidence) {
      output.push({
        kind: candidate.hasVerifiedEvidence ? "VERIFIED" : "VERIFICATION_LOST",
        candidateId: candidate.candidateId,
        from: String(old.hasVerifiedEvidence),
        to: String(candidate.hasVerifiedEvidence), at, findingCode: null,
      });
    }
  }
  for (const old of before.candidates) {
    if (!current.has(old.candidateId))
      output.push({
        kind: "REMOVED", candidateId: old.candidateId,
        from: old.state, to: null, at, findingCode: null,
      });
  }
  const oldFindings = new Map(before.findings.map(x => [findingKey(x), x]));
  const newFindings = new Map(after.findings.map(x => [findingKey(x), x]));
  for (const [key, finding] of newFindings) {
    if (!oldFindings.has(key))
      output.push({
        kind: "NEW_FINDING", candidateId: finding.candidateId,
        from: null, to: finding.severity, at, findingCode: finding.code,
      });
  }
  for (const [key, finding] of oldFindings) {
    if (!newFindings.has(key))
      output.push({
        kind: "FINDING_RESOLVED", candidateId: finding.candidateId,
        from: finding.severity, to: null, at, findingCode: finding.code,
      });
  }
  return output.sort((a, b) =>
    a.candidateId.localeCompare(b.candidateId) ||
    a.kind.localeCompare(b.kind) ||
    (a.findingCode ?? "").localeCompare(b.findingCode ?? ""));
}
function reviewTotals(
  ledger: IntegrityRemediationExecutionLedger,
  delta: IntegrityExecutionReviewChange[],
): IntegrityExecutionReviewTotals {
  return {
    candidates: ledger.totals.candidates,
    started: ledger.totals.candidates - ledger.totals.notStarted,
    completed: ledger.totals.completed,
    verified: ledger.totals.verifiedCompleted,
    pending: ledger.totals.notStarted + ledger.totals.requested +
      ledger.totals.inProgress,
    blocked: ledger.totals.blocked,
    failed: ledger.totals.failed,
    cancelled: ledger.totals.cancelled,
    findings: ledger.findings.length,
    errors: ledger.totals.errors, warnings: ledger.totals.warnings,
    newFindings: delta.filter(x => x.kind === "NEW_FINDING").length,
    resolvedFindings: delta.filter(x => x.kind === "FINDING_RESOLVED").length,
    newlyVerified: delta.filter(x => x.kind === "VERIFIED").length,
    verificationLost: delta.filter(x => x.kind === "VERIFICATION_LOST").length,
    transitions: delta.filter(x => x.kind === "STARTED" ||
      x.kind === "STATE_CHANGED").length,
  };
}
export function buildIntegrityExecutionReviewHistory(
  plan: IntegrityRemediationPlan,
  decisions: readonly IntegrityRemediationDecisionRecord[],
  events: readonly IntegrityRemediationExecutionEvent[],
  checkpointTimes: readonly string[],
  verifiedEvidenceRefs: readonly string[] = [],
): IntegrityExecutionReviewHistory {
  if (!Array.isArray(checkpointTimes) || checkpointTimes.length < 1 ||
      checkpointTimes.length > 366)
    throw new WorkInputError("INVALID", "Invalid execution checkpoints.");
  const checkpoints = [...new Set(checkpointTimes.map(x =>
    timestamp(x, "execution checkpoint")))].sort();
  const sortedEvents = [...events].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) ||
    a.eventId.localeCompare(b.eventId));
  const output: IntegrityExecutionReviewCheckpoint[] = [];
  let previous: IntegrityRemediationExecutionLedger | null = null;
  for (const at of checkpoints) {
    const included = sortedEvents.filter(x => x.occurredAt <= at);
    const ledger = verifyIntegrityRemediationExecutionEvidence(
      buildIntegrityRemediationExecutionLedger(plan, decisions, included),
      verifiedEvidenceRefs);
    const delta = changes(previous, ledger, at);
    output.push({ at, ledger, changes: delta, totals: reviewTotals(ledger, delta) });
    previous = ledger;
  }
  const final = output[output.length - 1]!.ledger;
  const allChanges = output.flatMap(x => x.changes);
  const verified = allChanges.filter(x => x.kind === "VERIFIED");
  const improvements = allChanges.filter(x =>
    x.kind === "VERIFIED" || x.kind === "FINDING_RESOLVED");
  const regressions = allChanges.filter(x =>
    x.kind === "VERIFICATION_LOST" || x.kind === "NEW_FINDING");
  return {
    schemaVersion: 1, captureId: plan.captureId,
    checkpoints: output, final,
    summary: {
      checkpointCount: output.length,
      firstAt: checkpoints[0]!, lastAt: checkpoints[checkpoints.length - 1]!,
      peakInProgress: Math.max(...output.map(x => x.ledger.totals.inProgress)),
      peakBlocked: Math.max(...output.map(x => x.totals.blocked)),
      peakErrors: Math.max(...output.map(x => x.totals.errors)),
      peakUnverifiedCompletions: Math.max(...output.map(x =>
        x.ledger.totals.unverifiedCompleted)),
      firstVerifiedAt: verified[0]?.at ?? null,
      lastVerifiedAt: verified.at(-1)?.at ?? null,
      totalTransitions: output.reduce((sum, x) => sum + x.totals.transitions, 0),
      totalRegressions: regressions.length,
      totalImprovements: improvements.length,
      currentVerificationRate: final.totals.completed
        ? final.totals.verifiedCompleted / final.totals.completed : 1,
    },
  };
}
export function buildIntegrityExecutionReviewAudit(
  ledger: IntegrityRemediationExecutionLedger,
  events: readonly IntegrityRemediationExecutionEvent[],
): IntegrityExecutionReviewAudit {
  const findings = new Map<string, IntegrityRemediationExecutionFinding[]>();
  for (const finding of ledger.findings) {
    const group = findings.get(finding.eventId) ?? [];
    group.push(finding);
    findings.set(finding.eventId, group);
  }
  const acceptedIds = new Set(ledger.candidates.flatMap(candidate =>
    candidate.attempts.flatMap(attempt => attempt.eventIds)));
  const timeline = [...events].sort((a, b) =>
    a.occurredAt.localeCompare(b.occurredAt) ||
    a.eventId.localeCompare(b.eventId)).map((event, ordinal) => ({
    eventId: event.eventId, candidateId: event.candidateId,
    attemptId: event.attemptId, state: event.state,
    occurredAt: event.occurredAt, actorUserId: event.actorUserId,
    evidenceRefs: [...event.evidenceRefs],
    accepted: acceptedIds.has(event.eventId),
    findingCodes: (findings.get(event.eventId) ?? []).map(x => x.code),
    ordinal,
  }));
  const actorsById = new Map<string, IntegrityExecutionReviewEventLine[]>();
  const attemptsById = new Map<string, IntegrityExecutionReviewEventLine[]>();
  for (const event of timeline) {
    const actorRows = actorsById.get(event.actorUserId) ?? [];
    actorRows.push(event);
    actorsById.set(event.actorUserId, actorRows);
    const key = JSON.stringify([event.candidateId, event.attemptId]);
    const attemptRows = attemptsById.get(key) ?? [];
    attemptRows.push(event);
    attemptsById.set(key, attemptRows);
  }
  const actors: IntegrityExecutionReviewActor[] = [...actorsById].map(
    ([actorUserId, rows]) => ({
      actorUserId, totalEvents: rows.length,
      acceptedEvents: rows.filter(x => x.accepted).length,
      rejectedEvents: rows.filter(x => !x.accepted).length,
      candidates: [...new Set(rows.map(x => x.candidateId))].sort(),
      attempts: [...new Set(rows.map(x => x.attemptId))].sort(),
      firstAt: rows[0]!.occurredAt,
      lastAt: rows[rows.length - 1]!.occurredAt,
      stateChanges: Object.fromEntries([
        "REQUESTED", "IN_PROGRESS", "BLOCKED",
        "COMPLETED", "FAILED", "CANCELLED",
      ].map(state => [state, rows.filter(x =>
        x.accepted && x.state === state).length])) as Record<
          IntegrityRemediationExecutionState, number>,
    })).sort((a, b) => b.totalEvents - a.totalEvents ||
      a.actorUserId.localeCompare(b.actorUserId));
  const attempts: IntegrityExecutionReviewAttempt[] = [...attemptsById].map(
    ([, rows]) => {
      const accepted = rows.filter(x => x.accepted);
      const latest = accepted.at(-1);
      return {
        attemptId: rows[0]!.attemptId, candidateId: rows[0]!.candidateId,
        events: rows, startedAt: accepted[0]?.occurredAt ?? null,
        lastAt: latest?.occurredAt ?? null,
        latestState: latest?.state ?? null,
        acceptedEvents: accepted.length,
        rejectedEvents: rows.length - accepted.length,
        actors: [...new Set(rows.map(x => x.actorUserId))].sort(),
        evidenceRefs: [...new Set(accepted.flatMap(x => x.evidenceRefs))].sort(),
        findingCodes: [...new Set(rows.flatMap(x => x.findingCodes))].sort(),
      };
    }).sort((a, b) => a.candidateId.localeCompare(b.candidateId) ||
      a.attemptId.localeCompare(b.attemptId));
  const allRefs = new Set(timeline.flatMap(x => x.evidenceRefs));
  return {
    schemaVersion: 1, captureId: ledger.captureId,
    timeline, actors, attempts,
    unmatchedFindings: ledger.findings.filter(x =>
      !timeline.some(event => event.eventId === x.eventId)),
    totals: {
      events: timeline.length,
      accepted: timeline.filter(x => x.accepted).length,
      rejected: timeline.filter(x => !x.accepted).length,
      actors: actors.length, attempts: attempts.length,
      evidenceReferences: allRefs.size, findings: ledger.findings.length,
    },
  };
}
export function parseIntegrityExecutionReviewQuery(
  value: unknown,
): IntegrityExecutionReviewQuery {
  const raw = object(value, "execution review query");
  if (Object.keys(raw).some(x => ![
    "candidateIds", "actorUserIds", "attemptIds", "states",
    "accepted", "from", "to", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown execution review query field.");
  const states = raw.states === undefined
    ? undefined : strings(raw.states, "execution review states", 6);
  const allowedStates = [
    "REQUESTED", "IN_PROGRESS", "BLOCKED",
    "COMPLETED", "FAILED", "CANCELLED",
  ];
  if (states?.some(x => !allowedStates.includes(x)))
    throw new WorkInputError("INVALID", "Invalid execution review state.");
  if (raw.accepted !== undefined && typeof raw.accepted !== "boolean")
    throw new WorkInputError("INVALID", "Invalid accepted filter.");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 100;
  if (!Number.isSafeInteger(offset) || (offset as number) < 0 ||
      (offset as number) > 1000000 ||
      !Number.isSafeInteger(limit) || (limit as number) < 1 ||
      (limit as number) > 1000)
    throw new WorkInputError("INVALID", "Invalid review pagination.");
  const from = raw.from === undefined ? undefined :
    timestamp(raw.from, "execution review from");
  const to = raw.to === undefined ? undefined :
    timestamp(raw.to, "execution review to");
  if (from && to && from > to)
    throw new WorkInputError("INVALID", "Execution review range reversed.");
  return {
    ...(raw.candidateIds !== undefined ? {
      candidateIds: strings(raw.candidateIds, "candidate IDs"),
    } : {}),
    ...(raw.actorUserIds !== undefined ? {
      actorUserIds: strings(raw.actorUserIds, "actor IDs"),
    } : {}),
    ...(raw.attemptIds !== undefined ? {
      attemptIds: strings(raw.attemptIds, "attempt IDs"),
    } : {}),
    ...(states !== undefined ? {
      states: states as IntegrityRemediationExecutionState[],
    } : {}),
    ...(raw.accepted !== undefined ? { accepted: raw.accepted as boolean } : {}),
    ...(from !== undefined ? { from } : {}),
    ...(to !== undefined ? { to } : {}),
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityExecutionReview(
  audit: IntegrityExecutionReviewAudit,
  query: IntegrityExecutionReviewQuery,
): IntegrityExecutionReviewPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = audit.timeline.filter(event =>
    (!query.candidateIds || query.candidateIds.includes(event.candidateId)) &&
    (!query.actorUserIds || query.actorUserIds.includes(event.actorUserId)) &&
    (!query.attemptIds || query.attemptIds.includes(event.attemptId)) &&
    (!query.states || query.states.includes(event.state)) &&
    (query.accepted === undefined || query.accepted === event.accepted) &&
    (!query.from || event.occurredAt >= query.from) &&
    (!query.to || event.occurredAt <= query.to));
  return {
    captureId: audit.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    events: selected.slice(offset, offset + limit),
  };
}
function latestChange(candidate: IntegrityRemediationExecutionCandidate) {
  return candidate.attempts.reduce<string | null>((latest, attempt) =>
    latest === null || attempt.lastChangedAt > latest
      ? attempt.lastChangedAt : latest, null);
}
export function buildIntegrityExecutionReviewMatrix(
  ledger: IntegrityRemediationExecutionLedger,
): IntegrityExecutionReviewMatrix {
  const cases = new Map<string, IntegrityRemediationExecutionCandidate[]>();
  const workItems = new Map<string, IntegrityRemediationExecutionCandidate[]>();
  const unassignedCandidateIds: string[] = [];
  for (const candidate of ledger.candidates) {
    const association = candidate.attempts.length;
    void association;
    const planCase = (candidate as IntegrityRemediationExecutionCandidate & {
      caseKey?: string | null;
    }).caseKey;
    const planWork = (candidate as IntegrityRemediationExecutionCandidate & {
      workItemId?: string | null;
    }).workItemId;
    if (planCase) {
      const rows = cases.get(planCase) ?? [];
      rows.push(candidate);
      cases.set(planCase, rows);
    }
    if (planWork) {
      const rows = workItems.get(planWork) ?? [];
      rows.push(candidate);
      workItems.set(planWork, rows);
    }
    if (!planCase && !planWork)
      unassignedCandidateIds.push(candidate.candidateId);
  }
  const count = (rows: IntegrityRemediationExecutionCandidate[],
    state: IntegrityRemediationExecutionCandidate["state"]) =>
    rows.filter(x => x.state === state).length;
  const verified = (rows: IntegrityRemediationExecutionCandidate[]) =>
    rows.filter(x => x.hasVerifiedEvidence).length;
  const errors = (rows: IntegrityRemediationExecutionCandidate[]) =>
    rows.reduce((sum, x) => sum + x.findings.filter(f =>
      f.severity === "ERROR").length, 0);
  const latest = (rows: IntegrityRemediationExecutionCandidate[]) =>
    rows.map(latestChange).filter((x): x is string => x !== null)
      .sort().at(-1) ?? null;
  const caseRows = [...cases].map(([caseKey, rows]) => ({
    caseKey, candidateIds: rows.map(x => x.candidateId).sort(),
    total: rows.length, notStarted: count(rows, "NOT_STARTED"),
    inProgress: count(rows, "IN_PROGRESS"),
    completed: count(rows, "COMPLETED"),
    verified: verified(rows), blocked: count(rows, "BLOCKED"),
    failed: count(rows, "FAILED"), errorCount: errors(rows),
    latestChangeAt: latest(rows),
  })).sort((a, b) => a.caseKey.localeCompare(b.caseKey));
  const workRows = [...workItems].map(([workItemId, rows]) => ({
    workItemId, candidateIds: rows.map(x => x.candidateId).sort(),
    total: rows.length, completed: count(rows, "COMPLETED"),
    verified: verified(rows), blocked: count(rows, "BLOCKED"),
    failed: count(rows, "FAILED"), errorCount: errors(rows),
    latestChangeAt: latest(rows),
  })).sort((a, b) => a.workItemId.localeCompare(b.workItemId));
  return {
    captureId: ledger.captureId, cases: caseRows, workItems: workRows,
    unassignedCandidateIds: unassignedCandidateIds.sort(),
    totals: {
      cases: caseRows.length, workItems: workRows.length,
      unassigned: unassignedCandidateIds.length,
      affectedCases: caseRows.filter(x => x.errorCount ||
        x.blocked || x.failed).length,
      affectedWorkItems: workRows.filter(x => x.errorCount ||
        x.blocked || x.failed).length,
    },
  };
}
