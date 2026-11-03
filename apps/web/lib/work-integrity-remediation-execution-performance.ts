import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityRemediationExecutionLedger,
  IntegrityRemediationExecutionCandidate,
} from "./work-integrity-remediation-execution";
import type {
  IntegrityExecutionReviewHistory,
  IntegrityExecutionReviewAudit,
} from "./work-integrity-remediation-execution-review";
import type { IntegrityRemediationPlan } from "./work-integrity-remediation-plan";

export type IntegrityExecutionPerformanceWindow = {
  from: string;
  to: string;
  candidateIds: string[];
  started: number;
  completed: number;
  verified: number;
  failed: number;
  blocked: number;
  cancelled: number;
  newFindings: number;
  resolvedFindings: number;
  netCompletions: number;
  verificationRate: number;
  completionRate: number;
  averageAcceptedTransitions: number;
  throughputPerDay: number;
};
export type IntegrityExecutionPerformanceBottleneck = {
  candidateId: string;
  action: string;
  priority: string;
  state: IntegrityRemediationExecutionCandidate["state"];
  attempts: number;
  totalTransitions: number;
  totalActors: number;
  totalEvidenceRefs: number;
  findings: number;
  errors: number;
  warnings: number;
  latestActivityAt: string | null;
  ageSinceActivityMinutes: number | null;
  blockedMinutes: number;
  activeMinutes: number;
  score: number;
  reasons: string[];
};
export type IntegrityExecutionPerformanceActor = {
  actorUserId: string;
  totalEvents: number;
  acceptedEvents: number;
  rejectedEvents: number;
  candidatesTouched: number;
  attemptsTouched: number;
  completionEvents: number;
  blockedEvents: number;
  failureEvents: number;
  evidenceRefsSubmitted: number;
  acceptanceRate: number;
  firstActivityAt: string;
  lastActivityAt: string;
};
export type IntegrityExecutionPerformanceAction = {
  action: string;
  totalCandidates: number;
  started: number;
  completed: number;
  verified: number;
  failed: number;
  blocked: number;
  errors: number;
  averageTransitions: number;
  verificationRate: number;
};
export type IntegrityExecutionPerformanceReport = {
  schemaVersion: 1;
  captureId: string;
  evaluatedAt: string;
  windows: IntegrityExecutionPerformanceWindow[];
  bottlenecks: IntegrityExecutionPerformanceBottleneck[];
  actors: IntegrityExecutionPerformanceActor[];
  actions: IntegrityExecutionPerformanceAction[];
  totals: {
    candidates: number;
    started: number;
    completed: number;
    verified: number;
    failed: number;
    blocked: number;
    errors: number;
    warnings: number;
    acceptedEvents: number;
    rejectedEvents: number;
    actors: number;
    bottlenecks: number;
    averageTransitionsPerStartedCandidate: number;
    verificationRate: number;
    completionRate: number;
    outstandingRisk: number;
  };
};
export type IntegrityExecutionPerformanceQuery = {
  actions?: string[];
  priorities?: string[];
  states?: string[];
  minimumScore?: number;
  onlyUnverified?: boolean;
  onlyBlocked?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityExecutionPerformancePage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  bottlenecks: IntegrityExecutionPerformanceBottleneck[];
};
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid performance query.");
  return value as Record<string, unknown>;
}
function list(value: unknown, label: string) {
  if (!Array.isArray(value) || value.length > 1000 ||
      value.some(x => typeof x !== "string" || !x.length ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
function timestamp(value: string) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value)
    throw new WorkInputError("INVALID", "Invalid performance evaluation timestamp.");
  return value;
}
function duration(from: string, to: string) {
  return Math.max(0, Math.floor((Date.parse(to) - Date.parse(from)) / 60000));
}
function candidateTransitions(candidate: IntegrityRemediationExecutionCandidate) {
  return candidate.attempts.reduce((sum, attempt) =>
    sum + attempt.transitions, 0);
}
function latestActivity(candidate: IntegrityRemediationExecutionCandidate) {
  return candidate.attempts.map(x => x.lastChangedAt).sort().at(-1) ?? null;
}
function uniqueActors(candidate: IntegrityRemediationExecutionCandidate,
  audit: IntegrityExecutionReviewAudit) {
  return new Set(audit.timeline.filter(x =>
    x.candidateId === candidate.candidateId && x.accepted)
    .map(x => x.actorUserId)).size;
}
function riskScore(
  candidate: IntegrityRemediationExecutionCandidate,
  now: string,
  audit: IntegrityExecutionReviewAudit,
): IntegrityExecutionPerformanceBottleneck {
  const attempts = candidate.attempts;
  const latest = latestActivity(candidate);
  const age = latest === null ? null : duration(latest, now);
  const evidence = new Set(attempts.flatMap(x => x.evidenceRefs));
  const errors = candidate.findings.filter(x => x.severity === "ERROR").length;
  const warnings = candidate.findings.filter(x =>
    x.severity === "WARNING").length;
  const transitions = candidateTransitions(candidate);
  const blockedMinutes = attempts.filter(x => x.state === "BLOCKED")
    .reduce((sum, x) => sum + duration(x.lastChangedAt, now), 0);
  const activeMinutes = attempts.filter(x => x.state === "IN_PROGRESS")
    .reduce((sum, x) => sum + duration(x.lastChangedAt, now), 0);
  const reasons: string[] = [];
  if (candidate.state === "BLOCKED") reasons.push("BLOCKED");
  if (candidate.state === "FAILED") reasons.push("FAILED");
  if (candidate.state === "COMPLETED" &&
      !candidate.hasVerifiedEvidence) reasons.push("UNVERIFIED_COMPLETION");
  if (errors > 0) reasons.push("EXECUTION_ERRORS");
  if (warnings > 0) reasons.push("EXECUTION_WARNINGS");
  if (age !== null && age >= 1440 &&
      candidate.state !== "COMPLETED" &&
      candidate.state !== "CANCELLED") reasons.push("STALE_ACTIVITY");
  if (attempts.length > 1) reasons.push("REPEATED_ATTEMPTS");
  if (candidate.state === "NOT_STARTED") reasons.push("NOT_STARTED");
  const priorityWeight = ({
    P0: 40, P1: 30, P2: 20, P3: 10,
  } as Record<string, number>)[candidate.priority ?? ""] ?? 0;
  const score = priorityWeight +
    (candidate.state === "BLOCKED" ? 40 : 0) +
    (candidate.state === "FAILED" ? 35 : 0) +
    (candidate.state === "COMPLETED" &&
      !candidate.hasVerifiedEvidence ? 25 : 0) +
    errors * 12 + warnings * 4 +
    Math.min(25, Math.floor((age ?? 0) / 1440) * 3) +
    Math.min(20, Math.max(0, attempts.length - 1) * 5);
  return {
    candidateId: candidate.candidateId,
    action: candidate.action ?? "UNKNOWN",
    priority: candidate.priority ?? "UNKNOWN",
    state: candidate.state, attempts: attempts.length,
    totalTransitions: transitions,
    totalActors: uniqueActors(candidate, audit),
    totalEvidenceRefs: evidence.size,
    findings: candidate.findings.length, errors, warnings,
    latestActivityAt: latest, ageSinceActivityMinutes: age,
    blockedMinutes, activeMinutes, score, reasons,
  };
}
function performanceWindow(
  history: IntegrityExecutionReviewHistory,
  index: number,
): IntegrityExecutionPerformanceWindow {
  const current = history.checkpoints[index]!;
  const previous = history.checkpoints[index - 1];
  const before = previous?.ledger;
  const after = current.ledger;
  const changes = current.changes;
  const started = changes.filter(x => x.kind === "STARTED").length;
  const completed = after.candidates.filter(x => x.state === "COMPLETED" &&
    before?.candidates.find(y => y.candidateId === x.candidateId)
      ?.state !== "COMPLETED").length;
  const failed = after.candidates.filter(x => x.state === "FAILED" &&
    before?.candidates.find(y => y.candidateId === x.candidateId)
      ?.state !== "FAILED").length;
  const blocked = after.candidates.filter(x => x.state === "BLOCKED" &&
    before?.candidates.find(y => y.candidateId === x.candidateId)
      ?.state !== "BLOCKED").length;
  const cancelled = after.candidates.filter(x => x.state === "CANCELLED" &&
    before?.candidates.find(y => y.candidateId === x.candidateId)
      ?.state !== "CANCELLED").length;
  const verified = changes.filter(x => x.kind === "VERIFIED").length;
  const from = previous?.at ?? current.at;
  const to = current.at;
  const days = Math.max(1, (Date.parse(to) - Date.parse(from)) / 86400000);
  const touched = [...new Set(changes.map(x => x.candidateId))].sort();
  const acceptedTransitions = touched.map(id =>
    after.candidates.find(x => x.candidateId === id))
    .filter((x): x is IntegrityRemediationExecutionCandidate => !!x)
    .map(candidateTransitions);
  return {
    from, to, candidateIds: touched,
    started, completed, verified, failed, blocked, cancelled,
    newFindings: changes.filter(x => x.kind === "NEW_FINDING").length,
    resolvedFindings: changes.filter(x => x.kind === "FINDING_RESOLVED").length,
    netCompletions: after.totals.completed - (before?.totals.completed ?? 0),
    verificationRate: after.totals.completed
      ? after.totals.verifiedCompleted / after.totals.completed : 1,
    completionRate: after.totals.candidates
      ? after.totals.completed / after.totals.candidates : 1,
    averageAcceptedTransitions: acceptedTransitions.length
      ? acceptedTransitions.reduce((sum, x) => sum + x, 0) /
        acceptedTransitions.length : 0,
    throughputPerDay: completed / days,
  };
}
function actorMetrics(
  audit: IntegrityExecutionReviewAudit,
): IntegrityExecutionPerformanceActor[] {
  return audit.actors.map(actor => {
    const events = audit.timeline.filter(x =>
      x.actorUserId === actor.actorUserId);
    const accepted = events.filter(x => x.accepted);
    return {
      actorUserId: actor.actorUserId,
      totalEvents: actor.totalEvents,
      acceptedEvents: actor.acceptedEvents,
      rejectedEvents: actor.rejectedEvents,
      candidatesTouched: actor.candidates.length,
      attemptsTouched: actor.attempts.length,
      completionEvents: accepted.filter(x => x.state === "COMPLETED").length,
      blockedEvents: accepted.filter(x => x.state === "BLOCKED").length,
      failureEvents: accepted.filter(x => x.state === "FAILED").length,
      evidenceRefsSubmitted: new Set(accepted.flatMap(x =>
        x.evidenceRefs)).size,
      acceptanceRate: actor.totalEvents
        ? actor.acceptedEvents / actor.totalEvents : 1,
      firstActivityAt: actor.firstAt, lastActivityAt: actor.lastAt,
    };
  }).sort((a, b) => b.acceptedEvents - a.acceptedEvents ||
    a.actorUserId.localeCompare(b.actorUserId));
}
function actionMetrics(
  ledger: IntegrityRemediationExecutionLedger,
): IntegrityExecutionPerformanceAction[] {
  const groups = new Map<string, IntegrityRemediationExecutionCandidate[]>();
  for (const candidate of ledger.candidates) {
    const key = candidate.action ?? "UNKNOWN";
    const rows = groups.get(key) ?? [];
    rows.push(candidate);
    groups.set(key, rows);
  }
  return [...groups].map(([action, rows]) => {
    const started = rows.filter(x => x.state !== "NOT_STARTED").length;
    const completed = rows.filter(x => x.state === "COMPLETED").length;
    const verified = rows.filter(x => x.hasVerifiedEvidence).length;
    return {
      action, totalCandidates: rows.length, started, completed, verified,
      failed: rows.filter(x => x.state === "FAILED").length,
      blocked: rows.filter(x => x.state === "BLOCKED").length,
      errors: rows.reduce((sum, x) => sum + x.findings.filter(f =>
        f.severity === "ERROR").length, 0),
      averageTransitions: started
        ? rows.reduce((sum, x) => sum + candidateTransitions(x), 0) /
          started : 0,
      verificationRate: completed ? verified / completed : 1,
    };
  }).sort((a, b) => b.totalCandidates - a.totalCandidates ||
    a.action.localeCompare(b.action));
}
export function evaluateIntegrityExecutionPerformance(
  ledger: IntegrityRemediationExecutionLedger,
  history: IntegrityExecutionReviewHistory,
  audit: IntegrityExecutionReviewAudit,
  evaluatedAt: string,
): IntegrityExecutionPerformanceReport {
  timestamp(evaluatedAt);
  if (ledger.captureId !== history.captureId ||
      ledger.captureId !== audit.captureId)
    throw new WorkInputError("INVALID", "Performance capture mismatch.");
  const bottlenecks = ledger.candidates.map(x =>
    riskScore(x, evaluatedAt, audit)).sort((a, b) =>
    b.score - a.score || a.candidateId.localeCompare(b.candidateId));
  const actors = actorMetrics(audit);
  const actions = actionMetrics(ledger);
  const started = ledger.totals.candidates - ledger.totals.notStarted;
  return {
    schemaVersion: 1, captureId: ledger.captureId, evaluatedAt,
    windows: history.checkpoints.map((_, index) =>
      performanceWindow(history, index)),
    bottlenecks, actors, actions,
    totals: {
      candidates: ledger.totals.candidates, started,
      completed: ledger.totals.completed,
      verified: ledger.totals.verifiedCompleted,
      failed: ledger.totals.failed, blocked: ledger.totals.blocked,
      errors: ledger.totals.errors, warnings: ledger.totals.warnings,
      acceptedEvents: audit.totals.accepted,
      rejectedEvents: audit.totals.rejected,
      actors: actors.length,
      bottlenecks: bottlenecks.filter(x => x.reasons.length > 0).length,
      averageTransitionsPerStartedCandidate: started
        ? ledger.candidates.reduce((sum, x) =>
          sum + candidateTransitions(x), 0) / started : 0,
      verificationRate: ledger.totals.completed
        ? ledger.totals.verifiedCompleted / ledger.totals.completed : 1,
      completionRate: ledger.totals.candidates
        ? ledger.totals.completed / ledger.totals.candidates : 1,
      outstandingRisk: bottlenecks.filter(x =>
        x.state !== "COMPLETED" || x.reasons.includes("UNVERIFIED_COMPLETION"))
        .reduce((sum, x) => sum + x.score, 0),
    },
  };
}
export function parseIntegrityExecutionPerformanceQuery(
  value: unknown,
): IntegrityExecutionPerformanceQuery {
  const raw = object(value);
  if (Object.keys(raw).some(x => ![
    "actions", "priorities", "states", "minimumScore",
    "onlyUnverified", "onlyBlocked", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown performance query field.");
  for (const key of ["onlyUnverified", "onlyBlocked"]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid performance boolean.");
  }
  const minimumScore = raw.minimumScore ?? 0;
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 100;
  if (!Number.isFinite(minimumScore) || (minimumScore as number) < 0 ||
      (minimumScore as number) > 1000000 ||
      !Number.isSafeInteger(offset) || (offset as number) < 0 ||
      (offset as number) > 1000000 ||
      !Number.isSafeInteger(limit) || (limit as number) < 1 ||
      (limit as number) > 1000)
    throw new WorkInputError("INVALID", "Invalid performance query bounds.");
  return {
    ...(raw.actions !== undefined ? {
      actions: list(raw.actions, "performance actions"),
    } : {}),
    ...(raw.priorities !== undefined ? {
      priorities: list(raw.priorities, "performance priorities"),
    } : {}),
    ...(raw.states !== undefined ? {
      states: list(raw.states, "performance states"),
    } : {}),
    minimumScore: minimumScore as number,
    onlyUnverified: raw.onlyUnverified === true,
    onlyBlocked: raw.onlyBlocked === true,
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityExecutionPerformance(
  report: IntegrityExecutionPerformanceReport,
  query: IntegrityExecutionPerformanceQuery,
): IntegrityExecutionPerformancePage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.bottlenecks.filter(row =>
    (!query.actions || query.actions.includes(row.action)) &&
    (!query.priorities || query.priorities.includes(row.priority)) &&
    (!query.states || query.states.includes(row.state)) &&
    row.score >= (query.minimumScore ?? 0) &&
    (!query.onlyBlocked || row.state === "BLOCKED") &&
    (!query.onlyUnverified || row.reasons.includes("UNVERIFIED_COMPLETION")));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    bottlenecks: selected.slice(offset, offset + limit),
  };
}
export function compareIntegrityExecutionPerformance(
  before: IntegrityExecutionPerformanceReport,
  after: IntegrityExecutionPerformanceReport,
) {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Performance capture mismatch.");
  const old = new Map(before.bottlenecks.map(x => [x.candidateId, x]));
  const current = new Map(after.bottlenecks.map(x => [x.candidateId, x]));
  const worsened = after.bottlenecks.filter(x =>
    old.has(x.candidateId) && x.score > old.get(x.candidateId)!.score)
    .map(x => ({ candidateId: x.candidateId,
      scoreDelta: x.score - old.get(x.candidateId)!.score }));
  const improved = after.bottlenecks.filter(x =>
    old.has(x.candidateId) && x.score < old.get(x.candidateId)!.score)
    .map(x => ({ candidateId: x.candidateId,
      scoreDelta: x.score - old.get(x.candidateId)!.score }));
  return {
    captureId: before.captureId,
    from: before.evaluatedAt, to: after.evaluatedAt,
    introduced: after.bottlenecks.filter(x =>
      !old.has(x.candidateId)).map(x => x.candidateId),
    removed: before.bottlenecks.filter(x =>
      !current.has(x.candidateId)).map(x => x.candidateId),
    worsened, improved,
    completionRateDelta: after.totals.completionRate -
      before.totals.completionRate,
    verificationRateDelta: after.totals.verificationRate -
      before.totals.verificationRate,
    outstandingRiskDelta: after.totals.outstandingRisk -
      before.totals.outstandingRisk,
    blockedDelta: after.totals.blocked - before.totals.blocked,
    failedDelta: after.totals.failed - before.totals.failed,
  };
}
