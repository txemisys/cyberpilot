import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import type { IntegrityRemediationPlan } from "./work-integrity-remediation-plan";
import type { IntegrityRemediationDecisionRecord } from "./work-integrity-remediation-workspace";
import type { IntegrityRemediationExecutionEvent } from "./work-integrity-remediation-execution";
import {
  buildIntegrityRemediationExecutionLedger,
} from "./work-integrity-remediation-execution";
import {
  buildIntegrityExecutionReviewAudit,
} from "./work-integrity-remediation-execution-review";
import {
  reconcileIntegrityExecutionEvidence,
} from "./work-integrity-remediation-evidence-provenance";
import {
  evaluateIntegrityExecutionControls,
} from "./work-integrity-remediation-execution-controls";
import {
  evaluateIntegrityExecutionReadiness,
  type IntegrityExecutionReadinessPolicy,
} from "./work-integrity-remediation-execution-readiness";

export type IntegrityExecutionReadinessHistoryCheckpoint = {
  at: string;
  candidates: number;
  approved: number;
  completed: number;
  verified: number;
  withActiveAssociation: number;
  ready: number;
  blocked: number;
  controlErrors: number;
  provenanceErrors: number;
  readinessPercent: number;
  changes: IntegrityExecutionReadinessHistoryChange[];
};
export type IntegrityExecutionReadinessHistoryChangeKind =
  | "CANDIDATE_INTRODUCED" | "CANDIDATE_REMOVED"
  | "BECAME_READY" | "LOST_READINESS"
  | "APPROVAL_GAINED" | "APPROVAL_LOST"
  | "COMPLETED" | "COMPLETION_REVERSED"
  | "VERIFIED" | "VERIFICATION_LOST"
  | "ASSOCIATION_GAINED" | "ASSOCIATION_LOST"
  | "BLOCKER_ADDED" | "BLOCKER_RESOLVED";
export type IntegrityExecutionReadinessHistoryChange = {
  candidateId: string;
  kind: IntegrityExecutionReadinessHistoryChangeKind;
  from: string | null;
  to: string | null;
  at: string;
};
export type IntegrityExecutionReadinessHistory = {
  schemaVersion: 1;
  captureId: string;
  checkpoints: IntegrityExecutionReadinessHistoryCheckpoint[];
  summary: {
    checkpointCount: number;
    firstAt: string;
    lastAt: string;
    initialReady: number;
    finalReady: number;
    peakReady: number;
    peakBlocked: number;
    peakControlErrors: number;
    peakProvenanceErrors: number;
    readinessGains: number;
    readinessRegressions: number;
    associationGains: number;
    associationRegressions: number;
    approvalGains: number;
    blockerAdditions: number;
    blockerResolutions: number;
    netReadyDelta: number;
  };
};
export type IntegrityExecutionReadinessHistoryQuery = {
  candidateIds?: string[];
  kinds?: IntegrityExecutionReadinessHistoryChangeKind[];
  from?: string;
  to?: string;
  offset?: number;
  limit?: number;
};
export type IntegrityExecutionReadinessHistoryPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  changes: IntegrityExecutionReadinessHistoryChange[];
};
const kinds: IntegrityExecutionReadinessHistoryChangeKind[] = [
  "CANDIDATE_INTRODUCED", "CANDIDATE_REMOVED",
  "BECAME_READY", "LOST_READINESS", "APPROVAL_GAINED", "APPROVAL_LOST",
  "COMPLETED", "COMPLETION_REVERSED", "VERIFIED", "VERIFICATION_LOST",
  "ASSOCIATION_GAINED", "ASSOCIATION_LOST",
  "BLOCKER_ADDED", "BLOCKER_RESOLVED",
];
function validTime(value: unknown): value is string {
  return typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}
function validateCheckpoints(checkpoints: readonly string[]) {
  if (!Array.isArray(checkpoints) || checkpoints.length === 0 ||
      checkpoints.length > 100 || checkpoints.some(x => !validTime(x)))
    throw new WorkInputError("INVALID", "Invalid readiness checkpoints.");
  const unique = new Set(checkpoints);
  if (unique.size !== checkpoints.length)
    throw new WorkInputError("INVALID", "Duplicate readiness checkpoint.");
  return [...checkpoints].sort();
}
type SnapshotRow = {
  candidateId: string;
  ready: boolean;
  approved: boolean;
  completed: boolean;
  verified: boolean;
  active: boolean;
  blockers: string[];
};
function change(
  candidateId: string,
  kind: IntegrityExecutionReadinessHistoryChangeKind,
  at: string,
  from: string | null,
  to: string | null,
): IntegrityExecutionReadinessHistoryChange {
  return { candidateId, kind, from, to, at };
}
function diffSnapshots(
  previous: Map<string, SnapshotRow>,
  current: Map<string, SnapshotRow>,
  at: string,
): IntegrityExecutionReadinessHistoryChange[] {
  const changes: IntegrityExecutionReadinessHistoryChange[] = [];
  const all = [...new Set([...previous.keys(), ...current.keys()])].sort();
  for (const id of all) {
    const before = previous.get(id);
    const after = current.get(id);
    if (!before && after) {
      changes.push(change(id, "CANDIDATE_INTRODUCED", at, null, id));
      if (after.ready) changes.push(change(id, "BECAME_READY", at, "false", "true"));
      continue;
    }
    if (before && !after) {
      changes.push(change(id, "CANDIDATE_REMOVED", at, id, null));
      if (before.ready) changes.push(change(id, "LOST_READINESS", at, "true", "false"));
      continue;
    }
    if (!before || !after) continue;
    const flags = [
      ["ready", "BECAME_READY", "LOST_READINESS"],
      ["approved", "APPROVAL_GAINED", "APPROVAL_LOST"],
      ["completed", "COMPLETED", "COMPLETION_REVERSED"],
      ["verified", "VERIFIED", "VERIFICATION_LOST"],
      ["active", "ASSOCIATION_GAINED", "ASSOCIATION_LOST"],
    ] as const;
    for (const [key, gained, lost] of flags) {
      if (before[key] !== after[key])
        changes.push(change(id, after[key] ? gained : lost, at,
          String(before[key]), String(after[key])));
    }
    for (const blocker of after.blockers) {
      if (!before.blockers.includes(blocker))
        changes.push(change(id, "BLOCKER_ADDED", at, null, blocker));
    }
    for (const blocker of before.blockers) {
      if (!after.blockers.includes(blocker))
        changes.push(change(id, "BLOCKER_RESOLVED", at, blocker, null));
    }
  }
  return changes;
}
export function buildIntegrityExecutionReadinessHistory(
  plan: IntegrityRemediationPlan,
  decisions: readonly IntegrityRemediationDecisionRecord[],
  events: readonly IntegrityRemediationExecutionEvent[],
  linkHistory: readonly IntegrityLinkHistoryEvent[],
  checkpoints: readonly string[],
  policy: IntegrityExecutionReadinessPolicy,
): IntegrityExecutionReadinessHistory {
  const times = validateCheckpoints(checkpoints);
  const results: IntegrityExecutionReadinessHistoryCheckpoint[] = [];
  let previous = new Map<string, SnapshotRow>();
  for (const at of times) {
    const asOfDecisions = decisions.filter(x => x.reviewedAt <= at);
    const asOfEvents = events.filter(x => x.occurredAt <= at);
    const asOfLinks = linkHistory.filter(x => x.occurredAt <= at);
    const ledger = buildIntegrityRemediationExecutionLedger(
      plan, asOfDecisions, asOfEvents);
    const audit = buildIntegrityExecutionReviewAudit(ledger, asOfEvents);
    const provenance = reconcileIntegrityExecutionEvidence(
      plan, ledger, audit, asOfEvents, asOfLinks);
    const controls = evaluateIntegrityExecutionControls(
      plan, asOfDecisions, asOfEvents, ledger, audit, at);
    const readiness = evaluateIntegrityExecutionReadiness(
      plan, ledger, controls, provenance, policy);
    const current = new Map<string, SnapshotRow>(
      readiness.candidates.map(x => [x.candidateId, {
        candidateId: x.candidateId, ready: x.ready,
        approved: x.approved, completed: x.completed,
        verified: x.independentlyVerified,
        active: x.activeAssociations > 0,
        blockers: x.blockers,
      }]));
    const changes = diffSnapshots(previous, current, at);
    previous = current;
    results.push({
      at, candidates: readiness.totals.candidates,
      approved: readiness.totals.approved,
      completed: readiness.totals.completed,
      verified: readiness.totals.verified,
      withActiveAssociation: readiness.totals.withActiveAssociation,
      ready: readiness.totals.ready,
      blocked: readiness.totals.blocked,
      controlErrors: controls.totals.errors,
      provenanceErrors: provenance.totals.errors,
      readinessPercent: readiness.totals.readinessPercent,
      changes,
    });
  }
  const allChanges = results.flatMap(x => x.changes);
  const count = (kind: IntegrityExecutionReadinessHistoryChangeKind) =>
    allChanges.filter(x => x.kind === kind).length;
  return {
    schemaVersion: 1, captureId: plan.captureId, checkpoints: results,
    summary: {
      checkpointCount: results.length,
      firstAt: times[0]!, lastAt: times.at(-1)!,
      initialReady: results[0]!.ready,
      finalReady: results.at(-1)!.ready,
      peakReady: Math.max(...results.map(x => x.ready)),
      peakBlocked: Math.max(...results.map(x => x.blocked)),
      peakControlErrors: Math.max(...results.map(x => x.controlErrors)),
      peakProvenanceErrors: Math.max(...results.map(x => x.provenanceErrors)),
      readinessGains: count("BECAME_READY"),
      readinessRegressions: count("LOST_READINESS"),
      associationGains: count("ASSOCIATION_GAINED"),
      associationRegressions: count("ASSOCIATION_LOST"),
      approvalGains: count("APPROVAL_GAINED"),
      blockerAdditions: count("BLOCKER_ADDED"),
      blockerResolutions: count("BLOCKER_RESOLVED"),
      netReadyDelta: results.at(-1)!.ready - results[0]!.ready,
    },
  };
}
export function parseIntegrityExecutionReadinessHistoryQuery(
  value: unknown,
): IntegrityExecutionReadinessHistoryQuery {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid readiness history query.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(x => ![
    "candidateIds", "kinds", "from", "to", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown readiness history field.");
  const parseList = (value: unknown) => {
    if (!Array.isArray(value) || value.length > 1000 ||
        value.some(x => typeof x !== "string" || !x ||
          x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
      throw new WorkInputError("INVALID", "Invalid readiness history filter.");
    return [...new Set(value as string[])];
  };
  const selectedKinds = raw.kinds === undefined ? undefined :
    parseList(raw.kinds);
  if (selectedKinds?.some(x =>
    !kinds.includes(x as IntegrityExecutionReadinessHistoryChangeKind)))
    throw new WorkInputError("INVALID", "Unknown readiness history change.");
  if (raw.from !== undefined && !validTime(raw.from))
    throw new WorkInputError("INVALID", "Invalid history start.");
  if (raw.to !== undefined && !validTime(raw.to))
    throw new WorkInputError("INVALID", "Invalid history end.");
  if (raw.from && raw.to && raw.from > raw.to)
    throw new WorkInputError("INVALID", "Reversed history range.");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 100;
  if (!Number.isSafeInteger(offset) || (offset as number) < 0 ||
      (offset as number) > 1000000 ||
      !Number.isSafeInteger(limit) || (limit as number) < 1 ||
      (limit as number) > 1000)
    throw new WorkInputError("INVALID", "Invalid history pagination.");
  return {
    ...(raw.candidateIds === undefined ? {} :
      { candidateIds: parseList(raw.candidateIds) }),
    ...(selectedKinds === undefined ? {} :
      { kinds: selectedKinds as IntegrityExecutionReadinessHistoryChangeKind[] }),
    ...(raw.from === undefined ? {} : { from: raw.from as string }),
    ...(raw.to === undefined ? {} : { to: raw.to as string }),
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityExecutionReadinessHistory(
  history: IntegrityExecutionReadinessHistory,
  query: IntegrityExecutionReadinessHistoryQuery,
): IntegrityExecutionReadinessHistoryPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = history.checkpoints.flatMap(x => x.changes)
    .filter(x =>
      (!query.candidateIds || query.candidateIds.includes(x.candidateId)) &&
      (!query.kinds || query.kinds.includes(x.kind)) &&
      (!query.from || x.at >= query.from) &&
      (!query.to || x.at <= query.to));
  return {
    captureId: history.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    changes: selected.slice(offset, offset + limit),
  };
}
