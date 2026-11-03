import { WorkInputError } from "./remediation-work-input";
import type { IntegrityRemediationPlan } from "./work-integrity-remediation-plan";
import type { IntegrityRemediationExecutionLedger } from "./work-integrity-remediation-execution";
import type {
  IntegrityExecutionEvidenceReport,
  IntegrityExecutionEvidenceCandidate,
} from "./work-integrity-remediation-evidence-provenance";
import type {
  IntegrityExecutionControlReport,
  IntegrityExecutionControlCandidate,
} from "./work-integrity-remediation-execution-controls";

export type IntegrityExecutionReadinessBlocker =
  | "UNKNOWN_CANDIDATE" | "NOT_APPROVED" | "CONTROL_ERROR"
  | "CONTROL_WARNING" | "PROVENANCE_ERROR" | "PROVENANCE_WARNING"
  | "NO_ACTIVE_ASSOCIATION" | "NO_COMPLETION_REFERENCE"
  | "EXECUTION_NOT_COMPLETED" | "EXECUTION_FAILED"
  | "EXECUTION_BLOCKED" | "EXECUTION_CANCELLED"
  | "UNVERIFIED_EVIDENCE" | "UNBOUND_WORK_ITEM"
  | "MISSING_EXECUTION_CONTROLS" | "MISSING_PROVENANCE";
export type IntegrityExecutionReadinessPolicy = {
  requireApprovedDecision: boolean;
  requireCompletedExecution: boolean;
  requireActiveAssociation: boolean;
  requireBoundWorkItem: boolean;
  requireCompletionReference: boolean;
  requireIndependentVerification: boolean;
  blockControlWarnings: boolean;
  blockProvenanceWarnings: boolean;
  maximumControlErrors: number;
  maximumProvenanceErrors: number;
};
export type IntegrityExecutionReadinessCandidate = {
  candidateId: string;
  caseKey: string | null;
  workItemId: string | null;
  action: string;
  priority: string;
  executionState: string;
  approved: boolean;
  completed: boolean;
  independentlyVerified: boolean;
  provenanceComplete: boolean;
  activeAssociations: number;
  controlErrors: number;
  controlWarnings: number;
  provenanceErrors: number;
  provenanceWarnings: number;
  blockers: IntegrityExecutionReadinessBlocker[];
  ready: boolean;
};
export type IntegrityExecutionReadinessReport = {
  schemaVersion: 1;
  captureId: string;
  policy: IntegrityExecutionReadinessPolicy;
  limitation: string;
  candidates: IntegrityExecutionReadinessCandidate[];
  totals: {
    candidates: number;
    ready: number;
    blocked: number;
    completed: number;
    approved: number;
    verified: number;
    withActiveAssociation: number;
    withControlErrors: number;
    withProvenanceErrors: number;
    coveragePercent: number;
    readinessPercent: number;
    byBlocker: Record<IntegrityExecutionReadinessBlocker, number>;
  };
};
export type IntegrityExecutionReadinessQuery = {
  candidateIds?: string[];
  blockers?: IntegrityExecutionReadinessBlocker[];
  priorities?: string[];
  states?: string[];
  onlyReady?: boolean;
  onlyBlocked?: boolean;
  offset?: number;
  limit?: number;
};
export type IntegrityExecutionReadinessPage = {
  captureId: string;
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
  candidates: IntegrityExecutionReadinessCandidate[];
};
const blockerCodes: IntegrityExecutionReadinessBlocker[] = [
  "UNKNOWN_CANDIDATE", "NOT_APPROVED", "CONTROL_ERROR",
  "CONTROL_WARNING", "PROVENANCE_ERROR", "PROVENANCE_WARNING",
  "NO_ACTIVE_ASSOCIATION", "NO_COMPLETION_REFERENCE",
  "EXECUTION_NOT_COMPLETED", "EXECUTION_FAILED",
  "EXECUTION_BLOCKED", "EXECUTION_CANCELLED",
  "UNVERIFIED_EVIDENCE", "UNBOUND_WORK_ITEM",
  "MISSING_EXECUTION_CONTROLS", "MISSING_PROVENANCE",
];
const defaultPolicy: IntegrityExecutionReadinessPolicy = {
  requireApprovedDecision: true,
  requireCompletedExecution: true,
  requireActiveAssociation: true,
  requireBoundWorkItem: false,
  requireCompletionReference: true,
  requireIndependentVerification: true,
  blockControlWarnings: false,
  blockProvenanceWarnings: false,
  maximumControlErrors: 0,
  maximumProvenanceErrors: 0,
};
function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return value as Record<string, unknown>;
}
function list(value: unknown, label: string, maximum: number) {
  if (!Array.isArray(value) || value.length > maximum ||
      value.some(x => typeof x !== "string" || x.length < 1 ||
        x.length > 1500 || /[\u0000-\u001f\u007f]/.test(x)))
    throw new WorkInputError("INVALID", "Invalid " + label);
  return [...new Set(value as string[])];
}
export function parseIntegrityExecutionReadinessPolicy(
  value: unknown,
): IntegrityExecutionReadinessPolicy {
  if (value === undefined) return { ...defaultPolicy };
  const raw = object(value, "readiness policy");
  if (Object.keys(raw).some(x => !Object.keys(defaultPolicy).includes(x)))
    throw new WorkInputError("INVALID", "Unknown readiness policy field.");
  const policy = { ...defaultPolicy };
  for (const key of [
    "requireApprovedDecision", "requireCompletedExecution",
    "requireActiveAssociation", "requireBoundWorkItem",
    "requireCompletionReference", "requireIndependentVerification",
    "blockControlWarnings", "blockProvenanceWarnings",
  ] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean")
        throw new WorkInputError("INVALID", "Invalid readiness policy flag.");
      policy[key] = raw[key] as boolean;
    }
  }
  for (const key of [
    "maximumControlErrors", "maximumProvenanceErrors",
  ] as const) {
    if (raw[key] !== undefined) {
      if (!Number.isSafeInteger(raw[key]) || (raw[key] as number) < 0 ||
          (raw[key] as number) > 1000)
        throw new WorkInputError("INVALID", "Invalid readiness error limit.");
      policy[key] = raw[key] as number;
    }
  }
  return policy;
}
function blockersForCandidate(
  state: string,
  control: IntegrityExecutionControlCandidate | undefined,
  provenance: IntegrityExecutionEvidenceCandidate | undefined,
  verified: boolean,
  policy: IntegrityExecutionReadinessPolicy,
  workItemId: string | null,
): IntegrityExecutionReadinessBlocker[] {
  const blockers = new Set<IntegrityExecutionReadinessBlocker>();
  if (!control) blockers.add("MISSING_EXECUTION_CONTROLS");
  if (!provenance) blockers.add("MISSING_PROVENANCE");
  if (policy.requireApprovedDecision && control?.decision !== "ACCEPT")
    blockers.add("NOT_APPROVED");
  if (policy.requireCompletedExecution && state !== "COMPLETED") {
    if (state === "FAILED") blockers.add("EXECUTION_FAILED");
    else if (state === "BLOCKED") blockers.add("EXECUTION_BLOCKED");
    else if (state === "CANCELLED") blockers.add("EXECUTION_CANCELLED");
    else blockers.add("EXECUTION_NOT_COMPLETED");
  }
  if (policy.requireActiveAssociation &&
      (provenance?.activeAssociations ?? 0) === 0)
    blockers.add("NO_ACTIVE_ASSOCIATION");
  if (policy.requireBoundWorkItem && workItemId === null)
    blockers.add("UNBOUND_WORK_ITEM");
  if (policy.requireCompletionReference &&
      control?.hasTerminalEvidenceReference !== true)
    blockers.add("NO_COMPLETION_REFERENCE");
  if (policy.requireIndependentVerification && !verified)
    blockers.add("UNVERIFIED_EVIDENCE");
  if ((control?.findings.filter(x => x.severity === "ERROR").length ?? 0) >
      policy.maximumControlErrors)
    blockers.add("CONTROL_ERROR");
  if (policy.blockControlWarnings &&
      control?.findings.some(x => x.severity === "WARNING"))
    blockers.add("CONTROL_WARNING");
  if ((provenance?.findings.filter(x => x.severity === "ERROR").length ?? 0) >
      policy.maximumProvenanceErrors)
    blockers.add("PROVENANCE_ERROR");
  if (policy.blockProvenanceWarnings &&
      provenance?.findings.some(x => x.severity === "WARNING"))
    blockers.add("PROVENANCE_WARNING");
  return [...blockers].sort();
}
export function evaluateIntegrityExecutionReadiness(
  plan: IntegrityRemediationPlan,
  ledger: IntegrityRemediationExecutionLedger,
  controls: IntegrityExecutionControlReport,
  provenance: IntegrityExecutionEvidenceReport,
  policy: IntegrityExecutionReadinessPolicy = defaultPolicy,
): IntegrityExecutionReadinessReport {
  if (plan.captureId !== ledger.captureId ||
      plan.captureId !== controls.captureId ||
      plan.captureId !== provenance.captureId)
    throw new WorkInputError("INVALID", "Readiness capture mismatch.");
  const planned = new Map(plan.candidates.map(x => [x.id, x]));
  const controlMap = new Map(controls.candidates.map(x =>
    [x.candidateId, x]));
  const provenanceMap = new Map(provenance.candidates.map(x =>
    [x.candidateId, x]));
  const candidates = ledger.candidates.map(row => {
    const original = planned.get(row.candidateId);
    const control = controlMap.get(row.candidateId);
    const evidence = provenanceMap.get(row.candidateId);
    const blockers = blockersForCandidate(row.state, control, evidence,
      row.hasVerifiedEvidence, policy, original?.workItemId ?? null);
    if (!original) blockers.push("UNKNOWN_CANDIDATE");
    return {
      candidateId: row.candidateId,
      caseKey: original?.caseKey ?? null,
      workItemId: original?.workItemId ?? null,
      action: row.action ?? "UNKNOWN",
      priority: row.priority ?? "UNKNOWN",
      executionState: row.state,
      approved: control?.decision === "ACCEPT",
      completed: row.state === "COMPLETED",
      independentlyVerified: row.hasVerifiedEvidence,
      provenanceComplete: evidence?.evidenceProvenanceComplete ?? false,
      activeAssociations: evidence?.activeAssociations ?? 0,
      controlErrors: control?.findings.filter(x =>
        x.severity === "ERROR").length ?? 0,
      controlWarnings: control?.findings.filter(x =>
        x.severity === "WARNING").length ?? 0,
      provenanceErrors: evidence?.findings.filter(x =>
        x.severity === "ERROR").length ?? 0,
      provenanceWarnings: evidence?.findings.filter(x =>
        x.severity === "WARNING").length ?? 0,
      blockers, ready: blockers.length === 0,
    };
  });
  const byBlocker = Object.fromEntries(blockerCodes.map(code =>
    [code, candidates.filter(x => x.blockers.includes(code)).length])) as
    Record<IntegrityExecutionReadinessBlocker, number>;
  const count = candidates.length;
  const ready = candidates.filter(x => x.ready).length;
  return {
    schemaVersion: 1, captureId: plan.captureId, policy,
    limitation: "Readiness is a conservative analytical gate. It does not authorize work or prove that a security control is effective.",
    candidates, totals: {
      candidates: count, ready, blocked: count - ready,
      completed: candidates.filter(x => x.completed).length,
      approved: candidates.filter(x => x.approved).length,
      verified: candidates.filter(x => x.independentlyVerified).length,
      withActiveAssociation: candidates.filter(x =>
        x.activeAssociations > 0).length,
      withControlErrors: candidates.filter(x =>
        x.controlErrors > 0).length,
      withProvenanceErrors: candidates.filter(x =>
        x.provenanceErrors > 0).length,
      coveragePercent: count === 0 ? 100 :
        Math.round(100 * candidates.filter(x =>
          x.activeAssociations > 0).length / count),
      readinessPercent: count === 0 ? 100 :
        Math.round(100 * ready / count),
      byBlocker,
    },
  };
}
export function parseIntegrityExecutionReadinessQuery(
  value: unknown,
): IntegrityExecutionReadinessQuery {
  const raw = object(value, "readiness query");
  if (Object.keys(raw).some(x => ![
    "candidateIds", "blockers", "priorities", "states",
    "onlyReady", "onlyBlocked", "offset", "limit",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown readiness query field.");
  const blockers = raw.blockers === undefined ? undefined :
    list(raw.blockers, "readiness blockers", blockerCodes.length);
  if (blockers?.some(x =>
    !blockerCodes.includes(x as IntegrityExecutionReadinessBlocker)))
    throw new WorkInputError("INVALID", "Unknown readiness blocker.");
  for (const key of ["onlyReady", "onlyBlocked"]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid readiness query flag.");
  }
  if (raw.onlyReady === true && raw.onlyBlocked === true)
    throw new WorkInputError("INVALID", "Conflicting readiness filters.");
  const offset = raw.offset ?? 0;
  const limit = raw.limit ?? 100;
  if (!Number.isSafeInteger(offset) || (offset as number) < 0 ||
      (offset as number) > 1000000 ||
      !Number.isSafeInteger(limit) || (limit as number) < 1 ||
      (limit as number) > 1000)
    throw new WorkInputError("INVALID", "Invalid readiness pagination.");
  return {
    ...(raw.candidateIds === undefined ? {} :
      { candidateIds: list(raw.candidateIds, "candidate IDs", 1000) }),
    ...(blockers === undefined ? {} :
      { blockers: blockers as IntegrityExecutionReadinessBlocker[] }),
    ...(raw.priorities === undefined ? {} :
      { priorities: list(raw.priorities, "priorities", 100) }),
    ...(raw.states === undefined ? {} :
      { states: list(raw.states, "states", 100) }),
    onlyReady: raw.onlyReady === true,
    onlyBlocked: raw.onlyBlocked === true,
    offset: offset as number, limit: limit as number,
  };
}
export function queryIntegrityExecutionReadiness(
  report: IntegrityExecutionReadinessReport,
  query: IntegrityExecutionReadinessQuery,
): IntegrityExecutionReadinessPage {
  const offset = query.offset ?? 0;
  const limit = query.limit ?? 100;
  const selected = report.candidates.filter(row =>
    (!query.candidateIds || query.candidateIds.includes(row.candidateId)) &&
    (!query.blockers || row.blockers.some(x => query.blockers!.includes(x))) &&
    (!query.priorities || query.priorities.includes(row.priority)) &&
    (!query.states || query.states.includes(row.executionState)) &&
    (!query.onlyReady || row.ready) &&
    (!query.onlyBlocked || !row.ready));
  return {
    captureId: report.captureId, total: selected.length,
    offset, limit, hasMore: offset + limit < selected.length,
    candidates: selected.slice(offset, offset + limit),
  };
}
export function compareIntegrityExecutionReadiness(
  before: IntegrityExecutionReadinessReport,
  after: IntegrityExecutionReadinessReport,
) {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Readiness comparison capture mismatch.");
  const old = new Map(before.candidates.map(x => [x.candidateId, x]));
  const current = new Map(after.candidates.map(x => [x.candidateId, x]));
  return {
    captureId: before.captureId,
    newlyReady: after.candidates.filter(x =>
      x.ready && !old.get(x.candidateId)?.ready)
      .map(x => x.candidateId),
    readinessLost: before.candidates.filter(x =>
      x.ready && !current.get(x.candidateId)?.ready)
      .map(x => x.candidateId),
    introduced: after.candidates.filter(x => !old.has(x.candidateId))
      .map(x => x.candidateId),
    removed: before.candidates.filter(x => !current.has(x.candidateId))
      .map(x => x.candidateId),
    readyDelta: after.totals.ready - before.totals.ready,
    blockedDelta: after.totals.blocked - before.totals.blocked,
    verifiedDelta: after.totals.verified - before.totals.verified,
    coveragePercentDelta: after.totals.coveragePercent -
      before.totals.coveragePercent,
    blockerDeltas: Object.fromEntries(blockerCodes.map(code => [
      code, after.totals.byBlocker[code] - before.totals.byBlocker[code],
    ])) as Record<IntegrityExecutionReadinessBlocker, number>,
  };
}
