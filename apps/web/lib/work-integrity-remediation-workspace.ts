import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import type { IntegrityEvidencePortfolioInput } from "./work-integrity-evidence-portfolio";
import {
  planIntegrityRemediationFromEvents,
  type IntegrityRemediationPlan,
  type IntegrityRemediationCandidate,
} from "./work-integrity-remediation-plan";
import {
  buildIntegrityRemediationHistory,
  type IntegrityRemediationHistory,
} from "./work-integrity-remediation-history";
import {
  summarizeIntegrityRemediationWorkload,
  allocateIntegrityRemediationCapacity,
  type IntegrityRemediationCapacity,
} from "./work-integrity-remediation-capacity";
import {
  parseIntegrityRemediationGatePolicy,
  evaluateIntegrityRemediationGate,
  compareIntegrityRemediationGates,
  type IntegrityRemediationGatePolicy,
  type IntegrityRemediationGateReport,
} from "./work-integrity-remediation-gates";
import {
  exportIntegrityRemediation,
  parseIntegrityRemediationExportRequest,
  type IntegrityRemediationExportBundle,
} from "./work-integrity-remediation-export";
import type {
  IntegrityPortfolioRiskWeights,
} from "./work-integrity-portfolio-risk";

export type IntegrityRemediationDecision = "ACCEPT" | "DEFER" | "REJECT";
export type IntegrityRemediationDecisionRecord = {
  candidateId: string;
  decision: IntegrityRemediationDecision;
  reason: string;
  reviewerId: string;
  reviewedAt: string;
};
export type IntegrityRemediationDecisionStatus = {
  candidateId: string;
  decision: IntegrityRemediationDecision | "PENDING";
  reason: string | null;
  reviewerId: string | null;
  reviewedAt: string | null;
  stillPresent: boolean;
  priority: IntegrityRemediationCandidate["priority"] | null;
  action: IntegrityRemediationCandidate["action"] | null;
};
export type IntegrityRemediationDecisionSummary = {
  captureId: string;
  accepted: number;
  deferred: number;
  rejected: number;
  pending: number;
  stale: number;
  decisions: IntegrityRemediationDecisionStatus[];
  unknownCandidateIds: string[];
  reviewCoverage: number;
};
export type IntegrityRemediationDecisionPolicy = {
  allowStale: boolean;
  requireReasonsForRejection: boolean;
  requireReasonsForDeferral: boolean;
  minimumReviewerIdLength: number;
};
export type IntegrityRemediationDecisionAudit = {
  captureId: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
  summary: IntegrityRemediationDecisionSummary;
};
export type IntegrityRemediationReadiness = {
  captureId: string;
  ready: boolean;
  policyPassed: boolean;
  allUrgentReviewed: boolean;
  outstandingUrgent: string[];
  accepted: string[];
  deferred: string[];
  rejected: string[];
  pending: string[];
  unresolvedAuditErrors: number;
  blockedAccepted: string[];
  requiredReviewCount: number;
  completedReviewCount: number;
};
export type IntegrityRemediationWorkspace = {
  captureId: string;
  plan: IntegrityRemediationPlan;
  history: IntegrityRemediationHistory | null;
  gates: IntegrityRemediationGateReport | null;
  decisions: IntegrityRemediationDecisionSummary;
  readiness: IntegrityRemediationReadiness;
  workload: ReturnType<typeof summarizeIntegrityRemediationWorkload>;
  capacity: ReturnType<typeof allocateIntegrityRemediationCapacity> | null;
  exports: IntegrityRemediationExportBundle | null;
};
const validTime = (value: string) =>
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const validId = (value: string) =>
  value.length > 0 && value.length <= 1500 &&
  !/[\u0000-\u001f\u007f]/.test(value);
export function parseIntegrityRemediationDecisions(
  value: unknown,
): IntegrityRemediationDecisionRecord[] {
  if (!Array.isArray(value) || value.length > 10000)
    throw new WorkInputError("INVALID", "Invalid remediation decisions.");
  const seen = new Set<string>();
  const result: IntegrityRemediationDecisionRecord[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      throw new WorkInputError("INVALID", "Invalid remediation decision.");
    const row = entry as Record<string, unknown>;
    if (Object.keys(row).some(x => ![
      "candidateId", "decision", "reason", "reviewerId", "reviewedAt",
    ].includes(x)))
      throw new WorkInputError("INVALID", "Unknown remediation decision field.");
    if (typeof row.candidateId !== "string" || !validId(row.candidateId))
      throw new WorkInputError("INVALID", "Invalid candidate ID.");
    if (seen.has(row.candidateId))
      throw new WorkInputError("INVALID", "Duplicate remediation decision.");
    seen.add(row.candidateId);
    if (row.decision !== "ACCEPT" &&
        row.decision !== "DEFER" && row.decision !== "REJECT")
      throw new WorkInputError("INVALID", "Invalid remediation decision type.");
    if (typeof row.reason !== "string" || row.reason.length > 4000 ||
        /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(row.reason))
      throw new WorkInputError("INVALID", "Invalid remediation decision reason.");
    if (typeof row.reviewerId !== "string" || !validId(row.reviewerId))
      throw new WorkInputError("INVALID", "Invalid remediation reviewer.");
    if (typeof row.reviewedAt !== "string" || !validTime(row.reviewedAt))
      throw new WorkInputError("INVALID", "Invalid remediation review timestamp.");
    result.push({
      candidateId: row.candidateId,
      decision: row.decision,
      reason: row.reason,
      reviewerId: row.reviewerId,
      reviewedAt: row.reviewedAt,
    });
  }
  return result.sort((a, b) => a.candidateId.localeCompare(b.candidateId));
}
export function parseIntegrityRemediationDecisionPolicy(
  value: unknown,
): IntegrityRemediationDecisionPolicy {
  if (value === undefined) return {
    allowStale: false,
    requireReasonsForRejection: true,
    requireReasonsForDeferral: true,
    minimumReviewerIdLength: 1,
  };
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid remediation decision policy.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(x => ![
    "allowStale", "requireReasonsForRejection",
    "requireReasonsForDeferral", "minimumReviewerIdLength",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown decision policy field.");
  for (const key of [
    "allowStale", "requireReasonsForRejection", "requireReasonsForDeferral",
  ]) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean")
      throw new WorkInputError("INVALID", "Invalid decision policy flag.");
  }
  const min = raw.minimumReviewerIdLength ?? 1;
  if (!Number.isSafeInteger(min) || (min as number) < 1 || (min as number) > 100)
    throw new WorkInputError("INVALID", "Invalid minimum reviewer ID length.");
  return {
    allowStale: raw.allowStale === true,
    requireReasonsForRejection: raw.requireReasonsForRejection !== false,
    requireReasonsForDeferral: raw.requireReasonsForDeferral !== false,
    minimumReviewerIdLength: min as number,
  };
}
export function summarizeIntegrityRemediationDecisions(
  plan: IntegrityRemediationPlan,
  decisions: readonly IntegrityRemediationDecisionRecord[],
): IntegrityRemediationDecisionSummary {
  const current = new Map(plan.candidates.map(x => [x.id, x]));
  const decided = new Map(decisions.map(x => [x.candidateId, x]));
  const rows: IntegrityRemediationDecisionStatus[] = [];
  for (const item of plan.candidates) {
    const record = decided.get(item.id);
    rows.push({
      candidateId: item.id,
      decision: record?.decision ?? "PENDING",
      reason: record?.reason ?? null,
      reviewerId: record?.reviewerId ?? null,
      reviewedAt: record?.reviewedAt ?? null,
      stillPresent: true, priority: item.priority, action: item.action,
    });
  }
  for (const record of decisions) {
    if (current.has(record.candidateId)) continue;
    rows.push({
      candidateId: record.candidateId,
      decision: record.decision,
      reason: record.reason, reviewerId: record.reviewerId,
      reviewedAt: record.reviewedAt, stillPresent: false,
      priority: null, action: null,
    });
  }
  rows.sort((a, b) => a.candidateId.localeCompare(b.candidateId));
  const active = rows.filter(x => x.stillPresent);
  const accepted = active.filter(x => x.decision === "ACCEPT").length;
  const deferred = active.filter(x => x.decision === "DEFER").length;
  const rejected = active.filter(x => x.decision === "REJECT").length;
  const pending = active.filter(x => x.decision === "PENDING").length;
  return {
    captureId: plan.captureId,
    accepted, deferred, rejected, pending,
    stale: rows.length - active.length, decisions: rows,
    unknownCandidateIds: rows.filter(x => !x.stillPresent).map(x => x.candidateId),
    reviewCoverage: active.length === 0 ? 1 :
      (accepted + deferred + rejected) / active.length,
  };
}
export function auditIntegrityRemediationDecisions(
  plan: IntegrityRemediationPlan,
  decisions: readonly IntegrityRemediationDecisionRecord[],
  policy: IntegrityRemediationDecisionPolicy,
): IntegrityRemediationDecisionAudit {
  const summary = summarizeIntegrityRemediationDecisions(plan, decisions);
  const errors: string[] = [];
  const warnings: string[] = [];
  const known = new Set(plan.candidates.map(x => x.id));
  const seen = new Set<string>();
  for (const item of decisions) {
    if (seen.has(item.candidateId)) {
      errors.push("Duplicate decision for " + item.candidateId);
      continue;
    }
    seen.add(item.candidateId);
    if (!known.has(item.candidateId)) {
      const message = "Decision refers to absent candidate " + item.candidateId;
      if (policy.allowStale) warnings.push(message);
      else errors.push(message);
    }
    if (item.reviewerId.length < policy.minimumReviewerIdLength)
      errors.push("Reviewer identity too short for " + item.candidateId);
    if (policy.requireReasonsForRejection && item.decision === "REJECT" &&
        !item.reason.trim())
      errors.push("Rejection requires reason for " + item.candidateId);
    if (policy.requireReasonsForDeferral && item.decision === "DEFER" &&
        !item.reason.trim())
      errors.push("Deferral requires reason for " + item.candidateId);
    if (!validTime(item.reviewedAt))
      errors.push("Invalid review timestamp for " + item.candidateId);
  }
  return {
    captureId: plan.captureId, valid: errors.length === 0,
    errors, warnings, summary,
  };
}
export function evaluateIntegrityRemediationReadiness(
  plan: IntegrityRemediationPlan,
  summary: IntegrityRemediationDecisionSummary,
  gates?: IntegrityRemediationGateReport,
): IntegrityRemediationReadiness {
  if (plan.captureId !== summary.captureId ||
      (gates && gates.captureId !== plan.captureId))
    throw new WorkInputError("INVALID", "Readiness capture mismatch.");
  const decisions = new Map(summary.decisions.map(x => [x.candidateId, x]));
  const accepted: string[] = [];
  const deferred: string[] = [];
  const rejected: string[] = [];
  const pending: string[] = [];
  const outstandingUrgent: string[] = [];
  const blockedAccepted: string[] = [];
  for (const item of plan.candidates) {
    const status = decisions.get(item.id)?.decision ?? "PENDING";
    if (status === "ACCEPT") accepted.push(item.id);
    if (status === "DEFER") deferred.push(item.id);
    if (status === "REJECT") rejected.push(item.id);
    if (status === "PENDING") pending.push(item.id);
    if ((item.priority === "P0" || item.priority === "P1") &&
        status === "PENDING") outstandingUrgent.push(item.id);
    if (status === "ACCEPT" && item.blockedBy.length > 0)
      blockedAccepted.push(item.id);
  }
  const unresolvedAuditErrors = plan.candidates.filter(x =>
    x.action === "REVIEW_AUDIT_ERROR" &&
    !["ACCEPT", "REJECT"].includes(
      decisions.get(x.id)?.decision ?? "PENDING")).length;
  const policyPassed = gates?.passed ?? true;
  const allUrgentReviewed = outstandingUrgent.length === 0;
  return {
    captureId: plan.captureId,
    ready: policyPassed && allUrgentReviewed &&
      blockedAccepted.length === 0 && unresolvedAuditErrors === 0,
    policyPassed, allUrgentReviewed, outstandingUrgent,
    accepted, deferred, rejected, pending,
    unresolvedAuditErrors, blockedAccepted,
    requiredReviewCount: plan.candidates.length,
    completedReviewCount: accepted.length + deferred.length + rejected.length,
  };
}
export function buildIntegrityRemediationWorkspace(
  input: IntegrityEvidencePortfolioInput,
  events: readonly IntegrityLinkHistoryEvent[],
  options: {
    weights?: IntegrityPortfolioRiskWeights;
    checkpoints?: string[];
    gatePolicy?: IntegrityRemediationGatePolicy;
    decisions?: IntegrityRemediationDecisionRecord[];
    capacity?: IntegrityRemediationCapacity;
    exportRequest?: unknown;
  } = {},
): IntegrityRemediationWorkspace {
  const result = planIntegrityRemediationFromEvents(
    input, events, options.weights);
  const workload = summarizeIntegrityRemediationWorkload(result.plan);
  const history = options.checkpoints
    ? buildIntegrityRemediationHistory(
      input, events, options.checkpoints, options.weights)
    : null;
  const gates = options.gatePolicy
    ? evaluateIntegrityRemediationGate(result.plan, options.gatePolicy)
    : null;
  const decisions = summarizeIntegrityRemediationDecisions(
    result.plan, options.decisions ?? []);
  const readiness = evaluateIntegrityRemediationReadiness(
    result.plan, decisions, gates ?? undefined);
  const capacity = options.capacity
    ? allocateIntegrityRemediationCapacity(result.plan, options.capacity)
    : null;
  const exports = options.exportRequest !== undefined
    ? exportIntegrityRemediation(
      result.plan,
      parseIntegrityRemediationExportRequest(options.exportRequest),
      history ?? undefined, workload)
    : null;
  return {
    captureId: input.captureId, plan: result.plan,
    history, gates, decisions, readiness, workload, capacity, exports,
  };
}
export function compareIntegrityRemediationWorkspaces(
  before: IntegrityRemediationWorkspace,
  after: IntegrityRemediationWorkspace,
) {
  if (before.captureId !== after.captureId)
    throw new WorkInputError("INVALID", "Workspace capture mismatch.");
  const old = new Map(before.plan.candidates.map(x => [x.id, x]));
  const current = new Map(after.plan.candidates.map(x => [x.id, x]));
  const introduced = [...current.keys()].filter(x => !old.has(x)).sort();
  const resolved = [...old.keys()].filter(x => !current.has(x)).sort();
  const acceptedBefore = new Set(before.decisions.decisions.filter(x =>
    x.decision === "ACCEPT" && x.stillPresent).map(x => x.candidateId));
  const acceptedAfter = new Set(after.decisions.decisions.filter(x =>
    x.decision === "ACCEPT" && x.stillPresent).map(x => x.candidateId));
  return {
    captureId: before.captureId,
    beforeReady: before.readiness.ready,
    afterReady: after.readiness.ready,
    introduced, resolved,
    newlyAccepted: [...acceptedAfter].filter(x =>
      !acceptedBefore.has(x)).sort(),
    noLongerAccepted: [...acceptedBefore].filter(x =>
      !acceptedAfter.has(x)).sort(),
    urgentDelta: after.workload.totals.urgent -
      before.workload.totals.urgent,
    blockedDelta: after.workload.totals.blocked -
      before.workload.totals.blocked,
    reviewCoverageDelta: after.decisions.reviewCoverage -
      before.decisions.reviewCoverage,
    gateDelta: before.gates && after.gates
      ? compareIntegrityRemediationGates(before.gates, after.gates)
      : null,
  };
}
export function parseIntegrityRemediationWorkspaceGate(
  value: unknown,
): IntegrityRemediationGatePolicy {
  return parseIntegrityRemediationGatePolicy(value);
}
