import type { CaseSnapshot } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";
import { buildEvidenceReadiness, type EvidenceRequirement } from "./work-integrity-evidence-readiness";
import { forecastReviewCapacity, type CapacityPolicy } from "./work-integrity-capacity";
import { createSlaPlan, evaluateSlaPlan, type SlaPolicy, DEFAULT_SLA_POLICY } from "./work-integrity-sla";

/**
 * Offline readiness gate for publishing an integrity-review handoff.
 * A passing gate authorizes nothing; it is a policy evaluation only.
 */
export type ReadinessCriterion =
  | "COMPLETE_SNAPSHOT" | "COMPLETE_LINKED_COVERAGE"
  | "NO_STALE_REVIEWS" | "NO_CRITICAL_UNREVIEWED"
  | "EVIDENCE_READY" | "CAPACITY_COVERED"
  | "NO_ESCALATED_SLA" | "NO_OVERDUE_SLA";
export type ReadinessThreshold = {
  criterion: ReadinessCriterion;
  required: boolean;
  minimumRatio: number;
};
export type ReadinessGatePolicy = {
  thresholds: ReadinessThreshold[];
  maxCases: number;
  requireAllCriteria: boolean;
};
export type ReadinessFinding = {
  criterion: ReadinessCriterion;
  required: boolean;
  passed: boolean;
  observedRatio: number;
  requiredRatio: number;
  numerator: number;
  denominator: number;
  explanation: string;
};
export type ReadinessGateReport = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  assessedAt: string;
  complete: boolean;
  passed: boolean;
  findings: ReadinessFinding[];
  blocking: ReadinessFinding[];
  advisory: ReadinessFinding[];
  warnings: string[];
};
const criteria: ReadinessCriterion[] = [
  "COMPLETE_SNAPSHOT", "COMPLETE_LINKED_COVERAGE", "NO_STALE_REVIEWS",
  "NO_CRITICAL_UNREVIEWED", "EVIDENCE_READY", "CAPACITY_COVERED",
  "NO_ESCALATED_SLA", "NO_OVERDUE_SLA",
];
export const DEFAULT_READINESS_GATE: ReadinessGatePolicy = {
  thresholds: criteria.map(criterion => ({
    criterion, required: true, minimumRatio: 1,
  })),
  maxCases: 100000,
  requireAllCriteria: true,
};
export function validateReadinessGatePolicy(input: ReadinessGatePolicy): ReadinessGatePolicy {
  if (!input || !Array.isArray(input.thresholds) || input.thresholds.length > criteria.length)
    throw new Error("Invalid readiness thresholds.");
  if (!Number.isSafeInteger(input.maxCases) || input.maxCases < 1 || input.maxCases > 100000)
    throw new Error("Invalid readiness case limit.");
  if (typeof input.requireAllCriteria !== "boolean")
    throw new Error("Invalid readiness policy mode.");
  const seen = new Set<string>();
  const thresholds = input.thresholds.map(item => {
    if (!criteria.includes(item.criterion) || seen.has(item.criterion))
      throw new Error("Unknown or duplicate readiness criterion.");
    seen.add(item.criterion);
    if (typeof item.required !== "boolean" ||
        !Number.isFinite(item.minimumRatio) ||
        item.minimumRatio < 0 || item.minimumRatio > 1)
      throw new Error("Invalid readiness threshold.");
    return { ...item };
  });
  return { ...input, thresholds };
}
function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 1 : numerator / denominator;
}
export function evaluateReadinessGate(
  snapshot: CaseSnapshot,
  assessedAt: string,
  input: ReadinessGatePolicy,
  capacityPolicy: CapacityPolicy,
  evidenceRequirements: readonly EvidenceRequirement[],
  slaPolicy: SlaPolicy = DEFAULT_SLA_POLICY,
): ReadinessGateReport {
  const policy = validateReadinessGatePolicy(input);
  if (snapshot.cases.length > policy.maxCases)
    throw new Error("Readiness gate exceeds configured case limit.");
  const queue = buildReviewWorklist(snapshot);
  const evidence = buildEvidenceReadiness(snapshot, evidenceRequirements);
  const capacity = forecastReviewCapacity(snapshot, capacityPolicy);
  const sla = evaluateSlaPlan(createSlaPlan(snapshot, slaPolicy), assessedAt, slaPolicy);
  const counts: Record<ReadinessCriterion, { good: number; total: number; explanation: string }> = {
    COMPLETE_SNAPSHOT: {
      good: snapshot.complete ? 1 : 0, total: 1,
      explanation: "Source capture must cover all required pages and history.",
    },
    COMPLETE_LINKED_COVERAGE: {
      good: snapshot.cases.filter(item => item.completeCoverage).length,
      total: snapshot.cases.length,
      explanation: "Cases with complete linked-record coverage.",
    },
    NO_STALE_REVIEWS: {
      good: queue.entries.filter(item => item.state !== "STALE").length,
      total: queue.entries.length,
      explanation: "Cases without obsolete review revisions.",
    },
    NO_CRITICAL_UNREVIEWED: {
      good: queue.entries.filter(item => item.priority !== "P0" ||
        !!item.reviewEventId).length,
      total: queue.entries.length,
      explanation: "Cases without unreviewed P0 findings.",
    },
    EVIDENCE_READY: {
      good: evidence.ready, total: evidence.total,
      explanation: "Cases meeting configured evidence requirements.",
    },
    CAPACITY_COVERED: {
      good: capacity.demand.length - capacity.unallocated.length,
      total: capacity.demand.length,
      explanation: "Cases allocated within eligible analyst time budgets.",
    },
    NO_ESCALATED_SLA: {
      good: sla.total - sla.counts.ESCALATED,
      total: sla.total,
      explanation: "Cases not beyond their acknowledgement escalation threshold.",
    },
    NO_OVERDUE_SLA: {
      good: sla.total - sla.counts.ACK_OVERDUE - sla.counts.RESOLUTION_OVERDUE -
        sla.counts.ESCALATED,
      total: sla.total,
      explanation: "Cases without overdue SLA planning deadlines.",
    },
  };
  const findings = policy.thresholds.map(threshold => {
    const value = counts[threshold.criterion];
    const observedRatio = ratio(value.good, value.total);
    return {
      criterion: threshold.criterion, required: threshold.required,
      passed: observedRatio >= threshold.minimumRatio,
      observedRatio, requiredRatio: threshold.minimumRatio,
      numerator: value.good, denominator: value.total,
      explanation: value.explanation,
    };
  });
  const blocking = findings.filter(item => item.required && !item.passed);
  const advisory = findings.filter(item => !item.required && !item.passed);
  const passed = policy.requireAllCriteria
    ? blocking.length === 0
    : findings.some(item => item.required && item.passed) ||
      findings.every(item => !item.required);
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, assessedAt, complete: snapshot.complete,
    passed, findings, blocking, advisory,
    warnings: [
      "Passing a readiness gate is not a security authorization or proof of remediation.",
      "Evidence readiness, SLA targets and staffing estimates depend on explicit policy assumptions.",
      ...(!snapshot.complete ? ["Incomplete capture can hide additional findings."] : []),
    ],
  };
}
export type ReadinessGateDiff = {
  organizationId: string;
  improved: ReadinessCriterion[];
  degraded: ReadinessCriterion[];
  unchanged: ReadinessCriterion[];
  unknown: ReadinessCriterion[];
  passedBefore: boolean;
  passedAfter: boolean;
};
export function compareReadinessGates(
  before: ReadinessGateReport, after: ReadinessGateReport,
): ReadinessGateDiff {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cannot compare readiness gates across organizations.");
  const old = new Map(before.findings.map(item => [item.criterion, item]));
  const current = new Map(after.findings.map(item => [item.criterion, item]));
  const improved: ReadinessCriterion[] = [], degraded: ReadinessCriterion[] = [];
  const unchanged: ReadinessCriterion[] = [], unknown: ReadinessCriterion[] = [];
  for (const criterion of [...new Set([...old.keys(), ...current.keys()])].sort()) {
    const a = old.get(criterion), b = current.get(criterion);
    if (!a || !b || (!before.complete || !after.complete) &&
        criterion !== "COMPLETE_SNAPSHOT") {
      unknown.push(criterion);
      continue;
    }
    if (b.observedRatio > a.observedRatio) improved.push(criterion);
    else if (b.observedRatio < a.observedRatio) degraded.push(criterion);
    else unchanged.push(criterion);
  }
  return {
    organizationId: before.organizationId,
    improved, degraded, unchanged, unknown,
    passedBefore: before.passed, passedAfter: after.passed,
  };
}
export function readinessGateCsv(report: ReadinessGateReport): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const escaped = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + escaped.replace(/"/g, '""') + '"';
  };
  const lines = [[
    "criterion", "required", "passed", "observedRatio",
    "requiredRatio", "numerator", "denominator", "explanation",
  ].map(safe).join(",")];
  for (const item of report.findings) lines.push([
    item.criterion, item.required, item.passed, item.observedRatio,
    item.requiredRatio, item.numerator, item.denominator, item.explanation,
  ].map(safe).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function readinessGateJson(report: ReadinessGateReport): string {
  return JSON.stringify(report, null, 2) + "\n";
}
