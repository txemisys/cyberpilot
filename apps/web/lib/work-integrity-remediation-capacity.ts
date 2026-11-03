import { WorkInputError } from "./remediation-work-input";
import type {
  IntegrityRemediationPlan, IntegrityRemediationCandidate,
  IntegrityRemediationPriority,
} from "./work-integrity-remediation-plan";

export type IntegrityRemediationWorkload = {
  group: string;
  candidates: number;
  urgent: number;
  blocked: number;
  advisory: number;
  cases: string[];
  workItems: string[];
  riskPoints: number;
  actions: Record<string, number>;
};
export type IntegrityRemediationWorkloadReport = {
  schemaVersion: 1;
  captureId: string;
  byCase: IntegrityRemediationWorkload[];
  byWorkItem: IntegrityRemediationWorkload[];
  byAction: IntegrityRemediationWorkload[];
  unassigned: IntegrityRemediationWorkload;
  topCases: string[];
  topWorkItems: string[];
  totals: {
    groups: number;
    candidates: number;
    urgent: number;
    blocked: number;
    riskPoints: number;
    uniqueCases: number;
    uniqueWorkItems: number;
  };
};
export type IntegrityRemediationCapacity = {
  maximumCandidates: number;
  maximumUrgent: number;
  maximumRiskPoints: number;
};
export type IntegrityRemediationCapacityResult = {
  captureId: string;
  selected: IntegrityRemediationCandidate[];
  deferred: IntegrityRemediationCandidate[];
  selectedRiskPoints: number;
  deferredRiskPoints: number;
  selectedUrgent: number;
  capacityExhausted: boolean;
  remaining: IntegrityRemediationCapacity;
};
function urgent(priority: IntegrityRemediationPriority) {
  return priority === "P0" || priority === "P1";
}
function group(
  key: string,
  items: readonly IntegrityRemediationCandidate[],
): IntegrityRemediationWorkload {
  const actions: Record<string, number> = {};
  for (const item of items)
    actions[item.action] = (actions[item.action] ?? 0) + 1;
  return {
    group: key, candidates: items.length,
    urgent: items.filter(x => urgent(x.priority)).length,
    blocked: items.filter(x => x.blockedBy.length > 0).length,
    advisory: items.filter(x => !x.executable).length,
    cases: [...new Set(items.flatMap(x =>
      x.caseKey === null ? [] : [x.caseKey]))].sort(),
    workItems: [...new Set(items.flatMap(x =>
      x.workItemId === null ? [] : [x.workItemId]))].sort(),
    riskPoints: items.reduce((sum, x) =>
      sum + x.estimatedRiskReduction, 0),
    actions,
  };
}
function groups(
  candidates: readonly IntegrityRemediationCandidate[],
  key: (item: IntegrityRemediationCandidate) => string | null,
) {
  const buckets = new Map<string, IntegrityRemediationCandidate[]>();
  for (const item of candidates) {
    const id = key(item);
    if (id === null) continue;
    const rows = buckets.get(id) ?? [];
    rows.push(item);
    buckets.set(id, rows);
  }
  return [...buckets].map(([id, rows]) => group(id, rows)).sort((a, b) =>
    b.urgent - a.urgent ||
    b.riskPoints - a.riskPoints ||
    a.group.localeCompare(b.group));
}
export function summarizeIntegrityRemediationWorkload(
  plan: IntegrityRemediationPlan,
): IntegrityRemediationWorkloadReport {
  const byCase = groups(plan.candidates, x => x.caseKey);
  const byWorkItem = groups(plan.candidates, x => x.workItemId);
  const byAction = groups(plan.candidates, x => x.action);
  const unassigned = group("UNASSIGNED", plan.candidates.filter(x =>
    x.caseKey === null && x.workItemId === null));
  return {
    schemaVersion: 1, captureId: plan.captureId,
    byCase, byWorkItem, byAction, unassigned,
    topCases: byCase.slice(0, 10).map(x => x.group),
    topWorkItems: byWorkItem.slice(0, 10).map(x => x.group),
    totals: {
      groups: byCase.length + byWorkItem.length + byAction.length,
      candidates: plan.candidates.length,
      urgent: plan.candidates.filter(x => urgent(x.priority)).length,
      blocked: plan.candidates.filter(x => x.blockedBy.length > 0).length,
      riskPoints: plan.candidates.reduce((sum, x) =>
        sum + x.estimatedRiskReduction, 0),
      uniqueCases: byCase.length,
      uniqueWorkItems: byWorkItem.length,
    },
  };
}
export function parseIntegrityRemediationCapacity(
  value: unknown,
): IntegrityRemediationCapacity {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid remediation capacity.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(x => ![
    "maximumCandidates", "maximumUrgent", "maximumRiskPoints",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown capacity field.");
  for (const key of ["maximumCandidates", "maximumUrgent", "maximumRiskPoints"]) {
    const n = raw[key];
    if (!Number.isSafeInteger(n) || (n as number) < 0 ||
        (n as number) > 1000000)
      throw new WorkInputError("INVALID", "Invalid " + key);
  }
  return raw as IntegrityRemediationCapacity;
}
export function allocateIntegrityRemediationCapacity(
  plan: IntegrityRemediationPlan,
  capacity: IntegrityRemediationCapacity,
): IntegrityRemediationCapacityResult {
  const validated = parseIntegrityRemediationCapacity(capacity);
  const selected: IntegrityRemediationCandidate[] = [];
  const deferred: IntegrityRemediationCandidate[] = [];
  let riskPoints = 0;
  let urgentCount = 0;
  for (const item of plan.candidates) {
    const isUrgent = urgent(item.priority);
    if (selected.length >= validated.maximumCandidates ||
        (isUrgent && urgentCount >= validated.maximumUrgent) ||
        riskPoints + item.estimatedRiskReduction > validated.maximumRiskPoints) {
      deferred.push(item);
      continue;
    }
    selected.push(item);
    riskPoints += item.estimatedRiskReduction;
    if (isUrgent) urgentCount++;
  }
  return {
    captureId: plan.captureId, selected, deferred,
    selectedRiskPoints: riskPoints,
    deferredRiskPoints: deferred.reduce((sum, x) =>
      sum + x.estimatedRiskReduction, 0),
    selectedUrgent: urgentCount,
    capacityExhausted: deferred.length > 0,
    remaining: {
      maximumCandidates: validated.maximumCandidates - selected.length,
      maximumUrgent: validated.maximumUrgent - urgentCount,
      maximumRiskPoints: validated.maximumRiskPoints - riskPoints,
    },
  };
}
