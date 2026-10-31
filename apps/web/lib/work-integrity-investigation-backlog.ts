import type { CaseSnapshot } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";
import { buildEvidenceReadiness, type EvidenceRequirement } from "./work-integrity-evidence-readiness";
import { forecastReviewCapacity, type CapacityPolicy } from "./work-integrity-capacity";
import { evaluateSlaPlan, createSlaPlan, type SlaPolicy, DEFAULT_SLA_POLICY } from "./work-integrity-sla";

/**
 * Offline investigation backlog planning with deterministic dependencies.
 * Dependencies express a proposed workflow; they do not execute actions.
 */
export type InvestigationActionKind =
  | "RECOLLECT" | "REASSESS" | "REVIEW" | "COMPLETE_EVIDENCE"
  | "ALLOCATE_CAPACITY" | "ESCALATE" | "VERIFY";
export type InvestigationTask = {
  id: string;
  caseKey: string;
  workItemId: string;
  kind: InvestigationActionKind;
  priority: "P0" | "P1" | "P2" | "P3" | "P4";
  dependsOn: string[];
  estimatedMinutes: number;
  assignedAnalystId: string | null;
  rationale: string;
  coverageComplete: boolean;
};
export type InvestigationBacklog = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  assessedAt: string;
  complete: boolean;
  tasks: InvestigationTask[];
  byKind: Record<InvestigationActionKind, number>;
  estimatedMinutes: number;
  unassignedTasks: number;
  warnings: string[];
};
export type InvestigationPolicy = {
  minutesByKind: Record<InvestigationActionKind, number>;
  includeHistorical: boolean;
  includeReviewed: boolean;
  alwaysVerify: boolean;
  maxTasks: number;
};
export type InvestigationExecutionWave = {
  index: number;
  taskIds: string[];
  totalEstimatedMinutes: number;
  assignedAnalysts: string[];
};
export type InvestigationSchedule = {
  organizationId: string;
  waves: InvestigationExecutionWave[];
  unresolvedDependencies: string[];
  cyclicTaskIds: string[];
  executable: boolean;
};
export const DEFAULT_INVESTIGATION_POLICY: InvestigationPolicy = {
  minutesByKind: {
    RECOLLECT: 60, REASSESS: 45, REVIEW: 45, COMPLETE_EVIDENCE: 30,
    ALLOCATE_CAPACITY: 15, ESCALATE: 20, VERIFY: 60,
  },
  includeHistorical: false, includeReviewed: true,
  alwaysVerify: true, maxTasks: 100000,
};
const kinds: InvestigationActionKind[] = [
  "RECOLLECT", "REASSESS", "REVIEW", "COMPLETE_EVIDENCE",
  "ALLOCATE_CAPACITY", "ESCALATE", "VERIFY",
];
export function validateInvestigationPolicy(input: InvestigationPolicy): InvestigationPolicy {
  if (!input || !input.minutesByKind || typeof input.minutesByKind !== "object" ||
      Array.isArray(input.minutesByKind))
    throw new Error("Invalid investigation effort policy.");
  for (const kind of kinds) {
    const value = input.minutesByKind[kind];
    if (!Number.isSafeInteger(value) || value < 1 || value > 100000)
      throw new Error(`Invalid effort for ${kind}.`);
  }
  if (!Number.isSafeInteger(input.maxTasks) || input.maxTasks < 1 ||
      input.maxTasks > 100000 ||
      typeof input.includeHistorical !== "boolean" ||
      typeof input.includeReviewed !== "boolean" ||
      typeof input.alwaysVerify !== "boolean")
    throw new Error("Invalid investigation planning bounds.");
  return { ...input, minutesByKind: { ...input.minutesByKind } };
}
export function createInvestigationBacklog(
  snapshot: CaseSnapshot, assessedAt: string,
  capacityPolicy: CapacityPolicy,
  requirements: readonly EvidenceRequirement[],
  input: InvestigationPolicy = DEFAULT_INVESTIGATION_POLICY,
  slaPolicy: SlaPolicy = DEFAULT_SLA_POLICY,
): InvestigationBacklog {
  const policy = validateInvestigationPolicy(input);
  const worklist = buildReviewWorklist(snapshot);
  const evidence = buildEvidenceReadiness(snapshot, requirements);
  const capacity = forecastReviewCapacity(snapshot, capacityPolicy);
  const sla = evaluateSlaPlan(createSlaPlan(snapshot, slaPolicy), assessedAt, slaPolicy);
  const evidenceByKey = new Map(evidence.packets.map(item => [item.caseKey, item]));
  const ownerByKey = new Map(capacity.allocations.flatMap(allocation =>
    allocation.caseKeys.map(key => [key, allocation.analystId] as const)));
  const slaByKey = new Map(sla.evaluations.map(item => [item.caseKey, item.phase]));
  const tasks: InvestigationTask[] = [];
  for (const item of worklist.entries) {
    if (!policy.includeHistorical && item.historicalOnly) continue;
    if (!policy.includeReviewed && item.reviewEventId) continue;
    const packet = evidenceByKey.get(item.caseKey);
    const owner = ownerByKey.get(item.caseKey) ?? null;
    const caseTasks: InvestigationTask[] = [];
    const add = (kind: InvestigationActionKind, rationale: string,
      dependencies: string[] = []) => {
      const task: InvestigationTask = {
        id: JSON.stringify([item.caseKey, kind]),
        caseKey: item.caseKey, workItemId: item.workItemId,
        kind, priority: item.priority, dependsOn: dependencies,
        estimatedMinutes: policy.minutesByKind[kind],
        assignedAnalystId: owner, rationale,
        coverageComplete: item.completeCoverage && snapshot.complete,
      };
      caseTasks.push(task);
      return task.id;
    };
    const prerequisites: string[] = [];
    if (!snapshot.complete || !item.completeCoverage) {
      prerequisites.push(add("RECOLLECT",
        "Obtain missing source pages or linked history before making a definitive decision."));
    }
    if (!owner) {
      prerequisites.push(add("ALLOCATE_CAPACITY",
        "Find an eligible analyst with sufficient available time."));
    }
    if (item.state === "STALE") {
      prerequisites.push(add("REASSESS",
        "Review the current revision because prior review evidence is obsolete.",
        [...prerequisites]));
    } else if (!item.reviewEventId) {
      prerequisites.push(add("REVIEW",
        "Investigate the recorded diagnostic and document a human review.",
        [...prerequisites]));
    }
    const missingEvidence = packet?.gaps.length ?? 0;
    if (missingEvidence) {
      prerequisites.push(add("COMPLETE_EVIDENCE",
        "Complete configured evidence requirements; presence does not prove authenticity.",
        [...prerequisites]));
    }
    const slaPhase = slaByKey.get(item.caseKey);
    if (slaPhase === "ESCALATED" || slaPhase === "ACK_OVERDUE" ||
        slaPhase === "RESOLUTION_OVERDUE") {
      prerequisites.push(add("ESCALATE",
        "Review the elapsed SLA planning threshold with an authorized owner."));
    }
    if (policy.alwaysVerify) {
      add("VERIFY",
        "Independently verify the outcome and record evidence before closure.",
        [...new Set(prerequisites)]);
    }
    if (tasks.length + caseTasks.length > policy.maxTasks)
      throw new Error("Investigation backlog exceeds configured task limit.");
    tasks.push(...caseTasks);
  }
  const byKind = Object.fromEntries(kinds.map(kind => [kind, 0])) as
    Record<InvestigationActionKind, number>;
  for (const task of tasks) byKind[task.kind]++;
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, assessedAt,
    complete: snapshot.complete && worklist.entries.every(item => item.completeCoverage),
    tasks, byKind,
    estimatedMinutes: tasks.reduce((sum, item) => sum + item.estimatedMinutes, 0),
    unassignedTasks: tasks.filter(item => !item.assignedAnalystId).length,
    warnings: [
      "Tasks are offline recommendations; none are executed or assigned.",
      "Estimated minutes are configurable assumptions, not measured completion times.",
      ...(!snapshot.complete ? ["Incomplete source collection may hide additional work."] : []),
    ],
  };
}
export function scheduleInvestigationBacklog(
  backlog: InvestigationBacklog,
): InvestigationSchedule {
  const indexed = new Map<string, InvestigationTask>();
  for (const task of backlog.tasks) {
    if (indexed.has(task.id)) throw new Error("Duplicate investigation task ID.");
    indexed.set(task.id, task);
  }
  const unresolved = new Set<string>();
  for (const task of backlog.tasks)
    for (const id of task.dependsOn)
      if (!indexed.has(id)) unresolved.add(id);
  const remaining = new Set(indexed.keys());
  const completed = new Set<string>();
  const waves: InvestigationExecutionWave[] = [];
  while (remaining.size) {
    const available = [...remaining].filter(id => {
      const task = indexed.get(id)!;
      return task.dependsOn.every(dependency => completed.has(dependency));
    }).sort((a, b) => {
      const left = indexed.get(a)!, right = indexed.get(b)!;
      return left.priority.localeCompare(right.priority) || a.localeCompare(b);
    });
    if (!available.length) break;
    waves.push({
      index: waves.length,
      taskIds: available,
      totalEstimatedMinutes: available.reduce((sum, id) =>
        sum + indexed.get(id)!.estimatedMinutes, 0),
      assignedAnalysts: [...new Set(available.map(id =>
        indexed.get(id)!.assignedAnalystId).filter((id): id is string => id !== null))].sort(),
    });
    for (const id of available) {
      remaining.delete(id);
      completed.add(id);
    }
  }
  return {
    organizationId: backlog.organizationId, waves,
    unresolvedDependencies: [...unresolved].sort(),
    cyclicTaskIds: [...remaining].sort(),
    executable: !remaining.size && !unresolved.size && backlog.complete,
  };
}
export type InvestigationDiff = {
  organizationId: string;
  added: string[];
  removed: string[];
  reassigned: string[];
  changedDependencies: string[];
  uncertain: string[];
};
export function compareInvestigationBacklogs(
  before: InvestigationBacklog, after: InvestigationBacklog,
): InvestigationDiff {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cannot compare investigation backlogs across organizations.");
  const old = new Map(before.tasks.map(item => [item.id, item]));
  const current = new Map(after.tasks.map(item => [item.id, item]));
  const added: string[] = [], removed: string[] = [];
  const reassigned: string[] = [], changedDependencies: string[] = [], uncertain: string[] = [];
  for (const id of [...new Set([...old.keys(), ...current.keys()])].sort()) {
    const a = old.get(id), b = current.get(id);
    if (!a || !b) {
      if (!before.complete || !after.complete) uncertain.push(id);
      else if (!a) added.push(id);
      else removed.push(id);
      continue;
    }
    if (!a.coverageComplete || !b.coverageComplete) {
      uncertain.push(id);
      continue;
    }
    if (a.assignedAnalystId !== b.assignedAnalystId) reassigned.push(id);
    if (JSON.stringify([...a.dependsOn].sort()) !== JSON.stringify([...b.dependsOn].sort()))
      changedDependencies.push(id);
  }
  return { organizationId: before.organizationId, added, removed,
    reassigned, changedDependencies, uncertain };
}
export function investigationBacklogCsv(backlog: InvestigationBacklog): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutralized.replace(/"/g, '""') + '"';
  };
  const lines = [["id", "caseKey", "workItemId", "kind", "priority",
    "dependsOn", "estimatedMinutes", "assignedAnalystId",
    "rationale", "coverageComplete"].map(safe).join(",")];
  for (const task of backlog.tasks)
    lines.push([task.id, task.caseKey, task.workItemId, task.kind,
      task.priority, task.dependsOn.join(";"), task.estimatedMinutes,
      task.assignedAnalystId, task.rationale, task.coverageComplete].map(safe).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function investigationBacklogJson(backlog: InvestigationBacklog): string {
  return JSON.stringify(backlog, null, 2) + "\n";
}
