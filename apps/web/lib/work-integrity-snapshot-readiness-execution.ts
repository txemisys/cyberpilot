import { createHash } from "node:crypto";
import {
  type ReadinessWorkQueue, type ReadinessWorkItem,
  validateReadinessWorkQueue,
} from "./work-integrity-snapshot-readiness-work";

/**
 * Derive a dependency-aware execution plan for remediation work proposals.
 * Dependencies are explicit item IDs, never inferred from unrelated tenants.
 * Cycles and missing predecessors are blockers, not silently ignored.
 */
export type WorkDependencyIssue =
  | "MISSING_DEPENDENCY" | "SELF_DEPENDENCY" | "CYCLIC_DEPENDENCY"
  | "BLOCKED_PREDECESSOR" | "UNRESOLVED_PREDECESSOR"
  | "OVERDUE_PREDECESSOR";
export type WorkDependencyFinding = {
  itemId: string;
  dependencyId: string;
  issue: WorkDependencyIssue;
  blocking: boolean;
  explanation: string;
};
export type WorkExecutionStage = {
  number: number;
  itemIds: string[];
  priority: string;
  dueAt: string | null;
  canStart: boolean;
  blockedBy: string[];
};
export type WorkExecutionPlan = {
  organizationId: string;
  evaluatedAt: string;
  totalItems: number;
  actionableItems: number;
  blockedItems: number;
  completedItems: number;
  stages: WorkExecutionStage[];
  findings: WorkDependencyFinding[];
  criticalPathItemIds: string[];
  planDigest: string;
  executable: boolean;
  limitations: string[];
};
export type WorkExecutionPolicy = {
  maxItems: number;
  maxDependenciesPerItem: number;
  maxStages: number;
  requirePredecessorCompletion: boolean;
  includeDismissedAsCompleted: boolean;
  blockOnOverduePredecessor: boolean;
};
function bounded(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new Error(`Invalid execution ${label}.`);
  return value;
}
function terminal(item: ReadinessWorkItem, includeDismissed: boolean): boolean {
  return item.state === "DONE" ||
    (includeDismissed && item.state === "DISMISSED");
}
function priorityRank(item: ReadinessWorkItem): number {
  return item.priority === "P0" ? 0 : item.priority === "P1" ? 1 :
    item.priority === "P2" ? 2 : 3;
}
function compare(a: ReadinessWorkItem, b: ReadinessWorkItem): number {
  return priorityRank(a) - priorityRank(b) ||
    (a.dueAt ?? "").localeCompare(b.dueAt ?? "") ||
    a.id.localeCompare(b.id);
}
export function planReadinessWorkExecution(
  queue: ReadinessWorkQueue, organizationId: string,
  evaluatedAt: string, policy: WorkExecutionPolicy,
): WorkExecutionPlan {
  const validation = validateReadinessWorkQueue(queue, organizationId);
  if (!validation.valid) throw new Error("Invalid readiness work queue.");
  const maxItems = bounded(policy.maxItems, 1, 10000, "item limit");
  const maxDependenciesPerItem = bounded(policy.maxDependenciesPerItem, 0, 1000,
    "dependency limit");
  const maxStages = bounded(policy.maxStages, 1, 10000, "stage limit");
  if (queue.items.length > maxItems)
    throw new Error("Execution item cardinality exceeded.");
  if (typeof policy.requirePredecessorCompletion !== "boolean" ||
      typeof policy.includeDismissedAsCompleted !== "boolean" ||
      typeof policy.blockOnOverduePredecessor !== "boolean")
    throw new Error("Invalid execution policy flags.");
  const now = Date.parse(evaluatedAt);
  if (!Number.isFinite(now)) throw new Error("Invalid execution evaluation time.");
  const byId = new Map(queue.items.map(item => [item.id, item]));
  const findings: WorkDependencyFinding[] = [];
  const graph = new Map<string, string[]>();
  const add = (itemId: string, dependencyId: string,
    issue: WorkDependencyIssue, blocking: boolean, explanation: string) =>
    findings.push({ itemId, dependencyId, issue, blocking, explanation });
  for (const item of queue.items) {
    if (!Array.isArray(item.dependencies) ||
        item.dependencies.length > maxDependenciesPerItem)
      throw new Error("Execution dependency cardinality exceeded.");
    const deps = [...new Set(item.dependencies)];
    graph.set(item.id, deps);
    for (const dependencyId of deps) {
      if (dependencyId === item.id)
        add(item.id, dependencyId, "SELF_DEPENDENCY", true,
          "An item cannot depend on itself.");
      const predecessor = byId.get(dependencyId);
      if (!predecessor) {
        add(item.id, dependencyId, "MISSING_DEPENDENCY", true,
          "The referenced predecessor does not exist in this work queue.");
        continue;
      }
      if (predecessor.organizationId !== organizationId)
        throw new Error("Cross-organization execution dependency forbidden.");
      if (predecessor.state === "BLOCKED")
        add(item.id, dependencyId, "BLOCKED_PREDECESSOR", true,
          "A predecessor is explicitly blocked.");
      if (!terminal(predecessor, policy.includeDismissedAsCompleted))
        add(item.id, dependencyId, "UNRESOLVED_PREDECESSOR",
          policy.requirePredecessorCompletion,
          "A predecessor has not been completed.");
      if (policy.blockOnOverduePredecessor &&
          predecessor.dueAt && Date.parse(predecessor.dueAt) < now &&
          !terminal(predecessor, policy.includeDismissedAsCompleted))
        add(item.id, dependencyId, "OVERDUE_PREDECESSOR", true,
          "An unresolved predecessor is past its due date.");
    }
  }
  const visited = new Set<string>();
  const visiting = new Set<string>();
  const cyclic = new Set<string>();
  function visit(id: string, stack: string[]): void {
    if (visiting.has(id)) {
      const offset = stack.indexOf(id);
      for (const member of stack.slice(offset)) cyclic.add(member);
      return;
    }
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependencyId of graph.get(id) ?? [])
      if (byId.has(dependencyId)) visit(dependencyId, [...stack, id]);
    visiting.delete(id);
    visited.add(id);
  }
  for (const item of queue.items) visit(item.id, []);
  for (const itemId of [...cyclic].sort())
    add(itemId, itemId, "CYCLIC_DEPENDENCY", true,
      "This item participates in a circular dependency chain.");
  const pending = new Map(queue.items.filter(item =>
    !terminal(item, policy.includeDismissedAsCompleted)).map(item => [item.id, item]));
  const stages: WorkExecutionStage[] = [];
  const scheduled = new Set<string>();
  while (pending.size && stages.length < maxStages) {
    const eligible = [...pending.values()].filter(item =>
      !cyclic.has(item.id) &&
      (graph.get(item.id) ?? []).every(dependencyId =>
        !pending.has(dependencyId) || scheduled.has(dependencyId)));
    if (!eligible.length) break;
    eligible.sort(compare);
    const stageIds = eligible.map(item => item.id);
    const blockedBy = [...new Set(eligible.flatMap(item =>
      findings.filter(finding => finding.itemId === item.id && finding.blocking)
        .map(finding => finding.dependencyId)))].sort();
    stages.push({
      number: stages.length + 1, itemIds: stageIds,
      priority: eligible[0]!.priority,
      dueAt: eligible.map(item => item.dueAt).filter(
        (value): value is string => value !== null).sort()[0] ?? null,
      canStart: blockedBy.length === 0,
      blockedBy,
    });
    for (const item of eligible) {
      pending.delete(item.id);
      scheduled.add(item.id);
    }
  }
  const unscheduled = [...pending.keys()];
  for (const itemId of unscheduled)
    if (!findings.some(finding => finding.itemId === itemId && finding.blocking))
      add(itemId, itemId, "CYCLIC_DEPENDENCY", true,
        "The item cannot be scheduled within the dependency graph.");
  const blockedIds = new Set(findings.filter(finding => finding.blocking)
    .map(finding => finding.itemId));
  for (const itemId of unscheduled) blockedIds.add(itemId);
  const criticalPathItemIds = stages.flatMap(stage => stage.itemIds).filter(id =>
    byId.get(id)?.priority === "P0");
  const normalized = {
    organizationId, evaluatedAt: new Date(now).toISOString(),
    stages: stages.map(stage => stage.itemIds),
    findings: findings.map(finding => [
      finding.itemId, finding.dependencyId, finding.issue, finding.blocking,
    ]).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
  };
  const planDigest = createHash("sha256").update(JSON.stringify(normalized))
    .digest("hex");
  findings.sort((a, b) => a.itemId.localeCompare(b.itemId) ||
    a.issue.localeCompare(b.issue) || a.dependencyId.localeCompare(b.dependencyId));
  return {
    organizationId, evaluatedAt: new Date(now).toISOString(),
    totalItems: queue.items.length,
    actionableItems: [...scheduled].filter(id => !blockedIds.has(id)).length,
    blockedItems: blockedIds.size,
    completedItems: queue.items.filter(item =>
      terminal(item, policy.includeDismissedAsCompleted)).length,
    stages, findings, criticalPathItemIds, planDigest,
    executable: blockedIds.size === 0 && unscheduled.length === 0,
    limitations: [
      "Stages are a logical plan and do not execute remediation actions.",
      "The plan uses caller-supplied work states and cannot verify real-world completion.",
      "The digest detects plan changes only against an independently trusted reference.",
    ],
  };
}
