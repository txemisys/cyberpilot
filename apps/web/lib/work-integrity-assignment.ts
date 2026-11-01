import type { CaseRow } from "./work-integrity-cases";
import type { CaseSnapshot } from "./work-integrity-snapshots";
import { compareCaseSnapshots } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";

/**
 * Review handoff manifests for analysts. These manifests are transport-neutral
 * and do not grant access or perform state transitions.
 */
export type AnalystAssignment = {
  analystId: string;
  caseKeys: string[];
  priority: "P0" | "P1" | "P2" | "P3" | "P4";
};
export type AssignmentPlan = {
  organizationId: string;
  capturedAt: string;
  assignments: AnalystAssignment[];
  unassigned: string[];
  complete: boolean;
  warnings: string[];
};
export type AssignmentOptions = {
  analystIds: string[];
  maxCasesPerAnalyst: number;
  includeReviewed: boolean;
  includeHistorical: boolean;
};
function uniqueAnalysts(ids: readonly string[]): string[] {
  if (!ids.length || ids.length > 100) throw new Error("Provide 1–100 analysts.");
  if (ids.some(id => typeof id !== "string" || !id.trim() || id.length > 200))
    throw new Error("Invalid analyst identifier.");
  if (new Set(ids).size !== ids.length) throw new Error("Duplicate analyst identifier.");
  return [...ids].sort();
}
export function buildAssignmentPlan(
  snapshot: CaseSnapshot,
  options: AssignmentOptions,
): AssignmentPlan {
  const analysts = uniqueAnalysts(options.analystIds);
  const maxCases = options.maxCasesPerAnalyst;
  if (!Number.isSafeInteger(maxCases) || maxCases < 1 || maxCases > 1000)
    throw new Error("Invalid analyst capacity.");
  const queue = buildReviewWorklist(snapshot).entries.filter(entry =>
    (options.includeReviewed || !entry.reviewEventId) &&
    (options.includeHistorical || !entry.historicalOnly));
  const assignments = analysts.map(analystId => ({
    analystId, caseKeys: [] as string[],
    priority: "P4" as AnalystAssignment["priority"],
  }));
  const unassigned: string[] = [];
  const ranks = ["P0", "P1", "P2", "P3", "P4"];
  for (const entry of queue) {
    const candidate = assignments
      .filter(assignment => assignment.caseKeys.length < maxCases)
      .sort((a, b) => a.caseKeys.length - b.caseKeys.length ||
        a.analystId.localeCompare(b.analystId))[0];
    if (!candidate) {
      unassigned.push(entry.caseKey);
      continue;
    }
    candidate.caseKeys.push(entry.caseKey);
    if (ranks.indexOf(entry.priority) < ranks.indexOf(candidate.priority))
      candidate.priority = entry.priority;
  }
  return {
    organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt,
    assignments, unassigned, complete: snapshot.complete,
    warnings: [
      "Assignments are planning recommendations; they do not modify access controls or review ownership.",
      ...(!snapshot.complete ? ["Incomplete case coverage may omit additional workload."] : []),
      ...(unassigned.length ? ["Some cases exceed configured analyst capacity."] : []),
    ],
  };
}
export type AssignmentDrift = {
  removed: string[];
  added: string[];
  changed: Array<{ caseKey: string; from: string; to: string }>;
  retained: number;
  unknown: string[];
};
export function compareAssignmentPlans(
  before: AssignmentPlan, after: AssignmentPlan,
): AssignmentDrift {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cannot compare assignment plans across organizations.");
  const index = (plan: AssignmentPlan) => {
    const map = new Map<string, string>();
    for (const assignment of plan.assignments) {
      for (const key of assignment.caseKeys) {
        if (map.has(key)) throw new Error("Duplicate case assignment.");
        map.set(key, assignment.analystId);
      }
    }
    return map;
  };
  const old = index(before);
  const current = index(after);
  const removed: string[] = [];
  const added: string[] = [];
  const changed: AssignmentDrift["changed"] = [];
  const unknown: string[] = [];
  let retained = 0;
  for (const [key, analyst] of old) {
    const next = current.get(key);
    if (!next) {
      if (before.complete && after.complete) removed.push(key);
      else unknown.push(key);
    } else if (next !== analyst) changed.push({ caseKey: key, from: analyst, to: next });
    else retained++;
  }
  for (const key of current.keys()) {
    if (old.has(key)) continue;
    if (before.complete && after.complete) added.push(key);
    else unknown.push(key);
  }
  return {
    removed: removed.sort(), added: added.sort(),
    changed: changed.sort((a, b) => a.caseKey.localeCompare(b.caseKey)),
    retained, unknown: unknown.sort(),
  };
}
export type ReviewCoverageGap = {
  caseKey: string;
  workItemId: string;
  reason: "UNASSIGNED" | "STALE_REVIEW" | "INCOMPLETE_LINKS" | "NO_REVIEW";
  severity: CaseRow["severity"];
};
export function reviewCoverageGaps(
  snapshot: CaseSnapshot, plan: AssignmentPlan,
): ReviewCoverageGap[] {
  if (snapshot.organizationId !== plan.organizationId)
    throw new Error("Review coverage scope mismatch.");
  const assigned = new Set(plan.assignments.flatMap(x => x.caseKeys));
  const gaps: ReviewCoverageGap[] = [];
  for (const row of snapshot.cases) {
    if (!assigned.has(row.key) && row.reviewEventId === null)
      gaps.push({ caseKey: row.key, workItemId: row.workItemId,
        reason: "UNASSIGNED", severity: row.severity });
    if (row.state === "STALE")
      gaps.push({ caseKey: row.key, workItemId: row.workItemId,
        reason: "STALE_REVIEW", severity: row.severity });
    if (!row.completeCoverage)
      gaps.push({ caseKey: row.key, workItemId: row.workItemId,
        reason: "INCOMPLETE_LINKS", severity: row.severity });
    if (row.reviewEventId === null)
      gaps.push({ caseKey: row.key, workItemId: row.workItemId,
        reason: "NO_REVIEW", severity: row.severity });
  }
  return gaps.sort((a, b) => a.caseKey.localeCompare(b.caseKey) ||
    a.reason.localeCompare(b.reason));
}
export function assignmentPlanJson(plan: AssignmentPlan): string {
  return JSON.stringify(plan, null, 2) + "\n";
}
export function changedAssignmentCases(
  before: CaseSnapshot, after: CaseSnapshot,
): string[] {
  return compareCaseSnapshots(before, after).deltas
    .filter(x => x.kind !== "UNCHANGED")
    .map(x => x.key).sort();
}
