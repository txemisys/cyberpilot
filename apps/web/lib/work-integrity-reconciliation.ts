import type { CaseRow } from "./work-integrity-cases";
import type { CaseSnapshot } from "./work-integrity-snapshots";
import { compareCaseSnapshots } from "./work-integrity-snapshots";
import { buildEvidenceReadiness, type EvidenceRequirement } from "./work-integrity-evidence-readiness";
import { buildHandoffManifest, type HandoffPolicy } from "./work-integrity-handoff";

/** Read-only reconciliation of review ownership and evidence readiness. */
export type ReconciliationStatus =
  | "READY_ASSIGNED" | "READY_UNASSIGNED" | "BLOCKED_ASSIGNED"
  | "BLOCKED_UNASSIGNED" | "HISTORICAL" | "INDETERMINATE";
export type ReconciliationRow = {
  caseKey: string;
  workItemId: string;
  code: string;
  priority: string;
  status: ReconciliationStatus;
  recipientId: string | null;
  evidenceReady: boolean;
  missingFields: string[];
  currentRevision: number;
  reviewEventId: string | null;
  completeCoverage: boolean;
};
export type ReconciliationReport = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  complete: boolean;
  total: number;
  rows: ReconciliationRow[];
  byStatus: Record<ReconciliationStatus, number>;
  byRecipient: Record<string, number>;
  unassigned: number;
  blocked: number;
  warnings: string[];
};
export type ReconciliationDiff = {
  organizationId: string;
  complete: boolean;
  newlyReady: string[];
  newlyBlocked: string[];
  newlyAssigned: string[];
  newlyUnassigned: string[];
  changedRecipient: string[];
  uncertain: string[];
};
const statuses: ReconciliationStatus[] = [
  "READY_ASSIGNED", "READY_UNASSIGNED", "BLOCKED_ASSIGNED",
  "BLOCKED_UNASSIGNED", "HISTORICAL", "INDETERMINATE",
];
export function reconcileReviewReadiness(
  snapshot: CaseSnapshot,
  handoffPolicy: HandoffPolicy,
  evidenceRequirements: readonly EvidenceRequirement[],
): ReconciliationReport {
  const handoff = buildHandoffManifest(snapshot, handoffPolicy);
  const readiness = buildEvidenceReadiness(snapshot, evidenceRequirements);
  const assignments = new Map(handoff.items.map(item => [item.key, item]));
  const packets = new Map(readiness.packets.map(packet => [packet.caseKey, packet]));
  const rows = snapshot.cases.map(row => {
    const packet = packets.get(row.key)!;
    const handoffItem = assignments.get(row.key);
    const recipientId = handoffItem?.recipientId ?? null;
    const evidenceReady = packet.readyForHumanReview;
    const status: ReconciliationStatus =
      !snapshot.complete || !row.completeCoverage ? "INDETERMINATE" :
      row.historicalOnly ? "HISTORICAL" :
      evidenceReady ? recipientId ? "READY_ASSIGNED" : "READY_UNASSIGNED" :
      recipientId ? "BLOCKED_ASSIGNED" : "BLOCKED_UNASSIGNED";
    return {
      caseKey: row.key, workItemId: row.workItemId, code: row.code,
      priority: handoffItem?.priority ?? "P4", status, recipientId,
      evidenceReady, missingFields: [...new Set(packet.gaps.map(gap => gap.field))].sort(),
      currentRevision: row.taskRevision, reviewEventId: row.reviewEventId,
      completeCoverage: row.completeCoverage,
    };
  }).sort((a, b) => a.status.localeCompare(b.status) || a.caseKey.localeCompare(b.caseKey));
  const byStatus = Object.fromEntries(statuses.map(status => [status, 0])) as Record<ReconciliationStatus, number>;
  const byRecipient: Record<string, number> = {};
  for (const row of rows) {
    byStatus[row.status]++;
    if (row.recipientId) byRecipient[row.recipientId] = (byRecipient[row.recipientId] ?? 0) + 1;
  }
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, complete: snapshot.complete,
    total: rows.length, rows, byStatus, byRecipient,
    unassigned: rows.filter(row => row.recipientId === null).length,
    blocked: rows.filter(row => !row.evidenceReady).length,
    warnings: [
      "A ready and assigned case is prepared for review, not resolved or verified.",
      ...(!snapshot.complete ? ["Incomplete source coverage prevents definitive readiness conclusions."] : []),
      ...handoff.warnings,
    ],
  };
}
export function compareReconciliationReports(
  before: ReconciliationReport, after: ReconciliationReport,
): ReconciliationDiff {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cannot compare reconciliation reports across organizations.");
  const old = new Map(before.rows.map(row => [row.caseKey, row]));
  const current = new Map(after.rows.map(row => [row.caseKey, row]));
  const newlyReady: string[] = [];
  const newlyBlocked: string[] = [];
  const newlyAssigned: string[] = [];
  const newlyUnassigned: string[] = [];
  const changedRecipient: string[] = [];
  const uncertain: string[] = [];
  for (const key of new Set([...old.keys(), ...current.keys()])) {
    const previous = old.get(key);
    const next = current.get(key);
    if (!previous || !next) {
      if (!before.complete || !after.complete) uncertain.push(key);
      continue;
    }
    if (previous.status === "INDETERMINATE" || next.status === "INDETERMINATE") {
      uncertain.push(key);
      continue;
    }
    if (!previous.evidenceReady && next.evidenceReady) newlyReady.push(key);
    if (previous.evidenceReady && !next.evidenceReady) newlyBlocked.push(key);
    if (!previous.recipientId && next.recipientId) newlyAssigned.push(key);
    if (previous.recipientId && !next.recipientId) newlyUnassigned.push(key);
    if (previous.recipientId && next.recipientId &&
        previous.recipientId !== next.recipientId) changedRecipient.push(key);
  }
  return {
    organizationId: before.organizationId,
    complete: before.complete && after.complete,
    newlyReady: newlyReady.sort(), newlyBlocked: newlyBlocked.sort(),
    newlyAssigned: newlyAssigned.sort(), newlyUnassigned: newlyUnassigned.sort(),
    changedRecipient: changedRecipient.sort(), uncertain: uncertain.sort(),
  };
}
export type ReconciliationAction = {
  caseKey: string;
  action: "RECOLLECT" | "COMPLETE_EVIDENCE" | "ASSIGN_REVIEWER" | "REASSESS" | "REVIEW";
  priority: number;
  explanation: string;
};
export function reconciliationActions(report: ReconciliationReport): ReconciliationAction[] {
  const actions: ReconciliationAction[] = [];
  for (const row of report.rows) {
    if (row.status === "INDETERMINATE") actions.push({
      caseKey: row.caseKey, action: "RECOLLECT", priority: 1,
      explanation: "Capture or linked record coverage is incomplete.",
    });
    else if (row.missingFields.includes("revision")) actions.push({
      caseKey: row.caseKey, action: "REASSESS", priority: 2,
      explanation: "Recorded review does not match the current task revision.",
    });
    else if (!row.evidenceReady) actions.push({
      caseKey: row.caseKey, action: "COMPLETE_EVIDENCE", priority: 3,
      explanation: "Required evidence fields or human review are missing.",
    });
    if (!row.recipientId && row.status !== "HISTORICAL") actions.push({
      caseKey: row.caseKey, action: "ASSIGN_REVIEWER", priority: 4,
      explanation: "No eligible reviewer has been assigned within the configured capacity.",
    });
    if (row.evidenceReady && row.recipientId) actions.push({
      caseKey: row.caseKey, action: "REVIEW", priority: 5,
      explanation: "Packet is prepared for an authorized human review.",
    });
  }
  return actions.sort((a, b) => a.priority - b.priority || a.caseKey.localeCompare(b.caseKey));
}
export function reconciliationCsv(report: ReconciliationReport): string {
  const safe = (value: unknown) => {
    const text = String(value ?? "");
    const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(text) ? "'" + text : text;
    return '"' + neutralized.replace(/"/g, '""') + '"';
  };
  const lines = [[
    "caseKey", "workItemId", "code", "priority", "status",
    "recipientId", "evidenceReady", "missingFields", "currentRevision",
    "reviewEventId", "completeCoverage",
  ].map(safe).join(",")];
  for (const row of report.rows) lines.push([
    row.caseKey, row.workItemId, row.code, row.priority, row.status,
    row.recipientId, row.evidenceReady, row.missingFields.join(";"),
    row.currentRevision, row.reviewEventId, row.completeCoverage,
  ].map(safe).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function reconciliationJson(report: ReconciliationReport): string {
  return JSON.stringify(report, null, 2) + "\n";
}
export function snapshotReconciliationDiff(
  before: CaseSnapshot, after: CaseSnapshot,
  policy: HandoffPolicy, requirements: readonly EvidenceRequirement[],
) {
  const diagnosticChanges = compareCaseSnapshots(before, after);
  const old = reconcileReviewReadiness(before, policy, requirements);
  const current = reconcileReviewReadiness(after, policy, requirements);
  return {
    diagnosticChanges,
    reconciliationChanges: compareReconciliationReports(old, current),
    currentActions: reconciliationActions(current),
  };
}
