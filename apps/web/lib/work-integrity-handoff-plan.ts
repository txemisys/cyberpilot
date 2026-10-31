import type { CaseSnapshot } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";
import { buildEvidenceReadiness, type EvidenceRequirement } from "./work-integrity-evidence-readiness";
import { forecastReviewCapacity, type CapacityPolicy } from "./work-integrity-capacity";
import { evaluateSlaPlan, createSlaPlan, type SlaPolicy, DEFAULT_SLA_POLICY } from "./work-integrity-sla";

/** Immutable offline operational handoff planning. No real assignment is created. */
export type HandoffPlanPolicy = {
  maxPackets: number;
  maxCasesPerPacket: number;
  requireCompleteCapture: boolean;
  includeHistorical: boolean;
  includeReviewed: boolean;
  groupBy: "PRIORITY" | "WORK_ITEM" | "DIAGNOSTIC";
};
export type HandoffPlanCase = {
  caseKey: string;
  workItemId: string;
  resourceId: string;
  diagnosticCode: string;
  priority: "P0" | "P1" | "P2" | "P3" | "P4";
  reviewState: string;
  evidenceReady: boolean;
  evidenceGaps: string[];
  coverageComplete: boolean;
  estimatedMinutes: number | null;
  assignedAnalystId: string | null;
  slaPhase: string;
  nextAction: string;
};
export type HandoffPlanPacket = {
  id: string;
  groupKey: string;
  organizationId: string;
  capturedAt: string;
  assessedAt: string;
  cases: HandoffPlanCase[];
  totalEstimatedMinutes: number;
  evidenceReady: number;
  evidenceBlocked: number;
  unassigned: number;
  urgent: number;
  complete: boolean;
  warnings: string[];
};
export type HandoffPlan = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  assessedAt: string;
  complete: boolean;
  packets: HandoffPlanPacket[];
  totalCases: number;
  omittedCases: number;
  unassignedCases: number;
  evidenceBlockedCases: number;
  warnings: string[];
};
export type HandoffPlanDiff = {
  organizationId: string;
  newCaseKeys: string[];
  removedCaseKeys: string[];
  reassignedCaseKeys: string[];
  evidenceImprovedCaseKeys: string[];
  evidenceDegradedCaseKeys: string[];
  uncertainCaseKeys: string[];
};
export const DEFAULT_HANDOFF_PLAN_POLICY: HandoffPlanPolicy = {
  maxPackets: 1000, maxCasesPerPacket: 25,
  requireCompleteCapture: true, includeHistorical: false,
  includeReviewed: true, groupBy: "PRIORITY",
};
export function validateHandoffPlanPolicy(policy: HandoffPlanPolicy): HandoffPlanPolicy {
  if (!policy || !Number.isSafeInteger(policy.maxPackets) ||
      policy.maxPackets < 1 || policy.maxPackets > 10000 ||
      !Number.isSafeInteger(policy.maxCasesPerPacket) ||
      policy.maxCasesPerPacket < 1 || policy.maxCasesPerPacket > 10000)
    throw new Error("Invalid handoff packet bounds.");
  if (typeof policy.requireCompleteCapture !== "boolean" ||
      typeof policy.includeHistorical !== "boolean" ||
      typeof policy.includeReviewed !== "boolean" ||
      !["PRIORITY", "WORK_ITEM", "DIAGNOSTIC"].includes(policy.groupBy))
    throw new Error("Invalid handoff policy.");
  return { ...policy };
}
export function createHandoffPlan(
  snapshot: CaseSnapshot,
  assessedAt: string,
  capacityPolicy: CapacityPolicy,
  requirements: readonly EvidenceRequirement[],
  policy: HandoffPlanPolicy = DEFAULT_HANDOFF_PLAN_POLICY,
  slaPolicy: SlaPolicy = DEFAULT_SLA_POLICY,
): HandoffPlan {
  const config = validateHandoffPlanPolicy(policy);
  if (config.requireCompleteCapture && !snapshot.complete)
    throw new Error("Cannot create complete handoff from partial capture.");
  const worklist = buildReviewWorklist(snapshot);
  const evidence = buildEvidenceReadiness(snapshot, requirements);
  const capacity = forecastReviewCapacity(snapshot, capacityPolicy);
  const sla = evaluateSlaPlan(createSlaPlan(snapshot, slaPolicy), assessedAt, slaPolicy);
  const evidenceByKey = new Map(evidence.packets.map(item => [item.caseKey, item]));
  const demandByKey = new Map(capacity.demand.map(item => [item.caseKey, item]));
  const ownerByKey = new Map(capacity.allocations.flatMap(allocation =>
    allocation.caseKeys.map(key => [key, allocation.analystId] as const)));
  const slaByKey = new Map(sla.evaluations.map(item => [item.caseKey, item.phase]));
  const eligible = worklist.entries.filter(item =>
    (config.includeHistorical || !item.historicalOnly) &&
    (config.includeReviewed || !item.reviewEventId));
  const groups = new Map<string, HandoffPlanCase[]>();
  for (const item of eligible) {
    const groupKey = config.groupBy === "PRIORITY" ? item.priority :
      config.groupBy === "WORK_ITEM" ? item.workItemId : item.code;
    const evidencePacket = evidenceByKey.get(item.caseKey);
    const entry: HandoffPlanCase = {
      caseKey: item.caseKey, workItemId: item.workItemId,
      resourceId: item.resourceId, diagnosticCode: item.code,
      priority: item.priority, reviewState: item.state,
      evidenceReady: evidencePacket?.readyForHumanReview ?? false,
      evidenceGaps: evidencePacket?.gaps.map(gap => gap.field) ?? ["missingPacket"],
      coverageComplete: item.completeCoverage && snapshot.complete,
      estimatedMinutes: demandByKey.get(item.caseKey)?.estimatedMinutes ?? null,
      assignedAnalystId: ownerByKey.get(item.caseKey) ?? null,
      slaPhase: slaByKey.get(item.caseKey) ?? "UNKNOWN",
      nextAction: item.suggestedAction,
    };
    const existing = groups.get(groupKey) ?? [];
    existing.push(entry);
    groups.set(groupKey, existing);
  }
  const packets: HandoffPlanPacket[] = [];
  for (const groupKey of [...groups.keys()].sort()) {
    const items = groups.get(groupKey)!;
    for (let offset = 0; offset < items.length; offset += config.maxCasesPerPacket) {
      if (packets.length >= config.maxPackets)
        throw new Error("Handoff exceeds maximum packet count.");
      const cases = items.slice(offset, offset + config.maxCasesPerPacket);
      const incomplete = cases.some(item => !item.coverageComplete);
      const urgent = cases.filter(item =>
        ["ESCALATED", "ACK_OVERDUE", "RESOLUTION_OVERDUE"].includes(item.slaPhase)).length;
      packets.push({
        id: JSON.stringify([snapshot.organizationId, snapshot.capturedAt, groupKey,
          Math.floor(offset / config.maxCasesPerPacket)]),
        groupKey, organizationId: snapshot.organizationId,
        capturedAt: snapshot.capturedAt, assessedAt, cases,
        totalEstimatedMinutes: cases.reduce((sum, item) => sum + (item.estimatedMinutes ?? 0), 0),
        evidenceReady: cases.filter(item => item.evidenceReady).length,
        evidenceBlocked: cases.filter(item => !item.evidenceReady).length,
        unassigned: cases.filter(item => !item.assignedAnalystId).length,
        urgent, complete: !incomplete,
        warnings: [
          ...(incomplete ? ["Some linked evidence is incomplete."] : []),
          ...(urgent ? ["Some SLA planning thresholds have elapsed."] : []),
          ...(cases.some(item => !item.assignedAnalystId)
            ? ["Some cases have no eligible capacity allocation."] : []),
        ],
      });
    }
  }
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, assessedAt,
    complete: snapshot.complete && packets.every(item => item.complete),
    packets, totalCases: eligible.length,
    omittedCases: snapshot.cases.length - eligible.length,
    unassignedCases: packets.reduce((sum, item) => sum + item.unassigned, 0),
    evidenceBlockedCases: packets.reduce((sum, item) => sum + item.evidenceBlocked, 0),
    warnings: [
      "This is an offline planning artifact, not a completed review or verified remediation.",
      "Capacity allocations are recommendations and do not create real assignments.",
      ...(!snapshot.complete ? ["Partial source capture can omit other cases."] : []),
    ],
  };
}
export function compareHandoffPlans(
  before: HandoffPlan, after: HandoffPlan,
): HandoffPlanDiff {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cannot compare handoffs across organizations.");
  const old = new Map(before.packets.flatMap(packet =>
    packet.cases.map(item => [item.caseKey, item] as const)));
  const current = new Map(after.packets.flatMap(packet =>
    packet.cases.map(item => [item.caseKey, item] as const)));
  const newCaseKeys: string[] = [], removedCaseKeys: string[] = [];
  const reassignedCaseKeys: string[] = [], evidenceImprovedCaseKeys: string[] = [];
  const evidenceDegradedCaseKeys: string[] = [], uncertainCaseKeys: string[] = [];
  for (const key of [...new Set([...old.keys(), ...current.keys()])].sort()) {
    const a = old.get(key), b = current.get(key);
    if (!a || !b) {
      if (!before.complete || !after.complete) uncertainCaseKeys.push(key);
      else if (!a) newCaseKeys.push(key);
      else removedCaseKeys.push(key);
      continue;
    }
    if (!a.coverageComplete || !b.coverageComplete) {
      uncertainCaseKeys.push(key);
      continue;
    }
    if (a.assignedAnalystId !== b.assignedAnalystId) reassignedCaseKeys.push(key);
    if (!a.evidenceReady && b.evidenceReady) evidenceImprovedCaseKeys.push(key);
    if (a.evidenceReady && !b.evidenceReady) evidenceDegradedCaseKeys.push(key);
  }
  return {
    organizationId: before.organizationId, newCaseKeys, removedCaseKeys,
    reassignedCaseKeys, evidenceImprovedCaseKeys,
    evidenceDegradedCaseKeys, uncertainCaseKeys,
  };
}
export function handoffPlanCsv(manifest: HandoffPlan): string {
  const safe = (value: unknown) => {
    const raw = String(value ?? "");
    const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + neutralized.replace(/"/g, '""') + '"';
  };
  const lines = [["packetId", "caseKey", "workItemId", "resourceId",
    "diagnosticCode", "priority", "reviewState", "evidenceReady",
    "evidenceGaps", "coverageComplete", "estimatedMinutes",
    "assignedAnalystId", "slaPhase", "nextAction"].map(safe).join(",")];
  for (const packet of manifest.packets)
    for (const item of packet.cases)
      lines.push([packet.id, item.caseKey, item.workItemId, item.resourceId,
        item.diagnosticCode, item.priority, item.reviewState, item.evidenceReady,
        item.evidenceGaps.join(";"), item.coverageComplete, item.estimatedMinutes,
        item.assignedAnalystId, item.slaPhase, item.nextAction].map(safe).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function handoffPlanJson(manifest: HandoffPlan): string {
  return JSON.stringify(manifest, null, 2) + "\n";
}
