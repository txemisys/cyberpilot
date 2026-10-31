import type { CaseRow } from "./work-integrity-cases";
import type { CaseSnapshot } from "./work-integrity-snapshots";
import { compareCaseSnapshots } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";

/** Evidence preparation packets are immutable review aids, not proof of remediation. */
export type EvidenceRequirement = {
  id: string;
  diagnosticCodes: string[];
  mandatoryFields: Array<"diagnostic" | "recommendation" | "reviewRationale" |
    "reviewReference" | "reviewedAt" | "reviewEventId">;
  requireCurrentRevision: boolean;
  requireCompleteCoverage: boolean;
  requireHumanReview: boolean;
};
export type EvidenceGap = {
  caseKey: string;
  requirementId: string;
  field: string;
  reason: string;
  blocking: boolean;
};
export type EvidencePacket = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  caseKey: string;
  workItemId: string;
  diagnosticCode: string;
  resourceId: string;
  revision: number;
  state: CaseRow["state"];
  reviewEventId: string | null;
  reviewReference: string | null;
  reviewRationale: string | null;
  completeCoverage: boolean;
  requirements: string[];
  gaps: EvidenceGap[];
  readyForHumanReview: boolean;
  caveats: string[];
};
export type EvidenceReadiness = {
  total: number;
  ready: number;
  blocked: number;
  missingReview: number;
  staleReview: number;
  incompleteCoverage: number;
  byCode: Record<string, { total: number; ready: number; blocked: number }>;
  packets: EvidencePacket[];
};
const fields = [
  "diagnostic", "recommendation", "reviewRationale", "reviewReference",
  "reviewedAt", "reviewEventId",
] as const;
export function validateEvidenceRequirements(
  requirements: readonly EvidenceRequirement[],
): EvidenceRequirement[] {
  if (requirements.length > 100) throw new Error("Too many evidence requirements.");
  const seen = new Set<string>();
  return requirements.map(requirement => {
    if (typeof requirement.id !== "string" || !requirement.id.trim() ||
        requirement.id.length > 100)
      throw new Error("Invalid evidence requirement ID.");
    if (seen.has(requirement.id)) throw new Error("Duplicate evidence requirement.");
    seen.add(requirement.id);
    if (!Array.isArray(requirement.diagnosticCodes) ||
        requirement.diagnosticCodes.length > 100 ||
        requirement.diagnosticCodes.some(code => typeof code !== "string" || !code.trim()))
      throw new Error("Invalid evidence diagnostic codes.");
    if (!Array.isArray(requirement.mandatoryFields) ||
        requirement.mandatoryFields.some(field => !fields.includes(field)))
      throw new Error("Invalid evidence fields.");
    if (typeof requirement.requireCurrentRevision !== "boolean" ||
        typeof requirement.requireCompleteCoverage !== "boolean" ||
        typeof requirement.requireHumanReview !== "boolean")
      throw new Error("Invalid evidence requirement flags.");
    return { ...requirement,
      diagnosticCodes: [...new Set(requirement.diagnosticCodes)].sort(),
      mandatoryFields: [...new Set(requirement.mandatoryFields)] };
  });
}
export function applicableEvidenceRequirements(
  row: CaseRow, requirements: readonly EvidenceRequirement[],
): EvidenceRequirement[] {
  return requirements.filter(requirement =>
    !requirement.diagnosticCodes.length || requirement.diagnosticCodes.includes(row.code));
}
function fieldPresent(row: CaseRow, field: EvidenceRequirement["mandatoryFields"][number]): boolean {
  const value = row[field];
  return typeof value === "string" ? value.trim().length > 0 : value !== null && value !== undefined;
}
export function buildEvidencePacket(
  snapshot: CaseSnapshot, row: CaseRow,
  requirements: readonly EvidenceRequirement[],
): EvidencePacket {
  if (!snapshot.cases.some(candidate => candidate.key === row.key))
    throw new Error("Case is not part of the selected snapshot.");
  const selected = applicableEvidenceRequirements(row, validateEvidenceRequirements(requirements));
  const gaps: EvidenceGap[] = [];
  for (const requirement of selected) {
    for (const field of requirement.mandatoryFields) {
      if (!fieldPresent(row, field)) gaps.push({
        caseKey: row.key, requirementId: requirement.id, field,
        reason: `Required field ${field} is absent.`, blocking: true,
      });
    }
    if (requirement.requireHumanReview && !row.reviewEventId)
      gaps.push({ caseKey: row.key, requirementId: requirement.id,
        field: "humanReview", reason: "No human review event is recorded.", blocking: true });
    if (requirement.requireCurrentRevision &&
        (row.reviewedRevision === null || row.reviewedRevision !== row.taskRevision))
      gaps.push({ caseKey: row.key, requirementId: requirement.id,
        field: "revision", reason: "Review is not tied to the current work item revision.", blocking: true });
    if (requirement.requireCompleteCoverage && !row.completeCoverage)
      gaps.push({ caseKey: row.key, requirementId: requirement.id,
        field: "coverage", reason: "Linked-record coverage is incomplete.", blocking: true });
  }
  if (!snapshot.complete) gaps.push({
    caseKey: row.key, requirementId: "snapshot",
    field: "snapshotCoverage", reason: "Snapshot collection is incomplete.", blocking: true,
  });
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, caseKey: row.key,
    workItemId: row.workItemId, diagnosticCode: row.code,
    resourceId: row.resourceId, revision: row.taskRevision,
    state: row.state, reviewEventId: row.reviewEventId,
    reviewReference: row.reviewReference, reviewRationale: row.reviewRationale,
    completeCoverage: row.completeCoverage,
    requirements: selected.map(item => item.id),
    gaps, readyForHumanReview: gaps.every(gap => !gap.blocking),
    caveats: [
      "Readiness means the configured evidence fields are present; it does not prove their authenticity.",
      "A complete review packet does not establish verified remediation or control effectiveness.",
    ],
  };
}
export function buildEvidenceReadiness(
  snapshot: CaseSnapshot, requirements: readonly EvidenceRequirement[],
): EvidenceReadiness {
  const validated = validateEvidenceRequirements(requirements);
  const packets = snapshot.cases.map(row => buildEvidencePacket(snapshot, row, validated));
  const byCode: EvidenceReadiness["byCode"] = {};
  for (const packet of packets) {
    const counts = byCode[packet.diagnosticCode] ?? { total: 0, ready: 0, blocked: 0 };
    counts.total++;
    if (packet.readyForHumanReview) counts.ready++;
    else counts.blocked++;
    byCode[packet.diagnosticCode] = counts;
  }
  return {
    total: packets.length,
    ready: packets.filter(packet => packet.readyForHumanReview).length,
    blocked: packets.filter(packet => !packet.readyForHumanReview).length,
    missingReview: snapshot.cases.filter(row => !row.reviewEventId).length,
    staleReview: snapshot.cases.filter(row =>
      row.reviewEventId && row.reviewedRevision !== row.taskRevision).length,
    incompleteCoverage: snapshot.cases.filter(row => !row.completeCoverage).length,
    byCode, packets,
  };
}
export type EvidenceDrift = {
  caseKey: string;
  kind: string;
  beforeReady: boolean | null;
  afterReady: boolean | null;
  addedGaps: string[];
  removedGaps: string[];
  uncertain: boolean;
};
export function compareEvidenceReadiness(
  before: CaseSnapshot, after: CaseSnapshot,
  requirements: readonly EvidenceRequirement[],
): EvidenceDrift[] {
  const comparison = compareCaseSnapshots(before, after);
  const old = new Map(buildEvidenceReadiness(before, requirements).packets.map(packet => [packet.caseKey, packet]));
  const current = new Map(buildEvidenceReadiness(after, requirements).packets.map(packet => [packet.caseKey, packet]));
  return comparison.deltas.map(delta => {
    const previous = old.get(delta.key);
    const next = current.get(delta.key);
    const beforeGaps = new Set(previous?.gaps.map(gap => `${gap.requirementId}:${gap.field}`) ?? []);
    const afterGaps = new Set(next?.gaps.map(gap => `${gap.requirementId}:${gap.field}`) ?? []);
    return {
      caseKey: delta.key, kind: delta.kind,
      beforeReady: previous?.readyForHumanReview ?? null,
      afterReady: next?.readyForHumanReview ?? null,
      addedGaps: [...afterGaps].filter(key => !beforeGaps.has(key)).sort(),
      removedGaps: [...beforeGaps].filter(key => !afterGaps.has(key)).sort(),
      uncertain: delta.kind === "INDETERMINATE",
    };
  });
}
export type EvidenceReviewQueue = {
  caseKey: string;
  priority: string;
  missing: string[];
  action: string;
};
export function evidenceReviewQueue(readiness: EvidenceReadiness): EvidenceReviewQueue[] {
  const packets = new Map(readiness.packets.map(packet => [packet.caseKey, packet]));
  return readiness.packets.filter(packet => !packet.readyForHumanReview).map(packet => ({
    caseKey: packet.caseKey,
    priority: packet.gaps.some(gap => gap.field === "revision") ? "REASSESS" :
      packet.gaps.some(gap => gap.field === "coverage" || gap.field === "snapshotCoverage")
        ? "RECOLLECT" : "REVIEW",
    missing: [...new Set(packet.gaps.map(gap => gap.field))].sort(),
    action: packet.gaps.some(gap => gap.field === "coverage" || gap.field === "snapshotCoverage")
      ? "Collect complete source records before evaluating this packet."
      : "Supply missing evidence metadata and perform authorized human review.",
  })).sort((a, b) => a.priority.localeCompare(b.priority) || a.caseKey.localeCompare(b.caseKey));
}
export function evidencePacketJson(packet: EvidencePacket): string {
  return JSON.stringify(packet, null, 2) + "\n";
}
export function evidenceReadinessCsv(readiness: EvidenceReadiness): string {
  const safe = (value: unknown) => {
    const text = String(value ?? "");
    const neutralized = /^[\s\u0000-\u001f]*[=+@\-]/.test(text) ? "'" + text : text;
    return '"' + neutralized.replace(/"/g, '""') + '"';
  };
  const lines = [["caseKey", "workItemId", "code", "ready", "gaps", "requirements"]
    .map(safe).join(",")];
  for (const packet of readiness.packets)
    lines.push([packet.caseKey, packet.workItemId, packet.diagnosticCode,
      packet.readyForHumanReview,
      packet.gaps.map(gap => gap.field).join(";"),
      packet.requirements.join(";")].map(safe).join(","));
  return lines.join("\r\n") + "\r\n";
}
export function evidenceWorklist(
  snapshot: CaseSnapshot, requirements: readonly EvidenceRequirement[],
) {
  const readiness = buildEvidenceReadiness(snapshot, requirements);
  const priority = new Map(buildReviewWorklist(snapshot).entries.map(entry =>
    [entry.caseKey, entry.priority]));
  return evidenceReviewQueue(readiness).map(entry => ({
    ...entry, triagePriority: priority.get(entry.caseKey) ?? "P4",
  })).sort((a, b) => a.triagePriority.localeCompare(b.triagePriority) ||
    a.caseKey.localeCompare(b.caseKey));
}
