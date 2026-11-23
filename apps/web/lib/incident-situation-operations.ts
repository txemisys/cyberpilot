import { createHash } from "node:crypto";
import type { IncidentSituation, SituationConcern, SituationRisk }
  from "./incident-situation-domain";
export type IncidentBriefing = {
  schema: "cyberpilot.incident.situation.briefing.v1";
  incidentId: string; organizationId: string;
  status: string; severity: string; riskBand: SituationRisk;
  primaryConcerns: SituationConcern[]; escalationQueue: Array<{
    priority: SituationRisk; concernId: string;
    ownerRole: string; dueAt: string; action: string;
    expectedEvidence: string[]; externalWrites: 0 }>;
  sourceCoverage: Array<{ source: string; status: string;
    available: number; missing: number; sourceDigest: string | null }>;
  shiftHandoff: Array<{ stage: string; currentStatus: string;
    nextOwnerRole: string; blockingSources: string[];
    approvalNeeded: boolean }>;
  overdueNow: number; unresolvedCritical: number;
  operatorAcknowledgmentRequired: true;
  providerContainmentVerified: false;
};
const weight: Record<SituationRisk, number> =
  { P0: 4, P1: 3, P2: 2, P3: 1 };
function minutesAfter(value: string, amount: number) {
  return new Date(Date.parse(value) + amount * 60000).toISOString();
}
export function prepareIncidentBriefing(
  situation: IncidentSituation,
): IncidentBriefing {
  if (situation.concerns.length > 1000 ||
      situation.sourceSummaries.length !== 3 ||
      situation.stages.some(x => x.providerExecutionProven))
    throw Error("BRIEFING_INVALID_SITUATION");
  const primary = [...situation.concerns].sort((a,b) =>
    weight[b.urgency] - weight[a.urgency] ||
    a.minimumMinutes - b.minimumMinutes || a.id.localeCompare(b.id));
  const escalationQueue = primary.map(x => ({
    priority: x.urgency, concernId: x.id, ownerRole: x.ownerRole,
    dueAt: minutesAfter(situation.evaluatedAt, x.minimumMinutes),
    action: x.nextStep, expectedEvidence: x.requiredEvidence,
    externalWrites: 0 as const,
  }));
  return {
    schema: "cyberpilot.incident.situation.briefing.v1",
    incidentId: situation.incidentId,
    organizationId: situation.organizationId,
    status: situation.caseStatus, severity: situation.severity,
    riskBand: situation.riskBand, primaryConcerns: primary.slice(0, 15),
    escalationQueue: escalationQueue.slice(0, 300),
    sourceCoverage: situation.sourceSummaries.map(x => ({
      source: x.name, status: x.availability, available: x.records,
      missing: x.missingCount, sourceDigest: x.sourceDigest,
    })),
    shiftHandoff: situation.stages.map(stage => ({
      stage: stage.title, currentStatus: stage.status,
      nextOwnerRole: stage.risk === "DESTRUCTIVE" ? "Security commander" :
        stage.risk === "FINANCIAL" ? "Finance authority" : "Security reviewer",
      blockingSources: stage.pendingSources,
      approvalNeeded: stage.approvalNeeded && !stage.approvalRecorded,
    })),
    overdueNow: escalationQueue.filter(x => x.dueAt < situation.evaluatedAt).length,
    unresolvedCritical: situation.concerns.filter(x =>
      x.urgency === "P0").length,
    operatorAcknowledgmentRequired: true,
    providerContainmentVerified: false,
  };
}
export type SituationReconciliation = {
  schema: "cyberpilot.incident.situation.reconciliation.v1";
  incidentId: string; organizationId: string; evaluatedAt: string;
  sourceInputsConsistent: boolean;
  uniqueConcernCount: number; duplicateConcernIds: string[];
  orphanStepIds: string[]; unlinkedRemediationStages: string[];
  evidenceSourceCoverageGaps: string[];
  unsupportedCompletionClaims: string[];
  mismatchCount: number; criticalMismatchCount: number;
  decision: "BLOCK_MANUAL_SIGNOFF" | "REVIEW_SCOPE" | "REVIEW_READY";
  noProviderActionWasPerformed: true;
};
export function reconcileIncidentSituation(
  situation: IncidentSituation,
): SituationReconciliation {
  const ids = new Set<string>();
  const duplicateConcernIds: string[] = [];
  for (const row of situation.concerns) {
    if (ids.has(row.id)) duplicateConcernIds.push(row.id);
    ids.add(row.id);
  }
  const stepIds = new Set(situation.stages.map(x => x.id));
  const orphanStepIds = situation.stages.filter(x =>
    !x.id || x.pendingSources.some(source => !source.trim())).map(x => x.id);
  const unlinkedRemediationStages = situation.stages.filter(x =>
    x.approvalNeeded && x.remediations === 0).map(x => x.id);
  const evidenceSourceCoverageGaps = situation.stages.filter(x =>
    x.pendingSources.length > 0).map(x => x.id);
  const unsupportedCompletionClaims = [
    ...(situation.actualContainmentVerified ? ["ACTUAL_CONTAINMENT"] : []),
    ...(situation.externalWrites ? ["EXTERNAL_WRITE"] : []),
    ...(situation.stages.some(x => x.providerExecutionProven) ?
      ["PROVIDER_EXECUTION"] : []),
    ...(situation.sourceSummaries.some(x =>
      x.independentProviderReadbackVerified) ? ["INDEPENDENT_READBACK"] : []),
  ];
  const sourceInputsConsistent =
    situation.sourceSummaries.every(x =>
      x.records >= 0 && x.missingCount >= 0 &&
      !(x.availability === "ABSENT" && x.records > 0)) &&
    situation.stages.length === stepIds.size;
  const mismatchCount = duplicateConcernIds.length +
    orphanStepIds.length + unsupportedCompletionClaims.length +
    (sourceInputsConsistent ? 0 : 1);
  const criticalMismatchCount = unsupportedCompletionClaims.length +
    duplicateConcernIds.length;
  return {
    schema: "cyberpilot.incident.situation.reconciliation.v1",
    incidentId: situation.incidentId,
    organizationId: situation.organizationId,
    evaluatedAt: situation.evaluatedAt,
    sourceInputsConsistent, uniqueConcernCount: ids.size,
    duplicateConcernIds, orphanStepIds, unlinkedRemediationStages,
    evidenceSourceCoverageGaps, unsupportedCompletionClaims,
    mismatchCount, criticalMismatchCount,
    decision: mismatchCount ? "BLOCK_MANUAL_SIGNOFF" :
      situation.completeness !== "EXPLICIT_SCOPE_ONLY" ?
      "REVIEW_SCOPE" : "REVIEW_READY",
    noProviderActionWasPerformed: true,
  };
}
export type ShiftHandoffCard = {
  code: string; incidentId: string; organizationId: string;
  operatorRole: string; urgency: SituationRisk;
  objective: string; dueBy: string;
  evidenceNeeded: string[]; caveats: string[];
  previousActionVerified: false; requiresAck: true;
};
export function planIncidentShiftHandoff(situation: IncidentSituation) {
  const briefing = prepareIncidentBriefing(situation);
  const cards: ShiftHandoffCard[] = situation.concerns.map(c => ({
    code: c.id, incidentId: situation.incidentId,
    organizationId: situation.organizationId,
    operatorRole: c.ownerRole, urgency: c.urgency,
    objective: c.nextStep,
    dueBy: minutesAfter(situation.evaluatedAt, c.minimumMinutes),
    evidenceNeeded: c.requiredEvidence,
    caveats: [...c.unsupportedAssumptions,
      "No external provider operation was invoked",
      "Operator must confirm action and evidence independently"],
    previousActionVerified: false, requiresAck: true,
  }));
  return {
    schema: "cyberpilot.incident.situation.shift-handoff.v1" as const,
    organizationId: situation.organizationId, incidentId: situation.incidentId,
    evaluatedAt: situation.evaluatedAt,
    commanderAssigned: !situation.owners.unassigned,
    critical: cards.filter(x => x.urgency === "P0"),
    review: cards.filter(x => x.urgency !== "P0"),
    stages: briefing.shiftHandoff,
    noAutomaticDispatch: true as const,
  };
}
function csv(x: unknown) {
  const raw = String(x ?? "");
  const safe = /^[=+\-@\t\r]/.test(raw) ? "'" + raw : raw;
  return '"' + safe.replaceAll('"', '""')
    .replaceAll("\r", " ").replaceAll("\n", " ") + '"';
}
export function exportIncidentSituation(
  situation: IncidentSituation,
  format: "JSON" | "CSV" | "MARKDOWN",
) {
  const briefing = prepareIncidentBriefing(situation);
  const reconciliation = reconcileIncidentSituation(situation);
  const handoff = planIncidentShiftHandoff(situation);
  const document = {
    schema: "cyberpilot.incident.situation.dossier.v1", situation,
    briefing, reconciliation, handoff, exportedAt: situation.evaluatedAt,
    providerWrites: 0, independentlyVerifiedResolution: false,
  };
  const documentDigest = createHash("sha256")
    .update(JSON.stringify(document)).digest("hex");
  const filename = "cyberpilot-situation-" + situation.incidentId;
  if (format === "JSON") return {
    filename: filename + ".json", mime: "application/json",
    digest: documentDigest,
    content: JSON.stringify({ ...document, documentDigest }, null, 2),
  };
  if (format === "CSV") {
    const rows = [["incidentId","source","concernId","priority",
      "reason","ownerRole","evidenceNeeded","dueAt"],
      ...briefing.escalationQueue.map(item => {
        const concern = situation.concerns.find(x => x.id === item.concernId);
        return [situation.incidentId, concern?.source ?? "",
          item.concernId, item.priority, concern?.explanation ?? "",
          item.ownerRole, item.expectedEvidence.join(";"), item.dueAt];
      })];
    return { filename: filename + ".csv", mime: "text/csv",
      digest: documentDigest,
      content: rows.map(row => row.map(csv).join(",")).join("\r\n") };
  }
  if (format !== "MARKDOWN") throw Error("SITUATION_FORMAT_INVALID");
  const safe = (value: string) => value.replaceAll("<","&lt;")
    .replaceAll(">","&gt;").replaceAll("|","\\|");
  return {
    filename: filename + ".md", mime: "text/markdown",
    digest: documentDigest,
    content: [
      "# CyberPilot incident situation briefing",
      "Incident: " + situation.incidentId,
      "Organization: " + situation.organizationId,
      "Risk tier: " + situation.riskBand,
      "Source completeness: " + situation.completeness,
      "Provider execution confirmed: NO",
      "Situation digest: " + situation.situationDigest,
      "Export digest: " + documentDigest, "",
      "## Source availability",
      ...situation.sourceSummaries.map(x => "- " + x.name + " — " +
        x.availability + ", missing: " + x.missingCount),
      "", "## Operator priorities",
      ...briefing.escalationQueue.map(x => "- " + x.priority + ": " +
        safe(x.action) + " (" + safe(x.ownerRole) + ")"),
      "", "## Audit reconciliation",
      "Decision: " + reconciliation.decision,
      "Mismatches: " + reconciliation.mismatchCount,
      "", "Offline review does not certify incident containment.",
    ].join("\n"),
  };
}
