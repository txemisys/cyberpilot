import { createHash } from "node:crypto";
import type { IncidentSnapshot } from "./incident-case-domain";
import { incidentDigest, validateIncidentSnapshot } from "./incident-case-domain";
import { getIncidentPlaybook } from "./incident-playbook-catalog";
import type { IncidentEvidenceCorrelation } from "./incident-integrated-evidence-domain";
import type { AssetImpactAssessment } from "./incident-integrated-assets-domain";
import type { IncidentRemediationReadiness } from "./incident-integrated-remediation-domain";
export type SituationSourceState = "PRESENT" | "ABSENT" | "ERROR" | "TRUNCATED" |
  "INTEGRITY_INVALID" | "OUT_OF_SCOPE";
export type SituationInput = {
  incident: IncidentSnapshot; evidence: IncidentEvidenceCorrelation | null;
  assets: AssetImpactAssessment | null;
  remediation: IncidentRemediationReadiness | null;
  sourceStates: { evidence: SituationSourceState;
    assets: SituationSourceState; remediation: SituationSourceState };
  capturedAt: string; sourceMode: "PERSISTED_READ_ONLY";
};
export type SituationRisk = "P0" | "P1" | "P2" | "P3";
export type SituationConcern = {
  id: string; source: "INCIDENT" | "EVIDENCE" | "ASSETS" | "REMEDIATION";
  code: string; urgency: SituationRisk;
  explanation: string; requiredEvidence: string[];
  nextStep: string; ownerRole: string; minimumMinutes: number;
  unsupportedAssumptions: string[]; verifiedResolution: false;
};
export type SituationStage = {
  id: string; title: string; status: string; risk: string;
  pendingSources: string[]; evidenceRecords: number;
  impactedAssets: number; remediations: number;
  approvalNeeded: boolean; approvalRecorded: boolean;
  humanReviewRequired: true; providerExecutionProven: false;
};
export type SituationSourceSummary = {
  name: "EVIDENCE" | "ASSETS" | "REMEDIATION";
  availability: SituationSourceState; records: number;
  expected: number; missingCount: number; warningCount: number;
  truncated: boolean; sourceDigest: string | null;
  independentProviderReadbackVerified: false;
};
export type IncidentSituation = {
  schema: "cyberpilot.incident.situation.v1";
  organizationId: string; incidentId: string; playbookType: string;
  revision: number; incidentSnapshotDigest: string;
  evaluatedAt: string; caseStatus: string; severity: string;
  sourceStates: SituationInput["sourceStates"];
  sourceSummaries: SituationSourceSummary[];
  concerns: SituationConcern[]; stages: SituationStage[];
  riskBand: SituationRisk; priorityScore: number;
  owners: { incidentOwner: string | null; unassigned: boolean;
    pendingApprovalSteps: number; independentApproverRequired: boolean };
  work: { playbookSteps: number; pending: number; reported: number;
    verifiedInWorkflow: number; missingEvidenceSources: number;
    assetCandidates: number; staleAssets: number; possibleAdvisories: number;
    remediationCandidates: number; automatedModeTargets: number;
    workItemsIncomplete: number; unverifiedActions: number };
  completeness: "UNKNOWN" | "PARTIAL" | "EXPLICIT_SCOPE_ONLY";
  readOnly: true; externalProviderCalls: 0; externalWrites: 0;
  cyberScoreModified: false; actualContainmentVerified: false;
  incidentCauseEstablished: false; situationDigest: string;
};
const ranks: Record<SituationRisk, number> = { P0: 4, P1: 3, P2: 2, P3: 1 };
const validTime = (s: string) => Number.isFinite(Date.parse(s)) &&
  new Date(s).toISOString() === s;
const digest = (obj: unknown) => createHash("sha256")
  .update(JSON.stringify(obj)).digest("hex");
function issue(
  source: SituationConcern["source"], code: string, urgency: SituationRisk,
  explanation: string, requiredEvidence: string[], nextStep: string,
  ownerRole: string, minimumMinutes: number,
  unsupportedAssumptions: string[] = [],
): SituationConcern {
  return {
    id: source + ":" + code, source, code, urgency, explanation,
    requiredEvidence, nextStep, ownerRole, minimumMinutes,
    unsupportedAssumptions, verifiedResolution: false,
  };
}
function assertInput(input: SituationInput) {
  if (!input.incident || validateIncidentSnapshot(input.incident).length ||
      !validTime(input.capturedAt) ||
      input.sourceMode !== "PERSISTED_READ_ONLY")
    throw Error("SITUATION_INPUT_INVALID");
  const scope = input.incident.organizationId, id = input.incident.id;
  for (const report of [input.evidence, input.assets, input.remediation]) {
    if (report && (report.organizationId !== scope ||
        report.incidentId !== id))
      throw Error("SITUATION_TENANT_SCOPE_INVALID");
  }
  if (input.evidence && (input.evidence.incidentRevision !== input.incident.revision ||
      input.evidence.incidentDigest !== incidentDigest(input.incident)))
    throw Error("SITUATION_EVIDENCE_INCIDENT_DRIFT");
  if (input.assets && input.assets.incidentDigest !== incidentDigest(input.incident))
    throw Error("SITUATION_ASSETS_INCIDENT_DRIFT");
  if (input.remediation && (input.remediation.incidentRevision !==
      input.incident.revision || input.remediation.incidentDigest !==
      incidentDigest(input.incident)))
    throw Error("SITUATION_REMEDIATION_INCIDENT_DRIFT");
  const allowed: SituationSourceState[] = ["PRESENT", "ABSENT", "ERROR",
    "TRUNCATED", "INTEGRITY_INVALID", "OUT_OF_SCOPE"];
  for (const [key, state] of Object.entries(input.sourceStates)) {
    if (!["evidence", "assets", "remediation"].includes(key) ||
        !allowed.includes(state))
      throw Error("SITUATION_SOURCE_STATE_INVALID");
  }
  if (Object.keys(input.sourceStates).length !== 3)
    throw Error("SITUATION_SOURCE_STATE_INCOMPLETE");
  for (const key of ["evidence", "assets", "remediation"] as const) {
    const report = input[key];
    const state = input.sourceStates[key];
    if (Boolean(report) !== ["PRESENT", "TRUNCATED"].includes(state))
      throw Error("SITUATION_SOURCE_STATE_CONTRADICTORY");
  }
}
function severityPriority(incident: IncidentSnapshot): SituationRisk {
  return incident.severity === "CRITICAL" ? "P0" :
    incident.severity === "HIGH" ? "P1" :
    incident.severity === "MEDIUM" ? "P2" : "P3";
}
function summarizeSources(input: SituationInput): SituationSourceSummary[] {
  const { evidence, assets, remediation } = input;
  return [
    { name: "EVIDENCE" as const, availability: input.sourceStates.evidence,
      records: evidence?.sourceRecords.length ?? 0,
      expected: (evidence?.selectedEvidenceCount ?? 0) +
        (evidence?.selectedFindingCount ?? 0) +
        (evidence?.selectedDecisionCount ?? 0),
      missingCount: evidence?.missingIds.length ?? 0,
      warningCount: evidence?.warnings.length ?? 0,
      truncated: evidence?.truncated ?? false,
      sourceDigest: evidence?.sourceDigest ?? null,
      independentProviderReadbackVerified: false as const },
    { name: "ASSETS" as const, availability: input.sourceStates.assets,
      records: assets?.affectedDevices.length ?? 0,
      expected: (assets?.selectedDeviceIds ?? 0) +
        (assets?.selectedImportIds ?? 0) +
        (assets?.selectedExternalIds ?? 0),
      missingCount: (assets?.missingDeviceIds.length ?? 0) +
        (assets?.missingImportIds.length ?? 0) +
        (assets?.missingExternalIds.length ?? 0),
      warningCount: assets?.findings.length ?? 0,
      truncated: assets?.truncated ?? false,
      sourceDigest: assets?.sourceDigest ?? null,
      independentProviderReadbackVerified: false as const },
    { name: "REMEDIATION" as const, availability: input.sourceStates.remediation,
      records: remediation?.targetReviews.length ?? 0,
      expected: (remediation?.explicitRemediations ?? 0) +
        (remediation?.explicitFindings ?? 0) +
        (remediation?.explicitWorkItems ?? 0),
      missingCount: (remediation?.missingRemediationIds.length ?? 0) +
        (remediation?.missingFindingIds.length ?? 0) +
        (remediation?.missingWorkIds.length ?? 0),
      warningCount: (remediation?.warnings.length ?? 0) +
        (remediation?.blockers.length ?? 0),
      truncated: remediation?.truncated ?? false,
      sourceDigest: remediation?.sourceDigest ?? null,
      independentProviderReadbackVerified: false as const },
  ];
}
function evidenceConcerns(input: SituationInput): SituationConcern[] {
  const data = input.evidence;
  if (!data) return [issue("EVIDENCE", "EVIDENCE_ABSENT", "P1",
    "No current cross-product evidence assessment is attached",
    ["Explicit source references", "Current source observations"],
    "Review the available evidence inventory and select exact records",
    "Security reviewer", 60,
    ["Lack of observations is not evidence of absence of compromise"])];
  const concerns: SituationConcern[] = [];
  if (data.missingIds.length)
    concerns.push(issue("EVIDENCE", "EXPLICIT_REFERENCES_MISSING", "P1",
      "Selected evidence, findings or decisions were not found",
      data.missingIds.slice(0, 30),
      "Reconcile identifiers and retention with the original source",
      "Evidence owner", 60));
  if (data.foreignTenantIds.length)
    concerns.push(issue("EVIDENCE", "FOREIGN_TENANT_SOURCE", "P0",
      "A cross-tenant source record was detected and excluded",
      ["Authorized organization membership", "Correct source organization"],
      "Stop attribution and investigate source isolation",
      "Security administrator", 15));
  if (data.steps.some(x => x.missingSources.length))
    concerns.push(issue("EVIDENCE", "PLAYBOOK_PROOF_GAPS", "P1",
      "The playbook requires independent evidence not established by available records",
      [...new Set(data.steps.flatMap(x => x.missingSources))].slice(0, 60),
      "Acquire independent data or record unavailable coverage",
      "Incident evidence reviewer", 90));
  if (data.warnings.includes("SOURCE_COLLECTION_ERROR"))
    concerns.push(issue("EVIDENCE", "COLLECTION_ERROR", "P1",
      "One or more source collectors could not produce interpretable evidence",
      ["Collector error code", "Permission and retention diagnostics"],
      "Repair collection and capture a new observation", "Integration operator", 60));
  if (data.warnings.includes("SOURCE_STALE"))
    concerns.push(issue("EVIDENCE", "STALE_PROVENANCE", "P2",
      "Historic observations do not establish present controls",
      ["Fresh timestamped source observation"],
      "Re-collect and preserve historic versions", "Security reviewer", 240));
  if (data.truncated)
    concerns.push(issue("EVIDENCE", "EVIDENCE_POPULATION_TRUNCATED", "P1",
      "The evidence selection exceeds this bounded review",
      ["Remaining source pages and cursors"],
      "Partition the selection and verify each page", "Evidence owner", 60));
  return concerns;
}
function assetConcerns(input: SituationInput): SituationConcern[] {
  const data = input.assets;
  if (!data) return [issue("ASSETS", "ASSETS_ABSENT", "P2",
    "No exact imported inventory selection was reviewed",
    ["Original inventory reference", "Current device identity confirmation"],
    "Select exact device, external or import identifiers",
    "Asset administrator", 240)];
  const concerns: SituationConcern[] = [];
  if (data.conflictingExternalIds.length)
    concerns.push(issue("ASSETS", "AMBIGUOUS_DEVICE_IDENTITY", "P1",
      "Multiple imports claim the same external inventory identity",
      data.conflictingExternalIds.slice(0, 50),
      "Reconcile importer provenance before an isolation handoff",
      "Asset administrator", 60));
  if (data.staleDeviceIds.length)
    concerns.push(issue("ASSETS", "STALE_ASSET_OBSERVATIONS", "P2",
      "Selected devices have old inventory timestamps",
      data.staleDeviceIds.slice(0, 50),
      "Request fresh device telemetry from authorized inventory source",
      "IT operator", 240));
  if (data.unknownVersionIds.length)
    concerns.push(issue("ASSETS", "UNKNOWN_DEVICE_VERSION", "P2",
      "Unknown versions make vulnerability applicability uncertain",
      data.unknownVersionIds.slice(0, 50),
      "Request OS/software version confirmation", "IT operator", 240));
  if (data.highPriorityDeviceIds.length)
    concerns.push(issue("ASSETS", "ADVISORY_OR_GAP_REVIEW", "P1",
      "Selected assets have advisory candidates or unresolved inventory weaknesses",
      data.highPriorityDeviceIds.slice(0, 50),
      "Review OSV provenance and exposure without inferring exploitation",
      "Vulnerability reviewer", 120,
      ["An advisory does not prove exploitation or ransomware causality"]));
  if (data.foreignTenantIds.length)
    concerns.push(issue("ASSETS", "FOREIGN_ASSET_SOURCE", "P0",
      "Cross-tenant inventory records cannot be used",
      ["Verified inventory organization scope"],
      "Stop source linkage and investigate isolation", "Security administrator", 15));
  if (data.truncated)
    concerns.push(issue("ASSETS", "ASSET_POPULATION_TRUNCATED", "P1",
      "Asset pagination was truncated",
      ["Additional bounded inventory pages"],
      "Reconcile all selected devices before declaring complete scope",
      "Asset administrator", 90));
  return concerns;
}
function remediationConcerns(input: SituationInput): SituationConcern[] {
  const data = input.remediation;
  if (!data) return [issue("REMEDIATION", "REMEDIATION_ABSENT", "P1",
    "No supervised remediation readiness review is available",
    ["Exact remediation and finding identifiers", "Approver separation"],
    "Review existing remediation and task records",
    "Incident commander", 60)];
  const concerns: SituationConcern[] = [];
  if (data.unsafeAutomations)
    concerns.push(issue("REMEDIATION", "AUTOMATION_NOT_AUTHORIZED", "P0",
      "Historic automated mode is not licensed to execute in this context",
      ["Explicit tenant consent", "Separate executor credentials",
        "Target-specific risk approval"],
      "Disable dispatch and require dedicated approval process",
      "Security officer", 15));
  if (data.selfApprovals)
    concerns.push(issue("REMEDIATION", "SEPARATION_OF_DUTIES", "P0",
      "Reviewer and incident owner may overlap in an approval",
      ["Independent approver identity", "Exact scope-bound approval"],
      "Obtain separate approval before any provider change",
      "Security officer", 15));
  if (data.unfinishedWorkItems)
    concerns.push(issue("REMEDIATION", "UNFINISHED_WORK", "P1",
      "Existing remediation tasks are not completed",
      ["Task revision", "Responsible operator", "Independent completion proof"],
      "Resolve work item and verify remaining exposure", "Remediation owner", 60));
  if (data.missingIndependentProof)
    concerns.push(issue("REMEDIATION", "NO_INDEPENDENT_OUTCOME", "P1",
      "Readiness flags never establish external provider containment",
      ["Independent post-action provider telemetry"],
      "Perform separate authorized readback outside this offline integration",
      "Security reviewer", 60));
  if (data.foreignTenantIds.length)
    concerns.push(issue("REMEDIATION", "FOREIGN_REMEDIATION_SOURCE", "P0",
      "Cross-organization remediation or finding was excluded",
      ["Correct tenant scoped row ID"],
      "Block the action and reconcile organization identity",
      "Security administrator", 15));
  if (data.truncated)
    concerns.push(issue("REMEDIATION", "WORK_HISTORY_TRUNCATED", "P1",
      "Bounded remediation review is incomplete",
      ["Complete relevant paginated work records"],
      "Review remaining source records", "Security reviewer", 120));
  return concerns;
}
function incidentConcerns(input: SituationInput): SituationConcern[] {
  const snapshot = input.incident;
  const book = getIncidentPlaybook(snapshot.type);
  const result: SituationConcern[] = [];
  if (snapshot.ownerUserId === null)
    result.push(issue("INCIDENT", "OWNER_UNASSIGNED", "P1",
      "Incident responsibility has not been assigned",
      ["Active organization membership", "Explicit case owner assignment"],
      "Assign an incident commander", "Organization administrator", 30));
  if (snapshot.status === "CLOSED")
    result.push(issue("INCIDENT", "WORKFLOW_CLOSED_NOT_CONTAINMENT", "P1",
      "A closed guided case does not independently attest external containment",
      ["Provider readback", "Explicit residual risk review"],
      "Retain conservative security outcome until independently verified",
      "Security reviewer", 60));
  for (const step of book.steps) {
    const status = snapshot.steps.find(x => x.stepId === step.id);
    if (!status || status.status === "BLOCKED")
      result.push(issue("INCIDENT", "STEP_BLOCKED:" + step.id,
        step.risk === "DESTRUCTIVE" || step.risk === "FINANCIAL" ? "P0" : "P1",
        "Playbook step is blocked or absent", step.proofRequired,
        "Follow step fallback: " + step.fallback,
        step.suggestedOwner, step.targetMinutes));
    if (step.requiresApproval &&
        !snapshot.approvals.some(x => x.stepId === step.id &&
          x.expiresAt > input.capturedAt))
      result.push(issue("INCIDENT", "STEP_APPROVAL:" + step.id, "P1",
        "High impact step has no current recorded approval",
        ["Independent approver receipt", "Exact allowed target scope"],
        "Request separate approval; never execute from this review",
        "Security approver", step.targetMinutes));
  }
  return result;
}
export function buildIncidentSituation(input: SituationInput): IncidentSituation {
  assertInput(input);
  const { incident, evidence, assets, remediation } = input;
  const book = getIncidentPlaybook(incident.type);
  const concerns = [
    ...incidentConcerns(input), ...evidenceConcerns(input),
    ...assetConcerns(input), ...remediationConcerns(input),
  ];
  const riskWeight = (x: SituationConcern) => ranks[x.urgency];
  concerns.sort((a, b) => riskWeight(b) - riskWeight(a) ||
    a.minimumMinutes - b.minimumMinutes || a.id.localeCompare(b.id));
  const stages: SituationStage[] = book.steps.map(step => {
    const local = incident.steps.find(x => x.stepId === step.id)!;
    const correlation = evidence?.steps.find(x => x.stepId === step.id);
    const rem = remediation?.stepMappings.find(x => x.stepId === step.id);
    return {
      id: step.id, title: step.title, status: local.status, risk: step.risk,
      pendingSources: correlation?.missingSources ?? step.requiredEvidence,
      evidenceRecords: correlation?.matchedEvidenceIds.length ?? 0,
      impactedAssets: assets?.affectedDevices.length ?? 0,
      remediations: rem?.associatedRemediationIds.length ?? 0,
      approvalNeeded: step.requiresApproval,
      approvalRecorded: rem?.approvalRecorded ??
        incident.approvals.some(x => x.stepId === step.id &&
          x.expiresAt > input.capturedAt),
      humanReviewRequired: true, providerExecutionProven: false,
    };
  });
  const sourceSummaries = summarizeSources(input);
  const riskBand: SituationRisk = concerns.some(x => x.urgency === "P0") ?
    "P0" : concerns.some(x => x.urgency === "P1") ? "P1" :
    severityPriority(incident);
  const score = Math.min(100, ranks[riskBand] * 15 +
    concerns.filter(x => x.urgency === "P0").length * 8 +
    concerns.filter(x => x.urgency === "P1").length * 3 +
    sourceSummaries.filter(x => x.availability !== "PRESENT").length * 5);
  const completeness: IncidentSituation["completeness"] = sourceSummaries.every(x =>
    x.availability === "ABSENT") ? "UNKNOWN" :
    sourceSummaries.some(x => x.availability !== "PRESENT" ||
      x.truncated || x.missingCount > 0) ? "PARTIAL" : "EXPLICIT_SCOPE_ONLY";
  const report = {
    schema: "cyberpilot.incident.situation.v1" as const,
    organizationId: incident.organizationId, incidentId: incident.id,
    playbookType: incident.type, revision: incident.revision,
    incidentSnapshotDigest: incidentDigest(incident),
    evaluatedAt: input.capturedAt,
    caseStatus: incident.status, severity: incident.severity,
    sourceStates: input.sourceStates, sourceSummaries,
    concerns, stages, riskBand, priorityScore: score,
    owners: { incidentOwner: incident.ownerUserId,
      unassigned: incident.ownerUserId === null,
      pendingApprovalSteps: stages.filter(x =>
        x.approvalNeeded && !x.approvalRecorded).length,
      independentApproverRequired: stages.some(x => x.approvalNeeded) },
    work: {
      playbookSteps: stages.length,
      pending: incident.steps.filter(x => x.status === "PENDING").length,
      reported: incident.steps.filter(x => x.status === "REPORTED_DONE").length,
      verifiedInWorkflow: incident.steps.filter(x => x.status === "VERIFIED").length,
      missingEvidenceSources: stages.reduce((n, x) => n +
        x.pendingSources.length, 0),
      assetCandidates: assets?.affectedDevices.length ?? 0,
      staleAssets: assets?.staleDeviceIds.length ?? 0,
      possibleAdvisories: assets?.affectedDevices.filter(x =>
        x.advisoryStatus !== "NONE").length ?? 0,
      remediationCandidates: remediation?.targetReviews.length ?? 0,
      automatedModeTargets: remediation?.unsafeAutomations ?? 0,
      workItemsIncomplete: remediation?.unfinishedWorkItems ?? 0,
      unverifiedActions: remediation?.missingIndependentProof ?? 0,
    },
    completeness, readOnly: true as const,
    externalProviderCalls: 0 as const, externalWrites: 0 as const,
    cyberScoreModified: false as const,
    actualContainmentVerified: false as const,
    incidentCauseEstablished: false as const,
  };
  return { ...report, situationDigest: digest(report) };
}
export function compareIncidentSituations(
  earlier: IncidentSituation, current: IncidentSituation,
) {
  if (earlier.organizationId !== current.organizationId ||
      earlier.incidentId !== current.incidentId ||
      earlier.evaluatedAt > current.evaluatedAt)
    throw Error("SITUATION_COMPARISON_SCOPE_INVALID");
  const before = new Map(earlier.concerns.map(x => [x.id, x]));
  const after = new Map(current.concerns.map(x => [x.id, x]));
  return {
    schema: "cyberpilot.incident.situation.delta.v1" as const,
    incidentId: current.incidentId, organizationId: current.organizationId,
    addedConcerns: [...after.keys()].filter(x => !before.has(x)),
    noLongerReported: [...before.keys()].filter(x => !after.has(x)),
    priorityChanged: [...after.values()].filter(x =>
      before.has(x.id) && before.get(x.id)!.urgency !== x.urgency).map(x =>
      ({ id: x.id, prior: before.get(x.id)!.urgency, current: x.urgency })),
    sourceScopeChanged: earlier.sourceSummaries.some((x, i) =>
      x.sourceDigest !== current.sourceSummaries[i]?.sourceDigest),
    comparable: earlier.completeness === current.completeness &&
      earlier.sourceSummaries.every((x, i) =>
        x.availability === current.sourceSummaries[i]?.availability),
    providerContainmentChangeVerified: false as const,
    cyberScoreEvolutionVerified: false as const,
  };
}
