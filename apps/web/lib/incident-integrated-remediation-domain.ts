import { createHash } from "node:crypto";
import { type IncidentSnapshot, validateIncidentSnapshot,
  incidentDigest } from "./incident-case-domain";
import { getIncidentPlaybook } from "./incident-playbook-catalog";
export type RemediationRecord = {
  id: string; organizationId: string; findingId: string;
  playbookId: string; mode: "GUIDED" | "AUTOMATED";
  status: string; title: string; summary: string;
  approvedByUserId: string | null; approvedAt: string | null;
  startedAt: string | null; completedAt: string | null;
  verifiedAt: string | null; failureCode: string | null;
  createdAt: string; updatedAt: string;
};
export type RemediationWorkRecord = {
  id: string; organizationId: string; remediationId: string;
  findingId: string; title: string; status: string; priority: string;
  assigneeUserId: string | null; dueAt: string | null;
  revision: number; completedAt: string | null;
};
export type RemediationFindingRecord = {
  id: string; organizationId: string; severity: string; status: string;
  title: string; ruleId: string; lastSeenAt: string;
};
export type RemediationSelection = {
  remediationIds: string[]; findingIds: string[];
  workItemIds: string[]; expectedIncidentRevision: number;
};
export type RemediationReadinessGate = "BLOCKED" | "REVIEW_REQUIRED" |
  "MANUAL_HANDOFF_READY";
export type RemediationBarrier = "FOREIGN_TENANT" | "INCIDENT_REVISION_DRIFT" |
  "TARGET_NOT_SELECTED" | "FINDING_NOT_IN_TENANT" |
  "WORK_ITEM_NOT_FOUND" | "REMEDIATION_NOT_IN_TENANT" |
  "APPROVER_UNKNOWN" | "APPROVER_IS_INCIDENT_OWNER" |
  "APPROVAL_EXPIRED_OR_MISSING" | "AUTOMATED_MODE_NOT_AUTHORIZED" |
  "PROVIDER_OUTCOME_NOT_INDEPENDENT" | "WORK_IN_PROGRESS" |
  "FAILED_REMEDIATION" | "VERIFY_REQUIRED" |
  "PLAYBOOK_APPROVAL_MISSING" | "FINDING_NOT_OPEN" |
  "CASE_ALREADY_CLOSED" | "COVERAGE_INCOMPLETE";
export type RemediationTargetReview = {
  id: string; remediationId: string; findingId: string;
  organizationId: string; title: string;
  status: string; mode: "GUIDED" | "AUTOMATED";
  risk: "READ_ONLY" | "EXTERNAL_CHANGE" | "DESTRUCTIVE" | "FINANCIAL";
  selectedVia: "EXPLICIT_ID" | "EXPLICIT_FINDING" | "EXPLICIT_WORK_ITEM";
  exactFindingFound: boolean; currentFindingStatus: string | null;
  workItems: Array<{ id: string; status: string; priority: string;
    assigneeUserId: string | null; revision: number;
    overdue: boolean }>;
  approverId: string | null; approvedAt: string | null;
  approvalCurrent: boolean; independentApprover: boolean;
  dataProof: "NO_PROVIDER_PROOF" | "HISTORIC_WORKFLOW_FLAG";
  barriers: RemediationBarrier[];
  gate: RemediationReadinessGate;
  providerExecutionAuthorized: false;
};
export type PlaybookActionMapping = {
  stepId: string; title: string; providerCapability: string;
  risk: RemediationTargetReview["risk"]; approvalRequired: boolean;
  approvalRecorded: boolean; evidenceIndependentlyProven: boolean;
  associatedRemediationIds: string[];
  associatedFindingIds: string[]; incompleteRemediationIds: string[];
  standaloneManualInstructions: string[];
  providerActionPerformed: false; allowAutomaticDispatch: false;
};
export type IncidentRemediationReadiness = {
  schema: "cyberpilot.incident.remediation-readiness.v1";
  organizationId: string; incidentId: string;
  incidentType: string; at: string;
  incidentRevision: number; incidentDigest: string;
  sourceDigest: string; truncated: boolean;
  explicitRemediations: number; explicitFindings: number;
  explicitWorkItems: number; remediationRecords: number;
  workRecords: number; findingRecords: number;
  missingRemediationIds: string[]; missingFindingIds: string[];
  missingWorkIds: string[]; foreignTenantIds: string[];
  targetReviews: RemediationTargetReview[];
  stepMappings: PlaybookActionMapping[];
  unsafeAutomations: number; selfApprovals: number;
  unfinishedWorkItems: number; missingIndependentProof: number;
  blockers: RemediationBarrier[]; warnings: string[];
  gate: RemediationReadinessGate;
  actualContainmentVerified: false; actualProviderWrites: 0;
  consentEstablishedForAutomatedExecution: false;
  requiredExecutorCredentialAvailable: false;
};
export type RemediationReadinessInput = {
  incident: IncidentSnapshot; selection: RemediationSelection;
  remediations: RemediationRecord[]; findings: RemediationFindingRecord[];
  works: RemediationWorkRecord[]; at: string; approvalMaxAgeHours: number;
  truncated: boolean;
};
const validId = (v: unknown): v is string => typeof v === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
const validTime = (v: unknown): v is string => typeof v === "string" &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
const digest = (value: unknown) => createHash("sha256")
  .update(JSON.stringify(value)).digest("hex");
const ids = (values: unknown, maximum: number) => {
  if (!Array.isArray(values) || values.length > maximum ||
      values.some(x => !validId(x)))
    throw Error("REMEDIATION_SELECTION_IDS_INVALID");
  return values as string[];
};
function validate(input: RemediationReadinessInput) {
  if (validateIncidentSnapshot(input.incident).length ||
      !validTime(input.at) || input.remediations.length > 300 ||
      input.findings.length > 300 || input.works.length > 500 ||
      !Number.isSafeInteger(input.approvalMaxAgeHours) ||
      input.approvalMaxAgeHours < 1 || input.approvalMaxAgeHours > 8760 ||
      typeof input.truncated !== "boolean")
    throw Error("REMEDIATION_INTEGRATION_INPUT_INVALID");
  ids(input.selection.remediationIds, 100);
  ids(input.selection.findingIds, 100);
  ids(input.selection.workItemIds, 100);
}
function mapRisk(incident: IncidentSnapshot,
  remediation: RemediationRecord): RemediationTargetReview["risk"] {
  const book = getIncidentPlaybook(incident.type);
  const matching = book.steps.filter(s =>
    remediation.playbookId === s.id || remediation.playbookId ===
      incident.type + ":" + s.id);
  if (matching.length) return matching.some(x => x.risk === "DESTRUCTIVE") ?
    "DESTRUCTIVE" : matching.some(x => x.risk === "FINANCIAL") ?
    "FINANCIAL" : matching.some(x => x.risk === "EXTERNAL_CHANGE") ?
    "EXTERNAL_CHANGE" : "READ_ONLY";
  return remediation.mode === "AUTOMATED" ? "EXTERNAL_CHANGE" : "READ_ONLY";
}
function approvalForStep(incident: IncidentSnapshot, stepId: string, at: string) {
  return incident.approvals.some(x => x.stepId === stepId &&
    x.approvedAt <= at && x.expiresAt > at);
}
export function assessIncidentRemediationReadiness(
  input: RemediationReadinessInput,
): IncidentRemediationReadiness {
  validate(input);
  const { incident, selection, at } = input;
  const org = incident.organizationId;
  const foreignTenantIds = [...input.remediations, ...input.findings, ...input.works]
    .filter(x => x.organizationId !== org).map(x => x.id);
  const findingMap = new Map(input.findings.filter(x =>
    x.organizationId === org).map(x => [x.id, x]));
  const remediations = input.remediations.filter(x => x.organizationId === org);
  const works = input.works.filter(x => x.organizationId === org);
  const selectedRemediations = new Set(selection.remediationIds);
  const selectedFindings = new Set(selection.findingIds);
  const selectedWorks = new Set(selection.workItemIds);
  const byWork = new Set(works.filter(x => selectedWorks.has(x.id))
    .map(x => x.remediationId));
  const targetRows = remediations.filter(x =>
    selectedRemediations.has(x.id) || selectedFindings.has(x.findingId) ||
    byWork.has(x.id));
  const targets: RemediationTargetReview[] = targetRows.map(remediation => {
    const finding = findingMap.get(remediation.findingId);
    const associatedWorks = works.filter(x => x.remediationId === remediation.id);
    const risk = mapRisk(incident, remediation);
    const approvalCurrent = remediation.approvedAt !== null &&
      Date.parse(remediation.approvedAt) <= Date.parse(at) &&
      Date.parse(remediation.approvedAt) >= Date.parse(at) -
        input.approvalMaxAgeHours * 3600000;
    const independentApprover = remediation.approvedByUserId !== null &&
      remediation.approvedByUserId !== incident.ownerUserId &&
      remediation.approvedByUserId !== incident.updatedById;
    const barrier: RemediationBarrier[] = [];
    if (!finding) barrier.push("FINDING_NOT_IN_TENANT");
    else if (finding.status !== "OPEN") barrier.push("FINDING_NOT_OPEN");
    if (!remediation.approvedByUserId) barrier.push("APPROVER_UNKNOWN");
    if (remediation.approvedByUserId && !independentApprover)
      barrier.push("APPROVER_IS_INCIDENT_OWNER");
    if (!approvalCurrent) barrier.push("APPROVAL_EXPIRED_OR_MISSING");
    if (remediation.mode === "AUTOMATED")
      barrier.push("AUTOMATED_MODE_NOT_AUTHORIZED");
    if (remediation.status === "FAILED") barrier.push("FAILED_REMEDIATION");
    if (remediation.status === "EXECUTING") barrier.push("WORK_IN_PROGRESS");
    if (remediation.status === "SUCCEEDED" ||
        remediation.status === "VERIFIED")
      barrier.push("PROVIDER_OUTCOME_NOT_INDEPENDENT");
    if (associatedWorks.some(x => x.status !== "DONE"))
      barrier.push("VERIFY_REQUIRED");
    if (risk !== "READ_ONLY" &&
        !getIncidentPlaybook(incident.type).steps.some(x =>
          (remediation.playbookId === x.id ||
          remediation.playbookId === incident.type + ":" + x.id) &&
          approvalForStep(incident, x.id, at)))
      barrier.push("PLAYBOOK_APPROVAL_MISSING");
    if (incident.status === "CLOSED") barrier.push("CASE_ALREADY_CLOSED");
    return {
      id: "REMEDIATION:" + remediation.id, remediationId: remediation.id,
      findingId: remediation.findingId, organizationId: org,
      title: remediation.title, status: remediation.status,
      mode: remediation.mode, risk,
      selectedVia: selectedRemediations.has(remediation.id) ?
        "EXPLICIT_ID" as const : selectedFindings.has(remediation.findingId) ?
        "EXPLICIT_FINDING" as const : "EXPLICIT_WORK_ITEM" as const,
      exactFindingFound: Boolean(finding),
      currentFindingStatus: finding?.status ?? null,
      workItems: associatedWorks.map(x => ({
        id: x.id, status: x.status, priority: x.priority,
        assigneeUserId: x.assigneeUserId, revision: x.revision,
        overdue: x.dueAt !== null && x.dueAt < at && x.status !== "DONE",
      })),
      approverId: remediation.approvedByUserId,
      approvedAt: remediation.approvedAt, approvalCurrent,
      independentApprover, dataProof: remediation.status === "VERIFIED" ?
        "HISTORIC_WORKFLOW_FLAG" as const : "NO_PROVIDER_PROOF" as const,
      barriers: barrier,
      gate: barrier.some(x => ["AUTOMATED_MODE_NOT_AUTHORIZED",
        "APPROVER_IS_INCIDENT_OWNER", "CASE_ALREADY_CLOSED",
        "FINDING_NOT_IN_TENANT"].includes(x)) ? "BLOCKED" as const :
        barrier.length ? "REVIEW_REQUIRED" as const :
        "MANUAL_HANDOFF_READY" as const,
      providerExecutionAuthorized: false as const,
    };
  });
  const matchedRemediations = new Set(targets.map(x => x.remediationId));
  const matchedFindings = new Set(targets.map(x => x.findingId));
  const matchedWorks = new Set(targets.flatMap(x => x.workItems.map(y => y.id)));
  const missingRemediationIds = selection.remediationIds.filter(x =>
    !matchedRemediations.has(x));
  const missingFindingIds = selection.findingIds.filter(x =>
    !findingMap.has(x));
  const missingWorkIds = selection.workItemIds.filter(x =>
    !matchedWorks.has(x));
  const book = getIncidentPlaybook(incident.type);
  const steps: PlaybookActionMapping[] = book.steps.map(step => {
    const linked = targetRows.filter(x =>
      x.playbookId === step.id ||
      x.playbookId === incident.type + ":" + step.id);
    const actionReviews = targets.filter(x => linked.some(y => y.id === x.remediationId));
    return { stepId: step.id, title: step.title,
      providerCapability: step.providerCapability,
      risk: step.risk, approvalRequired: step.requiresApproval,
      approvalRecorded: approvalForStep(incident, step.id, at),
      evidenceIndependentlyProven: false,
      associatedRemediationIds: linked.map(x => x.id),
      associatedFindingIds: [...new Set(linked.map(x => x.findingId))],
      incompleteRemediationIds: actionReviews.filter(x =>
        x.gate !== "MANUAL_HANDOFF_READY").map(x => x.remediationId),
      standaloneManualInstructions: step.instructions,
      providerActionPerformed: false, allowAutomaticDispatch: false };
  });
  const blockers = [...new Set(targets.flatMap(x => x.barriers))];
  if (foreignTenantIds.length) blockers.push("FOREIGN_TENANT");
  if (missingRemediationIds.length) blockers.push("REMEDIATION_NOT_IN_TENANT");
  if (missingFindingIds.length) blockers.push("FINDING_NOT_IN_TENANT");
  if (missingWorkIds.length) blockers.push("WORK_ITEM_NOT_FOUND");
  if (selection.expectedIncidentRevision !== incident.revision)
    blockers.push("INCIDENT_REVISION_DRIFT");
  if (input.truncated) blockers.push("COVERAGE_INCOMPLETE");
  if (!selection.remediationIds.length && !selection.findingIds.length &&
      !selection.workItemIds.length) blockers.push("TARGET_NOT_SELECTED");
  const blocking = blockers.some(x => ["FOREIGN_TENANT", "INCIDENT_REVISION_DRIFT",
    "AUTOMATED_MODE_NOT_AUTHORIZED", "APPROVER_IS_INCIDENT_OWNER",
    "CASE_ALREADY_CLOSED", "REMEDIATION_NOT_IN_TENANT",
    "FINDING_NOT_IN_TENANT", "WORK_ITEM_NOT_FOUND"].includes(x));
  return {
    schema: "cyberpilot.incident.remediation-readiness.v1",
    organizationId: org, incidentId: incident.id, incidentType: incident.type,
    at, incidentRevision: incident.revision, incidentDigest: incidentDigest(incident),
    sourceDigest: digest({
      remediations: input.remediations.map(x => [x.id, x.status, x.approvedAt]),
      works: input.works.map(x => [x.id, x.revision, x.status]),
      findings: input.findings.map(x => [x.id, x.status]),
    }), truncated: input.truncated,
    explicitRemediations: selection.remediationIds.length,
    explicitFindings: selection.findingIds.length,
    explicitWorkItems: selection.workItemIds.length,
    remediationRecords: remediations.length, workRecords: works.length,
    findingRecords: input.findings.length,
    missingRemediationIds, missingFindingIds, missingWorkIds,
    foreignTenantIds, targetReviews: targets, stepMappings: steps,
    unsafeAutomations: targets.filter(x => x.mode === "AUTOMATED").length,
    selfApprovals: targets.filter(x => !x.independentApprover).length,
    unfinishedWorkItems: targets.reduce((sum, x) => sum +
      x.workItems.filter(w => w.status !== "DONE").length, 0),
    missingIndependentProof: steps.filter(x =>
      !x.evidenceIndependentlyProven).length,
    blockers, warnings: [
      ...(input.truncated ? ["REMEDIATION_SOURCE_TRUNCATED"] : []),
      ...(targets.some(x => x.status === "VERIFIED") ?
        ["HISTORIC_VERIFIED_STATUS_NOT_LIVE_CONFIRMATION"] : []),
      ...(incident.status === "CLOSED" ?
        ["INCIDENT_CLOSED_ONLY_WORKFLOW"] : []),
      ...(targets.some(x => x.workItems.some(w => w.overdue)) ?
        ["REMEDIATION_WORK_ITEMS_OVERDUE"] : []),
    ],
    gate: blocking ? "BLOCKED" : blockers.length ? "REVIEW_REQUIRED" :
      "MANUAL_HANDOFF_READY",
    actualContainmentVerified: false, actualProviderWrites: 0,
    consentEstablishedForAutomatedExecution: false,
    requiredExecutorCredentialAvailable: false,
  };
}
export function compareRemediationReadiness(
  prior: IncidentRemediationReadiness, next: IncidentRemediationReadiness,
) {
  if (prior.organizationId !== next.organizationId ||
      prior.incidentId !== next.incidentId || prior.at > next.at)
    throw Error("REMEDIATION_READINESS_COMPARISON_SCOPE_INVALID");
  const old = new Map(prior.targetReviews.map(x => [x.id, x]));
  const current = new Map(next.targetReviews.map(x => [x.id, x]));
  return {
    schema: "cyberpilot.incident.remediation-readiness.diff.v1" as const,
    incidentId: prior.incidentId, organizationId: prior.organizationId,
    added: [...current.keys()].filter(x => !old.has(x)),
    missing: [...old.keys()].filter(x => !current.has(x)),
    gateChanged: [...current.values()].filter(x => old.has(x.id) &&
      x.gate !== old.get(x.id)!.gate).map(x => ({
        id: x.id, previous: old.get(x.id)!.gate, current: x.gate,
      })),
    stoppedAutomationVerified: false as const,
    actualRemediationVerified: false as const,
  };
}
