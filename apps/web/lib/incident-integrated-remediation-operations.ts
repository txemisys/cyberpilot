import { createHash } from "node:crypto";
import type { IncidentRemediationReadiness,
  RemediationTargetReview, RemediationBarrier }
  from "./incident-integrated-remediation-domain";

export type RemediationHandoffTicket = {
  id: string; organizationId: string; incidentId: string;
  remediationId: string; findingId: string;
  title: string; urgency: "IMMEDIATE" | "HIGH" | "NORMAL";
  ownerRole: string; reason: string; dueAt: string;
  expectedProof: string[]; currentBarriers: RemediationBarrier[];
  requiresExplicitApproval: boolean;
  requiresIndependentVerification: true;
  allowedMode: "MANUAL_REVIEW_ONLY";
  providerWrites: 0; requestSubmittedToExecutor: false;
};
export type RemediationHandoffPlan = {
  schema: "cyberpilot.incident.remediation.handoff-plan.v1";
  organizationId: string; incidentId: string; asOf: string;
  inputDigest: string; targets: number;
  tickets: RemediationHandoffTicket[];
  blocked: number; readyForManualReview: number;
  awaitingApproval: number; automationUnsupported: number;
  overdueWorkItems: number;
  staffReviewRequired: true; automaticExecutionEnabled: false;
  externalProviderOperations: 0;
};
const priority = (item: RemediationTargetReview) =>
  item.risk === "DESTRUCTIVE" || item.risk === "FINANCIAL" ?
    "IMMEDIATE" as const :
    item.risk === "EXTERNAL_CHANGE" ? "HIGH" as const : "NORMAL" as const;
function proofNeeded(target: RemediationTargetReview) {
  return [
    "Exact affected tenant and provider object identity",
    "Current finding and remediation record with revision",
    "Authorized incident commander handoff",
    ...(target.risk !== "READ_ONLY" ? [
      "Separate time-bounded approval for exact action scope",
      "Documented rollback or impact mitigation procedure",
    ] : []),
    "Independent post-action provider readback",
    "Reconciled failures, partial results and unresolved unknowns",
  ];
}
export function planRemediationHandoffs(
  assessment: IncidentRemediationReadiness,
): RemediationHandoffPlan {
  if (assessment.targetReviews.length > 300 ||
      assessment.targetReviews.some(x =>
        x.organizationId !== assessment.organizationId))
    throw Error("REMEDIATION_HANDOFF_SCOPE_INVALID");
  const tickets = assessment.targetReviews.map(target => {
    const urgency = priority(target);
    const delay = urgency === "IMMEDIATE" ? 15 :
      urgency === "HIGH" ? 60 : 240;
    const dueAt = new Date(Date.parse(assessment.at) +
      delay * 60000).toISOString();
    const reason = target.barriers.length ?
      "Control gates require human reconciliation: " +
      target.barriers.join("; ") :
      "Ready for separate manual approval and provider-side validation";
    const operatorRole = target.risk === "FINANCIAL" ?
      "Finance security approver" :
      target.risk === "DESTRUCTIVE" ? "Incident commander and security officer" :
      target.risk === "EXTERNAL_CHANGE" ? "Privileged identity administrator" :
      "Security reviewer";
    return {
      id: "HANDOFF:" + target.remediationId,
      organizationId: assessment.organizationId,
      incidentId: assessment.incidentId,
      remediationId: target.remediationId, findingId: target.findingId,
      title: target.title, urgency, ownerRole: operatorRole,
      reason, dueAt, expectedProof: proofNeeded(target),
      currentBarriers: target.barriers,
      requiresExplicitApproval: target.risk !== "READ_ONLY",
      requiresIndependentVerification: true as const,
      allowedMode: "MANUAL_REVIEW_ONLY" as const,
      providerWrites: 0 as const, requestSubmittedToExecutor: false as const,
    };
  }).sort((a, b) => {
    const weight = { IMMEDIATE: 3, HIGH: 2, NORMAL: 1 };
    return weight[b.urgency] - weight[a.urgency] ||
      a.dueAt.localeCompare(b.dueAt) || a.id.localeCompare(b.id);
  });
  return {
    schema: "cyberpilot.incident.remediation.handoff-plan.v1",
    organizationId: assessment.organizationId,
    incidentId: assessment.incidentId, asOf: assessment.at,
    inputDigest: assessment.sourceDigest, targets: assessment.targetReviews.length,
    tickets, blocked: assessment.targetReviews.filter(x =>
      x.gate === "BLOCKED").length,
    readyForManualReview: assessment.targetReviews.filter(x =>
      x.gate === "MANUAL_HANDOFF_READY").length,
    awaitingApproval: assessment.targetReviews.filter(x =>
      x.barriers.includes("APPROVAL_EXPIRED_OR_MISSING") ||
      x.barriers.includes("PLAYBOOK_APPROVAL_MISSING")).length,
    automationUnsupported: assessment.unsafeAutomations,
    overdueWorkItems: assessment.targetReviews.reduce((n, x) => n +
      x.workItems.filter(y => y.overdue).length, 0),
    staffReviewRequired: true, automaticExecutionEnabled: false,
    externalProviderOperations: 0,
  };
}
export type RemediationReadinessMatrix = {
  schema: "cyberpilot.incident.remediation.matrix.v1";
  organizationId: string; incidentId: string;
  rows: Array<{ barrier: RemediationBarrier; count: number;
    remediationIds: string[]; nextStep: string; risk: string }>;
  manualOnlyTargets: number; automatedModeTargets: number;
  suspendedTargets: number; successfulHistoricFlags: number;
  unverifiedProviderOutcomes: number; sourceTruncated: boolean;
  digest: string; effectiveSecurityRemediationProven: false;
};
const reasons: Partial<Record<RemediationBarrier, string>> = {
  FOREIGN_TENANT: "Stop and verify organization-bound record identities",
  INCIDENT_REVISION_DRIFT: "Refresh current incident CAS revision before handoff",
  FINDING_NOT_IN_TENANT: "Verify finding exists in authorized organization",
  WORK_ITEM_NOT_FOUND: "Locate original task or record explicit missing source",
  REMEDIATION_NOT_IN_TENANT: "Verify remediation ID and permissions",
  APPROVER_UNKNOWN: "Assign authorized reviewer before changes",
  APPROVER_IS_INCIDENT_OWNER: "Obtain independent privileged approval",
  APPROVAL_EXPIRED_OR_MISSING: "Renew scope-bound approval",
  AUTOMATED_MODE_NOT_AUTHORIZED: "Do not use LIVE executor in offline workflow",
  PROVIDER_OUTCOME_NOT_INDEPENDENT: "Obtain independent post-action readback",
  WORK_IN_PROGRESS: "Wait for authenticated execution event or block",
  FAILED_REMEDIATION: "Investigate failure before attempting a new operation",
  VERIFY_REQUIRED: "Review incomplete work and verification evidence",
  PLAYBOOK_APPROVAL_MISSING: "Record approval for exact playbook step",
  FINDING_NOT_OPEN: "Reconcile finding lifecycle and incident timeline",
  CASE_ALREADY_CLOSED: "Reopen under incident governance before new actions",
  COVERAGE_INCOMPLETE: "Complete bounded pagination without guessing results",
  TARGET_NOT_SELECTED: "Explicitly select records before review",
};
export function summarizeRemediationReadiness(
  assessment: IncidentRemediationReadiness,
): RemediationReadinessMatrix {
  const keys: RemediationBarrier[] = [
    "FOREIGN_TENANT", "INCIDENT_REVISION_DRIFT", "TARGET_NOT_SELECTED",
    "FINDING_NOT_IN_TENANT", "WORK_ITEM_NOT_FOUND",
    "REMEDIATION_NOT_IN_TENANT", "APPROVER_UNKNOWN",
    "APPROVER_IS_INCIDENT_OWNER", "APPROVAL_EXPIRED_OR_MISSING",
    "AUTOMATED_MODE_NOT_AUTHORIZED", "PROVIDER_OUTCOME_NOT_INDEPENDENT",
    "WORK_IN_PROGRESS", "FAILED_REMEDIATION", "VERIFY_REQUIRED",
    "PLAYBOOK_APPROVAL_MISSING", "FINDING_NOT_OPEN",
    "CASE_ALREADY_CLOSED", "COVERAGE_INCOMPLETE",
  ];
  const rows = keys.map(barrier => {
    const affected = assessment.targetReviews.filter(x =>
      x.barriers.includes(barrier));
    return {
      barrier, count: affected.length +
        (assessment.blockers.includes(barrier) && !affected.length ? 1 : 0),
      remediationIds: affected.map(x => x.remediationId),
      nextStep: reasons[barrier] ?? "Request manual operator assessment",
      risk: barrier === "FOREIGN_TENANT" ||
        barrier === "AUTOMATED_MODE_NOT_AUTHORIZED" ?
        "CRITICAL" : barrier === "APPROVER_IS_INCIDENT_OWNER" ?
        "HIGH" : "MEDIUM",
    };
  }).filter(x => x.count > 0);
  return {
    schema: "cyberpilot.incident.remediation.matrix.v1",
    organizationId: assessment.organizationId, incidentId: assessment.incidentId,
    rows, manualOnlyTargets: assessment.targetReviews.filter(x =>
      x.mode === "GUIDED").length,
    automatedModeTargets: assessment.unsafeAutomations,
    suspendedTargets: assessment.targetReviews.filter(x =>
      x.gate === "BLOCKED").length,
    successfulHistoricFlags: assessment.targetReviews.filter(x =>
      x.status === "SUCCEEDED" || x.status === "VERIFIED").length,
    unverifiedProviderOutcomes: assessment.missingIndependentProof,
    sourceTruncated: assessment.truncated,
    digest: createHash("sha256").update(JSON.stringify(rows)).digest("hex"),
    effectiveSecurityRemediationProven: false,
  };
}
export type IncidentRemediationDecision = {
  id: string; incidentId: string; remediationId: string;
  verdict: "STOP" | "ESCALATE" | "MANUAL_REVIEW";
  conditions: string[]; requiredAuthorization: string[];
  allowedProviderCalls: 0; autoExecution: false;
};
export function buildIncidentRemediationDecisions(
  assessment: IncidentRemediationReadiness,
): IncidentRemediationDecision[] {
  return assessment.targetReviews.map(target => {
    const stop = target.gate === "BLOCKED";
    const critical = target.risk === "DESTRUCTIVE" ||
      target.risk === "FINANCIAL";
    const verdict: IncidentRemediationDecision["verdict"] = stop ?
      "STOP" : critical || target.gate === "REVIEW_REQUIRED" ?
      "ESCALATE" : "MANUAL_REVIEW";
    return { id: "DECISION:" + target.remediationId,
      incidentId: assessment.incidentId, remediationId: target.remediationId,
      verdict, conditions: target.barriers,
      requiredAuthorization: [
        "Organization-bound reviewer membership",
        ...(critical ? ["Independent high-impact approver"] : []),
        "Exact target and operation verification",
        "Separate explicit LIVE consent and executor permissions",
        "Independent provider-side completion readback",
      ], allowedProviderCalls: 0, autoExecution: false };
  });
}
function csvValue(x: unknown) {
  const value = String(x ?? "");
  return '"' + (/^[=+\-@\t\r]/.test(value) ? "'" + value : value)
    .replaceAll('"', '""').replaceAll("\r", " ")
    .replaceAll("\n", " ") + '"';
}
export function exportRemediationIntegration(
  assessment: IncidentRemediationReadiness,
  format: "JSON" | "CSV" | "MARKDOWN",
) {
  const plan = planRemediationHandoffs(assessment);
  const matrix = summarizeRemediationReadiness(assessment);
  const decisions = buildIncidentRemediationDecisions(assessment);
  const manifest = { assessment, plan, matrix, decisions,
    executionWasRequested: false, providerWrites: 0,
    actualRemediationProven: false };
  const digest = createHash("sha256")
    .update(JSON.stringify(manifest)).digest("hex");
  const filename = "incident-remediation-" + assessment.incidentId;
  if (format === "JSON") return {
    filename: filename + ".json", mime: "application/json", digest,
    content: JSON.stringify({ ...manifest, digest }, null, 2),
  };
  if (format === "CSV") {
    const rows = [["remediationId", "findingId", "mode", "status",
      "gate", "approvalCurrent", "independentApprover", "barriers"],
      ...assessment.targetReviews.map(x => [
        x.remediationId, x.findingId, x.mode, x.status, x.gate,
        String(x.approvalCurrent), String(x.independentApprover),
        x.barriers.join(";"),
      ])];
    return { filename: filename + ".csv", mime: "text/csv", digest,
      content: rows.map(r => r.map(csvValue).join(",")).join("\r\n") };
  }
  if (format !== "MARKDOWN") throw Error("REMEDIATION_EXPORT_FORMAT_INVALID");
  const safe = (x: string) => x.replaceAll("|", "\\|")
    .replaceAll("<", "&lt;").replaceAll(">", "&gt;");
  return { filename: filename + ".md", mime: "text/markdown", digest,
    content: ["# Incident supervised remediation handoffs",
      "Organization: " + assessment.organizationId,
      "Incident: " + assessment.incidentId,
      "Gate: " + assessment.gate,
      "Automatic execution: DISABLED",
      "Remediation provider verification: NOT ESTABLISHED",
      "Digest: " + digest, "",
      "## Reviewed remediation work",
      ...assessment.targetReviews.map(x => "- " + safe(x.title) +
        ": " + x.gate + " (" + x.mode + ")"),
      "", "## Required human authorization",
      ...plan.tickets.map(x => "- " + safe(x.title) +
        ": " + safe(x.ownerRole) + " due " + x.dueAt),
      "", "No Graph or other provider-side remediation was triggered.",
    ].join("\n") };
}
